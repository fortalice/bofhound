import base64
import logging
from io import BytesIO
from bloodhound.ad.utils import ADUtils
from bloodhound.enumeration.acls import SecurityDescriptor, ACL, ACCESS_ALLOWED_ACE, ACCESS_MASK, ACE, ACCESS_ALLOWED_OBJECT_ACE, has_extended_right, EXTRIGHTS_GUID_MAPPING, can_write_property, ace_applies
from bofhound.ad.models import BloodHoundComputer, BloodHoundDomain, BloodHoundGroup, BloodHoundObject, BloodHoundSchema, BloodHoundUser, BloodHoundOU, BloodHoundGPO, BloodHoundDomainTrust
from bofhound.logger import OBJ_EXTRA_FMT, ColorScheme
from bofhound import console

class ADDS():

    AT_SCHEMAIDGUID = "schemaidguid"
    AT_SAMACCOUNTTYPE = "samaccounttype"
    AT_DISTINGUISHEDNAME = "distinguishedname"
    AT_MSDS_GROUPMSAMEMBERSHIP = "msds-groupmsamembership"
    AT_OBJECTCLASS = "objectclass"
    AT_OBJECTID = "objectsid"
    AT_NAME = "name"
    AT_COMMONNAME = "cn"
    AT_SAMACCOUNTNAME = "samaccountname"
    AT_ORGUNIT = "ou"
    AT_OBJECTGUID = "objectguid"


    def __init__(self):
        self.sid = None
        self.SID_MAP = {} # {sid: BofHoundModel}
        self.DN_MAP = {} # {dn: BofHoundModel}
        self.DOMAIN_MAP = {} # {dc: ObjectIdentifier}
        self.ObjectTypeGuidMap = {} # { Name : schemaIdGuid }
        self.domains = []
        self.users = []
        self.computers = []
        self.groups = []
        self.ous = []
        self.gpos = []
        self.schemas = []
        self.trusts = []
        self.trustaccounts = []
        self.unknown_objects = []


    def import_objects(self, objects):
        """Parse a list of dictionaries representing attributes of an AD object
            and add or merge them into appropriate lists of objects in the ADDS instance

        objects: [] of {} containing attributes for AD objects
        """

        for object in objects:
            schemaIdGuid = object.get(ADDS.AT_SCHEMAIDGUID, None)
            if schemaIdGuid:
                new_schema = BloodHoundSchema(object)
                if new_schema.SchemaIdGuid is not None:
                    self.schemas.append(new_schema)
                    if new_schema.Name not in self.ObjectTypeGuidMap.keys():
                        self.ObjectTypeGuidMap[new_schema.Name] = new_schema.SchemaIdGuid
                continue

            accountType = int(object.get(ADDS.AT_SAMACCOUNTTYPE, 0))
            target_list = None

            # objectClass: top, container
            # objectClass: top, container, groupPolicyContainer
            # objectClass: top, organizationalUnit

            dn = object.get(ADDS.AT_DISTINGUISHEDNAME, None)
            sid = object.get(ADDS.AT_OBJECTID, None)
            guid = object.get(ADDS.AT_OBJECTGUID, None)

            # SID and DN are required attributes for bofhound objects
            if dn is None or (sid is None and guid is None):
                self.unknown_objects.append(object)
                continue

            originalObject = self.retrieve_object(dn.upper(), sid)
            bhObject = None

            # Groups
            if accountType in [268435456, 268435457, 536870912, 536870913]:
                bhObject = BloodHoundGroup(object)
                target_list = self.groups

            # Users
            elif object.get(ADDS.AT_MSDS_GROUPMSAMEMBERSHIP, b'') != b'' \
                or accountType in [805306368]:
                bhObject = BloodHoundUser(object)
                target_list = self.users

            # Computers
            elif accountType in [805306369]:
                bhObject = BloodHoundComputer(object)
                target_list = self.computers

            # Trust Accounts
            elif accountType in [805306370]:
                self.trustaccounts.append(object)

            # Other Things :)
            else:
                object_class = object.get(ADDS.AT_OBJECTCLASS, '')
                # if 'top, domain' in object_class or 'top, builtinDomain' in object_class:
                if 'top, domain' in object_class:
                    bhObject = BloodHoundDomain(object)
                    self.add_domain(bhObject)
                    target_list = self.domains
                # grab domain trusts
                elif 'trustedDomain' in object_class:
                    bhObject = BloodHoundDomainTrust(object)
                    bhObject.set_temporary_sid(len(self.trusts))
                    target_list = self.trusts
                # grab OUs
                elif 'top, organizationalUnit' in object_class:
                    bhObject = BloodHoundOU(object)
                    target_list = self.ous
                elif 'container, groupPolicyContainer' in object_class:
                    bhObject = BloodHoundGPO(object)
                    target_list = self.gpos
                # some well known SIDs dont return the accounttype property
                elif object.get(ADDS.AT_NAME) in ADUtils.WELLKNOWN_SIDS:
                    bhObject, target_list =  self._lookup_known_sid(object, object.get(ADDS.AT_NAME))
                elif object.get(ADDS.AT_COMMONNAME) in ADUtils.WELLKNOWN_SIDS:
                    bhObject, target_list =  self._lookup_known_sid(object, object.get(ADDS.AT_COMMONNAME))
                else:
                    self.unknown_objects.append(object)


            if originalObject:
                if bhObject:
                    originalObject.merge_entry(bhObject)
                else:
                    bhObject = BloodHoundObject(object)
                    originalObject.merge_entry(bhObject)
            elif bhObject:
                target_list.append(bhObject)
                if not isinstance(bhObject, BloodHoundDomainTrust): # trusts don't have SIDs
                    self.add_object_to_maps(bhObject)


    def add_object_to_maps(self, object:BloodHoundObject):
        if object.ObjectIdentifier:
            self.SID_MAP[object.ObjectIdentifier] = object

        if ADDS.AT_DISTINGUISHEDNAME in object.Properties.keys():
           self.DN_MAP[object.Properties[ADDS.AT_DISTINGUISHEDNAME]] = object


    def add_domain(self, object:BloodHoundObject):
        if ADDS.AT_DISTINGUISHEDNAME in object.Properties.keys() and object.ObjectIdentifier:
            dn = object.Properties[ADDS.AT_DISTINGUISHEDNAME]
            dc = BloodHoundObject.get_domain_component(dn.upper())
            if dc not in self.DOMAIN_MAP:
                self.DOMAIN_MAP[dc] = object.ObjectIdentifier


    def retrieve_object(self, dn=None, sid=None):
        if dn:
            if dn in self.DN_MAP.keys():
                return self.DN_MAP[dn]

        if sid:
            if sid in self.SID_MAP.keys():
                return self.SID_MAP[sid]

        return None


    def recalculate_sid(self, object:BloodHoundObject):
        if 'distinguishedname' in object.Properties.keys():
            # check for wellknown sid
            if object.ObjectIdentifier in ADUtils.WELLKNOWN_SIDS:
                object.Properties['domainsid'] = self.DOMAIN_MAP.get(
                    BloodHoundObject.get_domain_component(object.Properties['distinguishedname']),
                    f"S-????"
                )
                object.ObjectIdentifier = BloodHoundObject.get_sid(object.ObjectIdentifier, object.Properties['distinguishedname'])


    def build_relation(self, object, sid, relation, acetype='', inherited=False):
        if acetype != '':
            raise ValueError("BH 4.0 incompatible output called")

        PrincipalSid = BloodHoundObject.get_sid(sid, object.Properties["distinguishedname"])

        if sid in self.SID_MAP.keys():
            PrincipalType = self.SID_MAP[sid]._entry_type
        elif sid in ADUtils.WELLKNOWN_SIDS.keys():
            PrincipalType = ADUtils.WELLKNOWN_SIDS[sid][1].title()
        else:
            PrincipalType = "Unknown"

        return {'RightName': relation, 'PrincipalSID': PrincipalSid, 'IsInherited': inherited, 'PrincipalType': PrincipalType }


    def process(self):
        all_objects = self.users + self.groups + self.computers + self.domains + self.ous + self.gpos

        num_parsed_relations = 0
        with console.status(f" [bold] Processed {num_parsed_relations} ACLs", spinner="aesthetic") as status:
            for object in all_objects:
                self.recalculate_sid(object)
                num_parsed_relations += self.parse_acl(object)
                status.update(f" [bold] Processing {num_parsed_relations} ACLs")

        logging.info(f"Parsed {num_parsed_relations} ACL relationships")

        with console.status(" [bold] Creating default users", spinner="aesthetic"):
            self.write_default_users()
        logging.info("Created default users")

        with console.status(" [bold] Creating default groups", spinner="aesthetic"):
            self.write_default_groups()
        logging.info("Created default groups")

        with console.status(" [bold] Resolving group memberships", spinner="aesthetic"):
            self.resolve_group_members()
        logging.info("Resolved group memberships")

        with console.status(" [bold] Resolving delegation relationships", spinner="aesthetic"):
            self.resolve_delegation_targets()
        logging.info("Resolved delegation relationships")

        with console.status(" [bold] Resolving OU memberships", spinner="aesthetic"):
            self.resolve_ou_members()
        logging.info("Resolved OU memberships")

        with console.status(" [bold] Linking GPOs to OUs", spinner="aesthetic"):
            self.link_gpos()
        logging.info("Linked GPOs to OUs")

        if len(self.trusts) > 0:
            with console.status(" [bold] Resolving domain trusts", spinner="aesthetic"):
                self.resolve_domain_trusts()
            logging.info("Resolved domain trusts")


    def resolve_delegation_targets(self):
        for object in self.computers + self.users:
            delegatehosts = object.AllowedToDelegate
            resolved_delegation_list = []
            for host in delegatehosts:
                try:
                    target = host.split('/')[1]
                except IndexError:
                    logging.warning('Invalid delegation target: %s', host)
                    continue
                try:
                    sid = self.SID_MAP.get(target.lower())
                    resolved_delegation_list.append(sid)
                except KeyError:
                    if '.' in target:
                        resolved_delegation_list.append(target.upper())
            if len(delegatehosts) > 0:
                object.Properties['allowedtodelegate'] = delegatehosts
                object.AllowedToDelegate = resolved_delegation_list


    def write_default_users(self):
        """
        Write built-in users to users.json file
        """

        for domain in self.domains:
            domainsid = domain.ObjectIdentifier
            domainname = domain.Properties.get('name', 'UNKNOWN').upper()
            logging.debug(f"Adding default groups for {ColorScheme.domain}{domainname}[/] ({domainsid})", extra=OBJ_EXTRA_FMT)

            user = BloodHoundUser()
            user.AllowedToDelegate = []
            user.ObjectIdentifier = "%s-S-1-5-20" % domainname
            user.PrimaryGroupSID = None
            user.Properties = {
                "domain": domainname,
                "domainsid": domainsid,
                "name": "NT AUTHORITY@%s" % domainname,
                ADDS.AT_DISTINGUISHEDNAME: f"CN=S-1-5-20,CN=FOREIGNSECURITYPRINCIPALS,{BloodHoundObject.get_dn(domainname)}"
            }
            user.Aces = []
            user.SPNTargets = []
            user.HasSIDHistory = []
            user.IsDeleted = False
            user.IsACLProtected = False

            self.users.append(user)


    def write_default_groups(self):
        """
        Put default groups in the groups.json file
        """

        # Domain controllers
        # TODO: Determine root domains
        # 1. Look for Enterprise Admins
        # 2. If no enterprise admins group, treat all as forest roots
        #rootdomains = [ domain for domain in self.domains ]
        for domain in self.domains:
            domainsid = domain.ObjectIdentifier
            domainname = domain.Properties.get('name', 'UNKNOWN').upper()
            logging.debug(f"Adding default groups for {ColorScheme.domain}{domainname}[/] ({domainsid})", extra=OBJ_EXTRA_FMT)

            domain_controllers = [ computer for computer in self.computers if computer.PrimaryGroupSid.endswith('-516') ]

            group = BloodHoundGroup({})
            group.IsDeleted = False
            group.IsACLProtected = False
            group.ObjectIdentifier = "%s-S-1-5-9" % domainname
            group.Properties = {
                "domain": domainname.upper(),
                "name": "ENTERPRISE DOMAIN CONTROLLERS@%s" % domainname,
                ADDS.AT_DISTINGUISHEDNAME: f"CN=S-1-5-9,CN=FOREIGNSECURITYPRINCIPALS,{BloodHoundObject.get_dn(domainname)}"
            }
            group.Members = []
            group.Aces = []

            for computer in domain_controllers:
                memberdata = {
                    "ObjectIdentifier": computer.ObjectIdentifier,
                    "ObjectType": "Computer"
                }
                group.Members.append(memberdata)
            self.groups.append(group)


            # Everyone
            evgroup = BloodHoundGroup({})

            evgroup.IsDeleted = False
            evgroup.IsACLProtected = False
            evgroup.ObjectIdentifier = "%s-S-1-1-0" % domainname
            evgroup.Properties = {
                "domain": domainname,
                "domainsid": domainsid,
                "name": "EVERYONE@%s" % domainname,
                ADDS.AT_DISTINGUISHEDNAME: f"CN=S-1-5-0,CN=FOREIGNSECURITYPRINCIPALS,{BloodHoundObject.get_dn(domainname)}"
            }
            evgroup.Members = []
            evgroup.Aces = []

            self.groups.append(evgroup)

            # Authenticated users
            augroup = BloodHoundGroup({})

            augroup.IsDeleted = False
            augroup.IsACLProtected = False
            augroup.ObjectIdentifier = "%s-S-1-5-11" % domainname
            # Was this a mistake? augroup.ObjectIdentifier = "S-1-5-11"
            augroup.Properties = {
                    "domain": domainname,
                    "domainsid": domainsid,
                    "name": "AUTHENTICATED USERS@%s" % domainname,
                    ADDS.AT_DISTINGUISHEDNAME: f"CN=S-1-5-11,CN=FOREIGNSECURITYPRINCIPALS,{BloodHoundObject.get_dn(domainname)}"
                }
            augroup.Members = []
            augroup.Aces = []

            self.groups.append(augroup)

            # Interactive
            iugroup = BloodHoundGroup({})

            iugroup.IsDeleted = False
            iugroup.IsACLProtected = False
            iugroup.ObjectIdentifier = "%s-S-1-5-4" % domainname
            iugroup.Properties = {
                    "domain": domainname,
                    "domainsid": domainsid,
                    "name": "INTERACTIVE@%s" % domainname,
                    ADDS.AT_DISTINGUISHEDNAME: f"CN=S-1-5-4,CN=FOREIGNSECURITYPRINCIPALS,{BloodHoundObject.get_dn(domainname)}"
                }
            iugroup.Members = []
            iugroup.Aces = []

            self.groups.append(iugroup)


    def resolve_group_members(self):
        for group in self.groups:
            for user in self.users:
                if self._is_member_of(user, group):
                    group.add_group_member(user, "User")
                    logging.debug(f"Resolved {ColorScheme.user}{user.Properties['name']}[/] as member of {ColorScheme.group}{group.Properties['name']}[/]", extra=OBJ_EXTRA_FMT)


            for computer in self.computers:
                if self._is_member_of(computer, group):
                    group.add_group_member(computer, "Computer")
                    logging.debug(f"Resolved {ColorScheme.computer}{computer.Properties['name']}[/] as member of {ColorScheme.group}{group.Properties['name']}[/]", extra=OBJ_EXTRA_FMT)


            for subgroup in self.groups:
                if self._is_nested_group(subgroup, group):
                    group.add_group_member(subgroup, "Group")
                    logging.debug(f"Resolved {ColorScheme.group}{subgroup.Properties['name']}[/] as nested member of {ColorScheme.group}{group.Properties['name']}[/]", extra=OBJ_EXTRA_FMT)

    
    def resolve_ou_members(self):
        for user in self.users:
            ou = self._resolve_object_ou(user)
            if ou is not None:
                ou.add_ou_member(user, "User")
                logging.debug(f"Identified {ColorScheme.user}{user.Properties['name']}[/] as within OU {ColorScheme.ou}{ou.Properties['name']}[/]", extra=OBJ_EXTRA_FMT)

        for group in self.groups:
            ou = self._resolve_object_ou(group)
            if ou is not None:
                ou.add_ou_member(group, "Group")
                logging.debug(f"Identified {ColorScheme.group}{group.Properties['name']}[/] as within OU {ColorScheme.ou}{ou.Properties['name']}[/]", extra=OBJ_EXTRA_FMT)

        for computer in self.computers:
            ou = self._resolve_object_ou(computer)
            if ou is not None:
                ou.add_ou_member(computer, "Computer")
                logging.debug(f"Identified {ColorScheme.computer}{computer.Properties['name']}[/] as within OU {ColorScheme.ou}{ou.Properties['name']}[/]", extra=OBJ_EXTRA_FMT)

        for nested_ou in self.ous:
            ou = self._resolve_nested_ou(nested_ou)
            if ou is not None:
                ou.add_ou_member(nested_ou, "OU")
                logging.debug(f"Identified {ColorScheme.ou}{nested_ou.Properties['name']}[/] as within OU {ColorScheme.ou}{ou.Properties['name']}[/]", extra=OBJ_EXTRA_FMT)


    def link_gpos(self):
        for object in self.ous + self.domains:
            if object._entry_type == 'OU':
                self.add_domainsid_prop(object) # since OUs don't have a SID to get a domainsid from

            for gplink in object.GPLinks:
                if gplink[0] in self.DN_MAP.keys():
                    gpo = self.DN_MAP[gplink[0]]
                    object.add_linked_gpo(gpo, gplink[1])

                    if object._entry_type == 'Domain':
                       logging.debug(f"Linked {ColorScheme.gpo}{gpo.Properties['name']}[/] to domain {ColorScheme.domain}{object.Properties['name']}[/]", extra=OBJ_EXTRA_FMT)
                    else:
                        logging.debug(f"Linked {ColorScheme.gpo}{gpo.Properties['name']}[/] to OU {ColorScheme.ou}{object.Properties['name']}[/]", extra=OBJ_EXTRA_FMT)
    

    def resolve_domain_trusts(self):
        for trust in self.trusts:
            if trust.TrustProperties is not None:
                # Start by trying to add the target domain's sid if we have it
                target_domain_dn = ADUtils.domain2ldap(trust.TrustProperties['TargetDomainName'])
                if target_domain_dn in self.DOMAIN_MAP.keys():
                    trust.TrustProperties['TargetDomainSid'] = self.DOMAIN_MAP[target_domain_dn]

                # Append the trust dict to the origin domain's trust list
                if trust.LocalDomainDn in self.DOMAIN_MAP.keys():
                    for domain in self.domains:
                        if trust.LocalDomainDn == domain.Properties['distinguishedname']:
                            # don't add trust relationships more than once!
                            if not any(prior['TargetDomainName'] == trust.TrustProperties['TargetDomainName'] for prior in domain.Trusts):
                                domain.Trusts.append(trust.TrustProperties)
                            break


    def add_domainsid_prop(self, object):
        dc = BloodHoundObject.get_domain_component(object.Properties["distinguishedname"])
        if dc in self.DOMAIN_MAP.keys():
            object.Properties["domainsid"] = self.DOMAIN_MAP[dc]


    def resolve_trust_relationships(self):
        pass


    # Returns int: number of relations parsed
    def parse_acl(self, entry:BloodHoundObject):
        if not entry.RawAces:
            return 0

        try:
            value = base64.b64decode(entry.RawAces)
        except:
            logging.warning(f'Error base64 decoding nTSecurityDescriptor attribute on {entry._entry_type} {entry.Properties["name"]}')
            return 0

        if not value:
            return 0
        sd = SecurityDescriptor(BytesIO(value))
        # Check for protected DACL flag
        entry.IsACLProtected = sd.has_control(sd.PD)
        relations = []

        # Parse owner
        osid = str(sd.owner_sid)
        ignoresids = ["S-1-3-0", "S-1-5-18", "S-1-5-10"]
        # Ignore Creator Owner or Local System
        if osid not in ignoresids:
            relations.append(self.build_relation(entry, osid, 'Owns', inherited=False))
        for ace_object in sd.dacl.aces:
            if ace_object.ace.AceType != 0x05 and ace_object.ace.AceType != 0x00:
                # These are the only two aces we care about currently
                logging.debug('Don\'t care about acetype %d', ace_object.ace.AceType)
                continue
            # Check if sid is ignored
            sid = str(ace_object.acedata.sid)
            # Ignore Creator Owner or Local System
            if sid in ignoresids:
                continue
            if ace_object.ace.AceType == 0x05:
                is_inherited = ace_object.has_flag(ACE.INHERITED_ACE)
                # ACCESS_ALLOWED_OBJECT_ACE
                if not ace_object.has_flag(ACE.INHERITED_ACE) and ace_object.has_flag(ACE.INHERIT_ONLY_ACE):
                    # ACE is set on this object, but only inherited, so not applicable to us
                    continue

                # Check if the ACE has restrictions on object type (inherited case)
                if ace_object.has_flag(ACE.INHERITED_ACE) \
                    and ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_INHERITED_OBJECT_TYPE_PRESENT):
                    # Verify if the ACE applies to this object typ
                    try:
                        if not ace_applies(ace_object.acedata.get_inherited_object_type().lower(), entry._entry_type, self.ObjectTypeGuidMap):
                            continue
                    except KeyError:
                        pass
                mask = ace_object.acedata.mask
                # Now the magic, we have to check all the rights BloodHound cares about

                # Check generic access masks first
                if mask.has_priv(ACCESS_MASK.GENERIC_ALL) or mask.has_priv(ACCESS_MASK.WRITE_DACL) \
                    or mask.has_priv(ACCESS_MASK.WRITE_OWNER) or mask.has_priv(ACCESS_MASK.GENERIC_WRITE):
                    # For all generic rights we should check if it applies to our object type

                    try:
                        if ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT) \
                            and not ace_applies(ace_object.acedata.get_object_type().lower(), entry._entry_type, self.ObjectTypeGuidMap):
                            # If it does not apply, break out of the loop here in order to
                            # avoid individual rights firing later on
                            continue
                    except KeyError:
                        pass

                    # Check from high to low, ignore lower privs which may also match the bitmask,
                    # even though this shouldn't happen since we check for exact matches currently
                    if mask.has_priv(ACCESS_MASK.GENERIC_ALL):
                        # Report this as LAPS rights if it's a computer object AND laps is enabled

                        if entry._entry_type.lower() == 'computer' and \
                        ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT) and \
                        'haslaps' in entry.Properties.keys() and \
                        'ms-mcs-admpwd' in self.ObjectTypeGuidMap.keys():
                            if ace_object.acedata.get_object_type().lower() == self.ObjectTypeGuidMap['ms-mcs-admpwd']:
                                relations.append(self.build_relation(entry, sid, 'ReadLAPSPassword', inherited=is_inherited))
                        else:
                            relations.append(self.build_relation(entry, sid, 'GenericAll', inherited=is_inherited))
                        continue

                    if mask.has_priv(ACCESS_MASK.GENERIC_WRITE):
                        relations.append(self.build_relation(entry, sid, 'GenericWrite', inherited=is_inherited))
                        # Don't skip this if it's the domain object, since BloodHound reports duplicate
                        # rights as well, and this might influence some queries
                        if entry._entry_type.lower() != 'domain' and entry._entry_type.lower() != 'computer':
                            continue

                    # These are specific bitmasks so don't break the loop from here
                    if mask.has_priv(ACCESS_MASK.WRITE_DACL):
                        relations.append(self.build_relation(entry, sid, 'WriteDacl', inherited=is_inherited))

                    if mask.has_priv(ACCESS_MASK.WRITE_OWNER):
                        relations.append(self.build_relation(entry, sid, 'WriteOwner', inherited=is_inherited))

                # Property write privileges
                writeprivs = ace_object.acedata.mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_WRITE_PROP)
                if writeprivs:
                    # GenericWrite
                    if entry._entry_type.lower() in ['user', 'group', 'computer'] and not ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                        relations.append(self.build_relation(entry, sid, 'GenericWrite', inherited=is_inherited))
                    if entry._entry_type.lower() == 'group' and can_write_property(ace_object, EXTRIGHTS_GUID_MAPPING['WriteMember']):
                        relations.append(self.build_relation(entry, sid, 'AddMember', '', inherited=is_inherited))
                    if entry._entry_type.lower() == 'computer' and can_write_property(ace_object, EXTRIGHTS_GUID_MAPPING['AllowedToAct']):
                        relations.append(self.build_relation(entry, sid, 'AddAllowedToAct', '', inherited=is_inherited))

                    # Since 4.0
                    # Key credential link property write rights
                    if entry._entry_type.lower() in ['user', 'computer'] and ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT) \
                    and ace_object.acedata.get_object_type().lower() == '5b47d60f-6090-40b2-9f37-2a4de88f3063' \
                    and 'ms-ds-key-credential-link' in self.ObjectTypeGuidMap and ace_object.acedata.get_object_type().lower() == self.ObjectTypeGuidMap['ms-ds-key-credential-link']:
                        relations.append(self.build_relation(entry, sid, 'AddKeyCredentialLink', inherited=is_inherited))

                    # ServicePrincipalName property write rights (exclude generic rights)
                    if entry._entry_type.lower() == 'user' and ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT) \
                    and ace_object.acedata.get_object_type().lower() == 'f3a64788-5306-11d1-a9c5-0000f80367c1':
                        relations.append(self.build_relation(entry, sid, 'WriteSPN', inherited=is_inherited))

                elif ace_object.acedata.mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_SELF):
                    # Self add - since 4.0
                    if entry._entry_type.lower() == 'group' and ace_object.acedata.data.ObjectType == EXTRIGHTS_GUID_MAPPING['WriteMember']:
                        relations.append(self.build_relation(entry, sid, 'AddSelf', '', inherited=is_inherited))

                # Property read privileges
                if ace_object.acedata.mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_READ_PROP):
                    if entry._entry_type.lower() == 'computer' and \
                    ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT) and \
                    'haslaps' in entry.Properties.keys() and \
                    'ms-mcs-admpwd' in self.ObjectTypeGuidMap.keys():
                        if ace_object.acedata.get_object_type().lower() == self.ObjectTypeGuidMap['ms-mcs-admpwd']:
                           relations.append(self.build_relation(entry, sid, 'ReadLAPSPassword', inherited=is_inherited))

                # Extended rights
                control_access = ace_object.acedata.mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_CONTROL_ACCESS)
                if control_access:
                    # All Extended
                    if entry._entry_type.lower() in ['user', 'domain'] and not ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                        relations.append(self.build_relation(entry, sid, 'AllExtendedRights', '', inherited=is_inherited))
                    if entry._entry_type.lower() == 'computer' and not ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT) and \
                    'haslaps' in entry.Properties.keys():
                        relations.append(self.build_relation(entry, sid, 'AllExtendedRights', '', inherited=is_inherited))
                    if entry._entry_type.lower() == 'domain' and has_extended_right(ace_object, EXTRIGHTS_GUID_MAPPING['GetChanges']):
                        relations.append(self.build_relation(entry, sid, 'GetChanges', '', inherited=is_inherited))
                    if entry._entry_type.lower() == 'domain' and has_extended_right(ace_object, EXTRIGHTS_GUID_MAPPING['GetChangesAll']):
                        relations.append(self.build_relation(entry, sid, 'GetChangesAll', '', inherited=is_inherited))
                    if entry._entry_type.lower() == 'user' and has_extended_right(ace_object, EXTRIGHTS_GUID_MAPPING['UserForceChangePassword']):
                        relations.append(self.build_relation(entry, sid, 'ForceChangePassword', '', inherited=is_inherited))

            if ace_object.ace.AceType == 0x00:
                is_inherited = ace_object.has_flag(ACE.INHERITED_ACE)
                mask = ace_object.acedata.mask
                # ACCESS_ALLOWED_ACE
                if mask.has_priv(ACCESS_MASK.GENERIC_ALL):
                    # Generic all includes all other rights, so skip from here
                    relations.append(self.build_relation(entry, sid, 'GenericAll', inherited=is_inherited))
                    continue

                if mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_WRITE_PROP):
                    # Genericwrite is only for properties, don't skip after
                    relations.append(self.build_relation(entry, sid, 'GenericWrite', inherited=is_inherited))

                if mask.has_priv(ACCESS_MASK.WRITE_OWNER):
                    relations.append(self.build_relation(entry, sid, 'WriteOwner', inherited=is_inherited))

                # For users and domain, check extended rights
                if entry._entry_type.lower() in ['user', 'domain'] and mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_CONTROL_ACCESS):
                    relations.append(self.build_relation(entry, sid, 'AllExtendedRights', '', inherited=is_inherited))

                if entry._entry_type.lower() == 'computer' and mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_CONTROL_ACCESS) and \
                'haslaps' in entry.Properties.keys():
                    relations.append(self.build_relation(entry, sid, 'AllExtendedRights', '', inherited=is_inherited))

                if mask.has_priv(ACCESS_MASK.WRITE_DACL):
                    relations.append(self.build_relation(entry, sid, 'WriteDacl', inherited=is_inherited))

        entry.Aces = relations

        return len(relations)


    def _is_member_of(self, member, group):
        if ADDS.AT_DISTINGUISHEDNAME in member.Properties.keys():
            if member.Properties["distinguishedname"] in group.MemberDNs:
                return True

        if member.PrimaryGroupSid == group.ObjectIdentifier:
            return True

        return False


    def _is_nested_group(self, subgroup, group):
        try:
            if subgroup.Properties["distinguishedname"] in group.MemberDNs:
                return True
        except:
            pass
        return False


    def _resolve_object_ou(self, object):
        if "OU=" in object.Properties["distinguishedname"]:
            target_ou = "OU=" + object.Properties["distinguishedname"].split("OU=", 1)[1]
            for ou in self.ous:
                if ou.Properties["distinguishedname"] == target_ou:
                    return ou
        return None

    
    def _resolve_nested_ou(self, nested_ou):
        dn = nested_ou.Properties["distinguishedname"]
        # else is top-level OU
        if len(dn.split("OU=")) > 2:
            target_ou = "OU=" + dn.split("OU=", 2)[2]
            for ou in self.ous:
                if ou.Properties["distinguishedname"] == target_ou:
                    return ou
        else:
            dc = BloodHoundObject.get_domain_component(dn)
            for domain in self.domains:
                if dc == domain.Properties[self.AT_DISTINGUISHEDNAME]:
                    return domain
        return None


    def _lookup_known_sid(self, object, sid):
        known_sid_type = ADUtils.WELLKNOWN_SIDS[sid][1]
        if known_sid_type == "USER":
            bhObject = BloodHoundUser(object)
            target_list = self.users
        elif known_sid_type == "COMPUTER":
            bhObject = BloodHoundComputer(object)
            target_list = self.computers
        elif known_sid_type == "GROUP":
            bhObject = BloodHoundGroup(object)
            target_list = self.groups
        bhObject.Properties["name"] = ADUtils.WELLKNOWN_SIDS[sid][0].upper()
        return bhObject, target_list

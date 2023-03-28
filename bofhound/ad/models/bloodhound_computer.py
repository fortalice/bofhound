import calendar
from datetime import datetime
from bloodhound.ad.utils import ADUtils, LDAP_SID
from .bloodhound_object import BloodHoundObject
from bofhound.logger import OBJ_EXTRA_FMT, ColorScheme
import logging

class BloodHoundComputer(BloodHoundObject):

    COMMON_PROPERTIES = [
        'samaccountname', 'useraccountcontrol', 'distinguishedname',
        'dnshostname', 'samaccounttype', 'objectsid', 'primarygroupid',
        'isdeleted', 'serviceprincipalname', 'msds-allowedtodelegateto',
        'sidhistory', 'whencreated', 'lastlogon', 'lastlogontimestamp',
        'pwdlastset', 'operatingsystem', 'description', 'operatingsystemservicepack',
        'msds-allowedtoactonbehalfofotheridentity', 'ms-mcs-admpwdexpirationtime',
        'domainsid', 'name', 'unconstraineddelegation', 'enabled',
        'trustedtoauth', 'domain', 'highvalue', 'haslaps', 'serviceprincipalnames',
        'memberof'
    ]

    def __init__(self, object):
        super().__init__(object)

        self._entry_type = "Computer"
        self.not_collected = {
            "Collected": False,
            "FailureReason": None,
            "Results": []
        }
        self.uac = None
        self.IsACLProtected = False
        self.hostname = object.get('dnshostname', None)
        self.PrimaryGroupSid = self.get_primary_membership(object) # Returns none if non-existent
        self.sessions = None #['not currently supported by bofhound']
        self.AllowedToDelegate = []
        self.MemberOfDNs = []

        if self.ObjectIdentifier:
            self.Properties['domainsid'] = self.get_domain_sid()
            self.Properties['objectid'] = self.ObjectIdentifier

        if 'dnshostname' in object.keys():
            self.hostname = object.get('dnshostname', None)
            self.Properties['name'] = self.hostname.upper()
            logging.debug(f"Reading Computer object {ColorScheme.computer}{self.Properties['name']}[/]", extra=OBJ_EXTRA_FMT)

        if 'msds-allowedtodelegateto' in object.keys():
            self.AllowedToDelegate = object.get('msds-allowedtodelegateto').split(', ')

        if 'useraccountcontrol' in object.keys():
            self.uac = int(object.get('useraccountcontrol'))
            self.Properties['unconstraineddelegation'] = self.uac & 0x00080000 == 0x00080000
            self.Properties['enabled'] = self.uac & 2 == 0
            self.Properties['trustedtoauth'] = self.uac & 0x01000000 == 0x01000000

        if 'operatingsystem' in object.keys():
            self.Properties['operatingsystem'] = object.get('operatingsystem', 'Unknown')

        if 'operatingsystemservicepack' in object.keys():
            self.Properties['operatingsystem'] += f' {object.get("operatingsystemservicepack")}'

        if 'sidhistory' in object.keys():
            self.Properties['sidhistory'] = [LDAP_SID(bsid).formatCanonical() for bsid in object.get('sidhistory', [])]

        if 'distinguishedname' in object.keys():
            domain = ADUtils.ldap2domain(object.get('distinguishedname')).upper()
            self.Properties['domain'] = domain
            if 'samaccountname' in object.keys() and 'dnshostname' not in object.keys():
                samacctname = object.get("samaccountname")
                if samacctname.endswith("$"):
                    name = f'{samacctname[:-1]}.{domain}'.upper()
                else:
                    name = f'{samacctname}.{domain}'.upper()
                self.Properties["name"] = name
                logging.debug(f"Reading Computer object {ColorScheme.computer}{self.Properties['name']}[/]", extra=OBJ_EXTRA_FMT)

        # TODO: HighValue / AdminCount
        self.Properties['highvalue'] = False

        if 'ms-mcs-admpwdexpirationtime' in object.keys():
            self.Properties['haslaps'] = True

        if 'lastlogontimestamp' in object.keys():
            self.Properties['lastlogontimestamp'] = ADUtils.win_timestamp_to_unix(
                int(object.get('lastlogontimestamp'))
            )

        if 'lastlogon' in object.keys():
            self.Properties['lastlogon'] = ADUtils.win_timestamp_to_unix(
                int(object.get('lastlogon'))
            )

        if 'pwdlastset' in object.keys():
            self.Properties['pwdlastset'] = ADUtils.win_timestamp_to_unix(
                int(object.get('pwdlastset'))
            )

        if 'serviceprincipalname' in object.keys():
            self.Properties['serviceprincipalnames'] = object.get('serviceprincipalname').split(', ')

        if 'description' in object.keys():
            self.Properties['description'] = object.get('description')

        if 'ntsecuritydescriptor' in object.keys():
            self.RawAces = object['ntsecuritydescriptor']

        if 'memberof' in object.keys():
                self.MemberOfDNs = [f'CN={dn.upper()}' for dn in object.get('memberof').split(', CN=')]
                if len(self.MemberOfDNs) > 0:
                    self.MemberOfDNs[0] = self.MemberOfDNs[0][3:]


    def to_json(self, only_common_properties=True):
        data = super().to_json(only_common_properties)
        data["LocalAdmins"] = self.not_collected
        data["PSRemoteUsers"] = self.not_collected
        data["RemoteDesktopUsers"] = self.not_collected
        data["DcomUsers"] = self.not_collected
        data["Sessions"] = self.not_collected
        data["PrivilegedSessions"] = self.not_collected
        data["RegistrySessions"] = self.not_collected
        data["ObjectIdentifier"] = self.ObjectIdentifier
        data["PrimaryGroupSID"] = self.PrimaryGroupSid
        data["AllowedToDelegate"] = self.AllowedToDelegate
        data["AllowedToAct"] = []
        data["Aces"] = self.Aces
        data["IsACLProtected"] = self.IsACLProtected

        # TODO: RBCD
        # Process resource-based constrained delegation
        # _, aces = parse_binary_acl(data,
        #                            'computer',
        #                            object.get('msDS-AllowedToActOnBehalfOfOtherIdentity'),
        #                            self.addc.objecttype_guid_map)
        # outdata = self.aceresolver.resolve_aces(aces)
        # for delegated in outdata:
        #     if delegated['RightName'] == 'Owner':
        #         continue
        #     if delegated['RightName'] == 'GenericAll':
        #         data['AllowedToAct'].append({'MemberId': delegated['PrincipalSID'], 'MemberType': delegated['PrincipalType']})
        #
        # # Run ACL collection if this was not already done centrally
        # if 'acl' in collect and not skip_acl:
        #     _, aces = parse_binary_acl(data,
        #                                'computer',
        #                                object.get('nTSecurityDescriptor',
        #                                                           raw=True),
        #                                self.addc.objecttype_guid_map)
        #     # Parse aces
        #     data['Aces'] = self.aceresolver.resolve_aces(aces)

        return data

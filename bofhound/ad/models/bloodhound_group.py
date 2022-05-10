from bloodhound.ad.utils import ADUtils
from .bloodhound_object import BloodHoundObject
from bofhound.logger import OBJ_EXTRA_FMT, ColorScheme
import logging

class BloodHoundGroup(BloodHoundObject):

    COMMON_PROPERTIES = [
        'distinguishedname', 'samaccountname', 'samaccounttype', 'objectsid',
        'member', 'admincount', 'description', 'whencreated',
        'name', 'domain', 'domainsid', 'distinguishedname', 'admincount',
        'description', 'whencreated'
    ]

    def __init__(self, object):
        super().__init__(object)

        self._entry_type = "Group"
        self.Members = []
        self.Aces = []
        self.IsDeleted = False
        self.IsACLProtected = False
        self.MemberDNs = []
        self.IsACLProtected = False

        if 'distinguishedname' in object.keys() and 'samaccountname' in object.keys():
            domain = ADUtils.ldap2domain(object.get('distinguishedname')).upper()
            name = f'{object.get("samaccountname")}@{domain}'.upper()
            self.Properties["name"] = name
            self.Properties["domain"] = domain
            logging.debug(f"Reading Group object {ColorScheme.group}{name}[/]", extra=OBJ_EXTRA_FMT)

        if 'objectsid' in object.keys():
            #objectid = BloodHoundObject.get_sid(object.get('objectsid', None), object.get('distinguishedname', None))
            objectid = object.get('objectsid')
            self.ObjectIdentifier = objectid
            self.Properties["domainsid"] = objectid.rsplit('-',1)[0]


        if 'distinguishedname' in object.keys():
            self.Properties["distinguishedname"] = object.get('distinguishedname', None).upper()

        if 'admincount' in object.keys():
            self.Properties["admincount"] = int(object.get('admincount')) == 1 # do not move this lower, it may break imports for users

        if 'description' in object.keys():
            self.Properties["description"] = object.get('description')

        if 'whencreated' in object.keys():
            self.Properties["whencreated"] = object.get('whencreated')

        if 'member' in object.keys():
            self.MemberDNs = [f'CN={dn.upper()}' for dn in object.get('member').split(', CN=')]
            if len(self.MemberDNs) > 0:
                self.MemberDNs[0] = self.MemberDNs[0][3:]

        if 'ntsecuritydescriptor' in object.keys():
            self.RawAces = object['ntsecuritydescriptor']


    def add_group_member(self, object, object_type):
        member = {
            "ObjectIdentifier": object.ObjectIdentifier,
            "ObjectType": object_type
        }
        self.Members.append(member)


    def to_json(self, only_common_properties=True):
        group = super().to_json(only_common_properties)
        group["ObjectIdentifier"] = self.ObjectIdentifier
        group["Aces"] = self.Aces
        group["Members"] = self.Members
        group["IsDeleted"] = self.IsDeleted
        group["IsACLProtected"] = self.IsACLProtected

        return group

from bloodhound.ad.utils import ADUtils
from .bloodhound_object import BloodHoundObject
from bofhound.logger import OBJ_EXTRA_FMT, ColorScheme
import logging

class BloodHoundDomain(BloodHoundObject):

    COMMON_PROPERTIES = [
        'distinguishedname', 'objectid', 'description', 'whencreated',
        'functionallevel', 'domain',
        'name', 'highvalue'
    ]

    def __init__(self, object):
        super().__init__(object)

        self._entry_type = "Domain"
        self.GPLinks = []
        level_id = object.get('msds-behavior-version', 0)
        try:
            functional_level = ADUtils.FUNCTIONAL_LEVELS[int(level_id)]
        except KeyError:
            functional_level = 'Unknown'

        dc = None
        if 'distinguishedname' in object.keys():
            self.Properties["name"] = ADUtils.ldap2domain(object.get('distinguishedname').upper())
            self.Properties["domain"] = self.Properties["name"]
            dc = BloodHoundObject.get_domain_component(object.get('distinguishedname').upper())
            logging.debug(f"Reading Domain object {ColorScheme.domain}{self.Properties['name']}[/]", extra=OBJ_EXTRA_FMT)

        if 'objectsid' in object.keys():
            self.Properties["objectid"] = object.get('objectsid')

        if 'distinguishedname' in object.keys():
            self.Properties['distinguishedname'] = object.get('distinguishedname').upper()

        if 'description' in object.keys():
            self.Properties["description"] = object.get('description')

        if 'ntsecuritydescriptor' in object.keys():
            self.RawAces = object['ntsecuritydescriptor']
        
        if 'gplink' in object.keys():
            # [['DN1', 'GPLinkOptions1'], ['DN2', 'GPLinkOptions2'], ...]
            self.GPLinks = [link.upper()[:-1].split(';') for link in object.get('gplink').split('[LDAP//')][1:]

        self.Properties["highvalue"] = True

        self.Properties["functionallevel"] = functional_level

        self.Trusts = []
        self.Aces = []
        self.Links = []
        self.ChildObjects = []
        self.GPOChanges = {
            "AffectedComputers": [],
            "DcomUsers": [],
            "LocalAdmins": [],
            "PSRemoteUsers": [],
            "RemoteDesktopUsers": []
        }
        self.IsDeleted = False
        self.IsACLProtected = False


    def to_json(self, only_common_properties=True):
        domain = super().to_json(only_common_properties)

        domain["ObjectIdentifier"] = self.ObjectIdentifier
        domain["Trusts"] = self.Trusts
        # The below is all unsupported as of now.
        domain["Aces"] = self.Aces
        domain["Links"] = self.Links
        domain["ChildObjects"] = self.ChildObjects
        domain["GPOChanges"] = self.GPOChanges
        domain["IsDeleted"] = self.IsDeleted
        domain["IsACLProtected"] = self.IsACLProtected

        return domain

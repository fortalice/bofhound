from bloodhound.ad.utils import ADUtils
from .bloodhound_object import BloodHoundObject
from bofhound.logger import OBJ_EXTRA_FMT, ColorScheme
import logging

class BloodHoundGPO(BloodHoundObject):

    COMMON_PROPERTIES = [
        'distinguishedname', 'whencreated',
        'domain', 'domainsid', 'name', 'highvalue',
        'description', 'gpcpath'
    ]

    def __init__(self, object):
        super().__init__(object)

        self._entry_type = "GPO"
        
        if 'distinguishedname' in object.keys() and 'displayname' in object.keys():
            self.Properties["domain"] = ADUtils.ldap2domain(object.get('distinguishedname').upper())
            self.Properties["name"] = f"{object.get('displayname').upper()}@{self.Properties['domain']}"
            logging.debug(f"Reading GPO object {ColorScheme.gpo}{self.Properties['name']}[/]", extra=OBJ_EXTRA_FMT)

        if 'objectguid' in object.keys():
            self.ObjectIdentifier = object.get('objectguid').upper()
            #self.Properties["objectid"] = object.get('objectguid')

        if 'ntsecuritydescriptor' in object.keys():
            self.RawAces = object['ntsecuritydescriptor']

        if 'description' in object.keys():
            self.Properties["description"] = object.get('description')

        if 'gpcfilesyspath' in object.keys():
            self.Properties["gpcpath"] = object.get('gpcfilesyspath')

        self.Properties["highvalue"] = False

        self.Aces = []

        self.IsDeleted = False
        self.IsACLProtected = False

    def to_json(self, only_common_properties=True):
        gpo = super().to_json(only_common_properties)

        gpo["ObjectIdentifier"] = self.ObjectIdentifier
        # The below is all unsupported as of now.
        gpo["Aces"] = self.Aces
        gpo["IsDeleted"] = self.IsDeleted
        gpo["IsACLProtected"] = self.IsACLProtected

        return gpo

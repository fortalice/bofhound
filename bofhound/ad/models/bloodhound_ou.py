from distutils.ccompiler import gen_preprocess_options
from bloodhound.ad.utils import ADUtils
from .bloodhound_object import BloodHoundObject
from bofhound.logger import OBJ_EXTRA_FMT, ColorScheme
import logging

class BloodHoundOU(BloodHoundObject):

    COMMON_PROPERTIES = [
        'distinguishedname', 'whencreated',
        'domain', 'domainsid', 'name', 'highvalue', 'description',
        'blocksinheritance'
    ]

    def __init__(self, object):
        super().__init__(object)

        self._entry_type = "OU"
        self.GPLinks = []
        self.Properties["blocksinheritance"] = False
        
        if 'distinguishedname' in object.keys() and 'ou' in object.keys():
            self.Properties["domain"] = ADUtils.ldap2domain(object.get('distinguishedname').upper())
            self.Properties["name"] = f"{object.get('ou').upper()}@{self.Properties['domain']}"
            logging.debug(f"Reading OU object {ColorScheme.ou}{self.Properties['name']}[/]", extra=OBJ_EXTRA_FMT)

        if 'objectguid' in object.keys():
            self.ObjectIdentifier = object.get('objectguid').upper()
            #self.Properties["objectid"] = object.get('objectguid')

        if 'ntsecuritydescriptor' in object.keys():
            self.RawAces = object['ntsecuritydescriptor']

        if 'description' in object.keys():
            self.Properties["description"] = object.get('description')

        if 'gplink' in object.keys():
            # [['DN1', 'GPLinkOptions1'], ['DN2', 'GPLinkOptions2'], ...]
            self.GPLinks = [link.upper()[:-1].split(';') for link in object.get('gplink').split('[LDAP//')][1:]

        if 'gpoptions' in object.keys():
            gpoptions = object.get('gpoptions')
            if gpoptions == '1':
                self.Properties["blocksinheritance"] = True

        self.Properties["highvalue"] = False

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
        ou = super().to_json(only_common_properties)

        ou["ObjectIdentifier"] = self.ObjectIdentifier
        # The below is all unsupported as of now.
        ou["Aces"] = self.Aces
        ou["Links"] = self.Links
        ou["ChildObjects"] = self.ChildObjects
        ou["GPOChanges"] = self.GPOChanges
        ou["IsDeleted"] = self.IsDeleted
        ou["IsACLProtected"] = self.IsACLProtected

        return ou

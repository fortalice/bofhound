from bofhound.logger import OBJ_EXTRA_FMT, ColorScheme
from bofhound.ad.models.bloodhound_object import BloodHoundObject
from bloodhound.ad.utils import ADUtils
from bloodhound.ad.trusts import ADDomainTrust
import logging

class BloodHoundDomainTrust(object):
    
    def __init__(self, object):
        # Property for internal processing
        self.LocalDomainDn = ''

        # Property that holds final dict for domain JSON
        # {
        #     "TargetDomainName": "",
        #     "TargetDomainSid": "",
        #     "IsTransitive": "",
        #     "TrustDirection": "",
        #     "TrustType": "",
        #     "SidFilteringEnabled": ""
        # }
        self.TrustProperties = None

        if 'distinguishedname' in object.keys() and 'trustpartner' in object.keys() and \
            'trustdirection' in object.keys() and 'trusttype' in object.keys() and 'trustattributes' in object.keys():
            self.LocalDomainDn = BloodHoundObject.get_domain_component(object.get('distinguishedname')).upper()
            trust_partner = object.get('trustpartner').upper()
            domain = ADUtils.ldap2domain(object.get('distinguishedname')).upper()
            logging.debug(f'Reading trust relationship between {ColorScheme.domain}{domain}[/] and {ColorScheme.domain}{trust_partner}[/]', extra=OBJ_EXTRA_FMT)
            trust = ADDomainTrust(trust_partner, int(object.get('trustdirection')), object.get('trusttype'), int(object.get('trustattributes')), '')
            self.TrustProperties = trust.to_output()
    

    # Leaving the sid property blank, or setting it to a static value causes 
    # BloodHound to improperly display trusts. Each trusted domain seems to 
    # require a unique SID
    def set_temporary_sid(self, indx):
        self.TrustProperties['TargetDomainSid'] = f'S-1-5-21-{indx}'






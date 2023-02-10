import pytest
from bofhound.ad import ADDS
from bofhound.ad.models import BloodHoundObject, BloodHoundUser, BloodHoundComputer
from tests.test_data import testdata_ldapsearchbof_beacon_257_objects


@pytest.fixture
def raw_user():
    yield {
        'objectclass': 'top, person, organizationalPerson, user',
        'cn': 'Administrator',
        'distinguishedname': 'CN=Administrator,CN=Users,DC=test,DC=lab',
        'memberof': 'CN=Group Policy Creator Owners,CN=Users,DC=test,DC=lab, CN=Domain Admins,CN=Users,DC=test,DC=lab, CN=Enterprise Admins,CN=Users,DC=test,DC=lab, CN=Schema Admins,CN=Users,DC=test,DC=lab, CN=Administrators,CN=Builtin,DC=test,DC=lab',
        'ntsecuritydescriptor': 'AQAEnIgEAACkBAAAAAAAABQAAAAEAHQEGAAAAAUAPAAQAAAAAwAAAABCFkzAINARp2gAqgBuBSkUzChINxS8RZsHrW8BXl8oAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAABCFkzAINARp2gAqgBuBSm6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAABAgIF+ledARkCAAwE/C1M8UzChINxS8RZsHrW8BXl8oAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAABAgIF+ledARkCAAwE/C1M+6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAEDCCrypedARkCAAwE/C1M8UzChINxS8RZsHrW8BXl8oAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAEDCCrypedARkCAAwE/C1M+6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAEIvulmiedARkCAAwE/C088UzChINxS8RZsHrW8BXl8oAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAEIvulmiedARkCAAwE/C08+6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAPiIcAPhCtIRtCIAoMlo+TkUzChINxS8RZsHrW8BXl8oAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAPiIcAPhCtIRtCIAoMlo+Tm6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAOAAwAAAAAQAAAH96lr/mDdARooUAqgAwSeIBBQAAAAAABRUAAAB/ivvSK592RVonQNMFAgAABQAsABAAAAABAAAAHbGpRq5gWkC36P+KWNRW0gECAAAAAAAFIAAAADACAAAFACwAMAAAAAEAAAAcmrZtIpTREa69AAD4A2fBAQIAAAAAAAUgAAAAMQIAAAUALAAwAAAAAQAAAGK8BVjJvShEpeKFag9MGF4BAgAAAAAABSAAAAAxAgAABQAsAJQAAgACAAAAFMwoSDcUvEWbB61vAV5fKAECAAAAAAAFIAAAACoCAAAFACwAlAACAAIAAAC6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAKAAAAQAAAQAAAFMacqsvHtARmBkAqgBAUpsBAQAAAAAAAQAAAAAFACgAAAEAAAEAAABTGnKrLx7QEZgZAKoAQFKbAQEAAAAAAAUKAAAABQIoADABAAABAAAA3kfmkW/ZcEuVV9Y/9PPM2AEBAAAAAAAFCgAAAAAAJAC/AQ4AAQUAAAAAAAUVAAAAf4r70iufdkVaJ0DTAAIAAAAAJAC/AQ4AAQUAAAAAAAUVAAAAf4r70iufdkVaJ0DTBwIAAAAAGAC/AQ8AAQIAAAAAAAUgAAAAIAIAAAAAFACUAAIAAQEAAAAAAAULAAAAAAAUAP8BDwABAQAAAAAABRIAAAABBQAAAAAABRUAAAB/ivvSK592RVonQNMAAgAAAQUAAAAAAAUVAAAAf4r70iufdkVaJ0DTAAIAAA==',
        'name': 'Administrator',
        'objectguid': '7b79190e-285c-40fc-8300-0584b3ee974b',
        'primarygroupid': '513',
        'objectsid': 'S-1-5-21-3539700351-1165401899-3544196954-500',
        'samaccountname': 'Administrator',
        'samaccounttype': '805306368',
        'objectcategory': 'CN=Person,CN=Schema,CN=Configuration,DC=test,DC=lab'
    }


@pytest.fixture
def raw_trust():
    yield {
        'cn': 'child.windomain.local',
        'distinguishedname': 'CN=child.windomain.local,CN=System,DC=windomain,DC=local',
        'flatname': 'CHILD',
        'instancetype': '4',
        'name': 'child.windomain.local',
        'objectcategory': 'CN=Trusted-Domain,CN=Schema,CN=Configuration,DC=windomain,DC=local',
        'objectclass': 'top, leaf, trustedDomain',
        'objectguid': 'ccb3617a-af7a-4671-8c1d-aadbab087df1',
        'trustattributes': '32',
        'trustdirection': '3',
        'trustpartner': 'child.windomain.local',
        'trustposixfffset': '-2147483648',
        'trusttype': '2'
    }        
    

@pytest.fixture
def raw_domain():
    yield {
        'creationtime': '132979682115640324',
        'dc': 'windomain',
        'distinguishedname': 'DC=windomain,DC=local',
        'forcelogoff': '-9223372036854775808',
        'gplink': '[LDAP://cn={F08300B1-8BFF-4866-8524-14C03B50D991},cn=policies,cn=system,DC=windomain,DC=local;0][LDAP://cn={79081BF9-A672-4475-A982-D622CC600A49},cn=policies,cn=system,DC=windomain,DC=local;0][LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=windomain,DC=local;0]',
        'instancetype': '5',
        'lockoutobservationwindow': '-18000000000',
        'lockoutduration': '-18000000000',
        'lockoutthreshold': '0',
        'masteredBy': 'CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=windomain,DC=local',
        'name': 'windomain',
        'nextrid': '1000',
        'objectcategory': 'CN=Domain-DNS,CN=Schema,CN=Configuration,DC=windomain,DC=local',
        'objectclass': 'top, domain, domainDNS',
        'objectguid': '2825688f-74fd-460c-8b32-6b95b149f6ae',
        'objectsid': 'S-1-5-21-3539700351-1165401899-3544196954',
        'otherwellknownobjects': 'B:32:683A24E2E8164BD3AF86AC3C2CF3F981:CN=Keys,DC=windomain,DC=local, B:32:1EB93889E40C45DF9F0C64D23BBB6237:CN=Managed Service Accounts,DC=windomain,DC=local',
        'pwdhistorylength': '24',
        'pwdproperties': '1',
        'ridmanagerreference': 'CN=RID Manager$,CN=System,DC=windomain,DC=local',
        'serverstate': '1',
        'subrefs': 'DC=ForestDnsZones,DC=windomain,DC=local, DC=DomainDnsZones,DC=windomain,DC=local, CN=Configuration,DC=windomain,DC=local',
        'systemflags': '-1946157056',
        'wellknownobjects': 'B:32:6227F0AF1FC2410D8E3BB10615BB5B0F:CN=NTDS Quotas,DC=windomain,DC=local, B:32:F4BE92A4C777485E878E9421D53087DB:CN=Microsoft,CN=Program Data,DC=windomain,DC=local, B:32:09460C08AE1E4A4EA0F64AEE7DAA1E5A:CN=Program Data,DC=windomain,DC=local, B:32:22B70C67D56E4EFB91E9300FCA3DC1AA:CN=ForeignSecurityPrincipals,DC=windomain,DC=local, B:32:18E2EA80684F11D2B9AA00C04F79F805:CN=Deleted Objects,DC=windomain,DC=local, B:32:2FBAC1870ADE11D297C400C04FD8D5CD:CN=Infrastructure,DC=windomain,DC=local, B:32:AB8153B7768811D1ADED00C04FD8D5CD:CN=LostAndFound,DC=windomain,DC=local, B:32:AB1D30F3768811D1ADED00C04FD8D5CD:CN=System,DC=windomain,DC=local, B:32:A361B2FFFFD211D1AA4B00C04FD7D83A:OU=Domain Controllers,DC=windomain,DC=local, B:32:AA312825768811D1ADED00C04FD8D5CD:CN=Computers,DC=windomain,DC=local, B:32:A9D1CA15768811D1ADED00C04FD8D5CD:CN=Users,DC=windomain,DC=local'
    }


def test_import_objects_singleSchema():
    adds = ADDS()
    adds.import_objects([{ADDS.AT_SCHEMAIDGUID: 'ABWwRRnE0RG7yQCAx2ZwwA==', ADDS.AT_NAME: 'ANR'}])

    assert len(adds.schemas) == 1


def test_import_objects_noAccountType(raw_user):
    adds = ADDS()
    raw_user.pop(ADDS.AT_SAMACCOUNTTYPE)

    adds.import_objects([raw_user])

    assert (len(adds.users) == len(adds.computers) == len(adds.groups) \
            == len(adds.trustaccounts) == len(adds.domains) == 0) \
            and len(adds.unknown_objects) == 1


def test_import_objects_expectedValuesFromStandardDataSet(testdata_ldapsearchbof_beacon_257_objects):
    adds = ADDS()
    adds.import_objects(testdata_ldapsearchbof_beacon_257_objects)

    assert len(adds.SID_MAP) == 68
    assert len(adds.DN_MAP) == 68
    assert len(adds.DOMAIN_MAP) == 1
    assert len(adds.users) == 5
    assert len(adds.computers) == 4
    assert len(adds.groups) == 53
    assert len(adds.domains) == 1
    assert len(adds.schemas) == 0
    assert len(adds.trustaccounts) == 0
    assert len(adds.ous) == 1
    assert len(adds.gpos) == 4
    assert len(adds.unknown_objects) == 189


def test_import_objects_MinimalObject(raw_user):
    expected_sid = 'S-1-5-21-3539700351-1165401899-3544196954-500'
    expected_dn = 'CN=ADMINISTRATOR,CN=USERS,DC=TEST,DC=LAB'

    adds = ADDS()
    adds.import_objects([raw_user])

    sid_map_object = adds.SID_MAP[expected_sid]
    dn_map_object = adds.DN_MAP[expected_dn]

    assert len(adds.SID_MAP) == 1
    assert sid_map_object.Properties[ADDS.AT_DISTINGUISHEDNAME] == expected_dn
    assert dn_map_object.ObjectIdentifier == expected_sid


def test_import_objects_DuplicateObject(raw_user):
    expected_sid = 'S-1-5-21-3539700351-1165401899-3544196954-500'
    expected_dn = 'CN=ADMINISTRATOR,CN=USERS,DC=TEST,DC=LAB'

    adds = ADDS()
    adds.import_objects([raw_user, raw_user])

    sid_map_object = adds.SID_MAP[expected_sid]
    dn_map_object = adds.DN_MAP[expected_dn]

    assert len(adds.SID_MAP) == 1
    assert sid_map_object.Properties[ADDS.AT_DISTINGUISHEDNAME] == expected_dn
    assert dn_map_object.ObjectIdentifier == expected_sid


def test_import_unique_trust(raw_trust, raw_domain):
    expected_domain_count = 1
    expected_trust_count = 1

    adds = ADDS()

    adds = ADDS()
    adds.import_objects([raw_domain, raw_trust])
    adds.process()

    assert len(adds.domains) == expected_domain_count
    assert len(adds.domains[0].Trusts) == expected_trust_count


def test_import_duplicate_trust(raw_trust, raw_domain):
    expected_domain_count = 1
    expected_trust_count = 1

    adds = ADDS()

    adds = ADDS()
    adds.import_objects([raw_domain, raw_trust, raw_trust])
    adds.process()

    assert len(adds.domains) == expected_domain_count
    assert len(adds.domains[0].Trusts) == expected_trust_count
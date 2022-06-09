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


def test_import_objects_singleSchema():
    adds = ADDS()
    adds.import_objects([{ADDS.AT_SCHEMAIDGUID: 'de9b4c5c-ff5a-4866-8501-caa2cd7c075c'}])

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
    assert len(adds.users) == 4
    assert len(adds.computers) == 4
    assert len(adds.groups) == 54
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


import pytest
from bofhound.ad.models.bloodhound_object import BloodHoundObject


@pytest.fixture
def parsed_full_user():
    yield {
        'objectclass': 'top, person, organizationalPerson, user',
        'cn': 'Administrator',
        'description': 'Built-in account for administering the computer/domain',
        'distinguishedname': 'CN=Administrator,CN=Users,DC=test,DC=lab',
        'instancetype': '4',
        'whencreated': '20210826173042.0Z',
        'whenchanged': '20220403141221.0Z',
        'usncreated': '8196',
        'memberof': 'CN=Group Policy Creator Owners,CN=Users,DC=test,DC=lab, CN=Domain Admins,CN=Users,DC=test,DC=lab, CN=Enterprise Admins,CN=Users,DC=test,DC=lab, CN=Schema Admins,CN=Users,DC=test,DC=lab, CN=Administrators,CN=Builtin,DC=test,DC=lab',
        'usnchanged': '63985',
        'ntsecuritydescriptor': 'AQAEnIgEAACkBAAAAAAAABQAAAAEAHQEGAAAAAUAPAAQAAAAAwAAAABCFkzAINARp2gAqgBuBSkUzChINxS8RZsHrW8BXl8oAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAABCFkzAINARp2gAqgBuBSm6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAABAgIF+ledARkCAAwE/C1M8UzChINxS8RZsHrW8BXl8oAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAABAgIF+ledARkCAAwE/C1M+6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAEDCCrypedARkCAAwE/C1M8UzChINxS8RZsHrW8BXl8oAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAEDCCrypedARkCAAwE/C1M+6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAEIvulmiedARkCAAwE/C088UzChINxS8RZsHrW8BXl8oAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAEIvulmiedARkCAAwE/C08+6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAPiIcAPhCtIRtCIAoMlo+TkUzChINxS8RZsHrW8BXl8oAQIAAAAAAAUgAAAAKgIAAAUAPAAQAAAAAwAAAPiIcAPhCtIRtCIAoMlo+Tm6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAOAAwAAAAAQAAAH96lr/mDdARooUAqgAwSeIBBQAAAAAABRUAAAB/ivvSK592RVonQNMFAgAABQAsABAAAAABAAAAHbGpRq5gWkC36P+KWNRW0gECAAAAAAAFIAAAADACAAAFACwAMAAAAAEAAAAcmrZtIpTREa69AAD4A2fBAQIAAAAAAAUgAAAAMQIAAAUALAAwAAAAAQAAAGK8BVjJvShEpeKFag9MGF4BAgAAAAAABSAAAAAxAgAABQAsAJQAAgACAAAAFMwoSDcUvEWbB61vAV5fKAECAAAAAAAFIAAAACoCAAAFACwAlAACAAIAAAC6epa/5g3QEaKFAKoAMEniAQIAAAAAAAUgAAAAKgIAAAUAKAAAAQAAAQAAAFMacqsvHtARmBkAqgBAUpsBAQAAAAAAAQAAAAAFACgAAAEAAAEAAABTGnKrLx7QEZgZAKoAQFKbAQEAAAAAAAUKAAAABQIoADABAAABAAAA3kfmkW/ZcEuVV9Y/9PPM2AEBAAAAAAAFCgAAAAAAJAC/AQ4AAQUAAAAAAAUVAAAAf4r70iufdkVaJ0DTAAIAAAAAJAC/AQ4AAQUAAAAAAAUVAAAAf4r70iufdkVaJ0DTBwIAAAAAGAC/AQ8AAQIAAAAAAAUgAAAAIAIAAAAAFACUAAIAAQEAAAAAAAULAAAAAAAUAP8BDwABAQAAAAAABRIAAAABBQAAAAAABRUAAAB/ivvSK592RVonQNMAAgAAAQUAAAAAAAUVAAAAf4r70iufdkVaJ0DTAAIAAA==',
        'name': 'Administrator',
        'objectguid': '7b79190e-285c-40fc-8300-0584b3ee974b',
        'useraccountcontrol': '66048',
        'badpwdcount': '0',
        'codepage': '0',
        'countrycode': '0',
        'badpasswordtime': '132919604027661803',
        'lastlogoff': '0',
        'lastlogon': '132940422420644609',
        'logonhours': '?????????????????????',
        'pwdlastset': '132836191102481334',
        'primarygroupid': '513',
        'objectsid': 'S-1-5-21-3539700351-1165401899-3544196954-500',
        'admincount': '1',
        'accountexpires': '0',
        'logoncount': '208',
        'samaccountname': 'Administrator',
        'samaccounttype': '805306368',
        'objectcategory': 'CN=Person,CN=Schema,CN=Configuration,DC=test,DC=lab',
        'iscriticalsystemobject': 'TRUE',
        'dscorepropagationdata': '20210826202656.0Z, 20210826202656.0Z, 20210826175542.0Z, 16010101181216.0Z',
        'lastlogontimestamp': '132934687411151999',
        'msds-supportedencryptiontypes': '0'
    }


def test_constructor_firstEmptyObject():
    bho = BloodHoundObject()


def test_constructor_basicFullObject(parsed_full_user):
    bho = BloodHoundObject(parsed_full_user)

    assert bho.ObjectIdentifier == 'S-1-5-21-3539700351-1165401899-3544196954-500'
    assert bho.get_distinguished_name() == 'CN=ADMINISTRATOR,CN=USERS,DC=TEST,DC=LAB'
    assert bho.get_domain_sid() == 'S-1-5-21-3539700351-1165401899-3544196954'
    assert bho.Properties['whencreated'] == 1629999042

def test_merge_entry_fullOverwrite():
    bho1 = BloodHoundObject({
        'objectsid': '024929',
        'otherproperty': 1
    })

    bho2 = BloodHoundObject({
        'objectsid': '024930',
        'otherproperty': 2
    })

    bho1.merge_entry(bho2, base_preference=False)
    assert bho1.ObjectIdentifier == '024930'
    assert bho1.get_property('otherproperty') == 2


def test_merge_entry_preferBase():
    bho1 = BloodHoundObject({
        'objectsid': '024929',
        'otherproperty': 1
    })

    bho2 = BloodHoundObject({
        'objectsid': '024930',
        'otherproperty': 2
    })

    bho1.merge_entry(bho2, base_preference=True)
    assert bho1.ObjectIdentifier == '024929'
    assert bho1.get_property('otherproperty') == 1


def test_merge_entry_nonExistentBaseAttribute():
    bho1 = BloodHoundObject()
    bho2 = BloodHoundObject({
        'objectsid': '024930',
        'otherproperty': 2
    })

    bho1.merge_entry(bho2)
    assert bho1.ObjectIdentifier == '024930'


def test_merge_entry_nonExistentSourceAttribute():
    bho1 = BloodHoundObject({
        'objectsid': '024929',
        'otherproperty': 1
    })
    bho2 = BloodHoundObject()

    bho1.merge_entry(bho2, base_preference=True)
    assert bho1.ObjectIdentifier == '024929'


def test_merge_entry_emptyBaseAttributes():
    bho1 = BloodHoundObject({
        'objectsid': '',
        'distinguishedname': ''
    })
    bho2 = BloodHoundObject({
        'objectsid': '024929',
        'distinguishedname': 'DC=value'
    })

    bho1.merge_entry(bho2, base_preference=True)
    assert bho1.ObjectIdentifier == '024929'
    assert bho1.get_property('distinguishedname') == 'DC=VALUE'


def test_merge_entry_emptySourceAttributes():
    bho1 = BloodHoundObject({
        'objectsid': '',
        'distinguishedname': ''
    })
    bho2 = BloodHoundObject({
        'objectsid': '024929',
        'distinguishedname': 'DC=value'
    })

    bho2.merge_entry(bho1)
    assert bho2.ObjectIdentifier == '024929'
    assert bho2.Properties['distinguishedname'] == 'DC=VALUE'

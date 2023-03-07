import os
import pytest
from bofhound.ad.models.bloodhound_computer import BloodHoundComputer
from bofhound.parsers.brc4_ldap_sentinel import Brc4LdapSentinelParser
from bofhound.ad.adds import ADDS
from tests.test_data import *


def test_parse_file_ldapsearchpyNormalFile(brc4ldapsentinel_standard_file_252):
    parsed_objects = Brc4LdapSentinelParser.parse_file(brc4ldapsentinel_standard_file_252)
    assert len(parsed_objects) == 252


def test_parse_data_computer():
    data = """[+] AccountDisabled                    : FALSE

+-------------------------------------------------------------------+
[+] objectClass                        : top; person; organizationalPerson; user; computer
[+] cn                                 : WS1
[+] distinguishedName                  : CN=WS1,CN=Computers,DC=castle,DC=lab
[+] instanceType                       : 4
[+] whenCreated                        : 3/1/2023 5:33:52 PM
[+] whenChanged                        : 3/1/2023 5:34:27 PM
[+] uSNCreated                         : high: 0 low: 12880
[+] uSNChanged                         : high: 0 low: 12894
[+] name                               : WS1
[+] objectGUID                         : {7FE62E98-AA0F-4DA0-98DC-80B22ED80B24}
[+] userAccountControl                 : 4096
[+] badPwdCount                        : 0
[+] codePage                           : 0
[+] countryCode                        : 0
[+] badPasswordTime                    : Value not set
[+] lastLogoff                         : Value not set
[+] lastLogon                          : 3/7/2023 10:14:50 AM
[+] localPolicyFlags                   : 0
[+] pwdLastSet                         : 3/1/2023 9:33:52 AM
[+] primaryGroupID                     : 515
[+] objectSid                          : S-1-5-21-4033075623-2380760593-384075220-1104
[+] accountExpires                     : Never expires
[+] logonCount                         : 23
[+] sAMAccountName                     : WS1$
[+] sAMAccountType                     : 805306369
[+] operatingSystem                    : Windows 10 Pro N
[+] operatingSystemVersion             : 10.0 (19045)
[+] dNSHostName                        : ws1.castle.lab
[+] servicePrincipalName               : RestrictedKrbHost/WS1; HOST/WS1; RestrictedKrbHost/ws1.castle.lab; HOST/ws1.castle.lab
[+] objectCategory                     : CN=Computer,CN=Schema,CN=Configuration,DC=castle,DC=lab
[+] isCriticalSystemObject             : FALSE
[+] dSCorePropagationData              : 1/1/1601
[+] lastLogonTimestamp                 : 3/1/2023 9:34:27 AM
[+] msDS-SupportedEncryptionTypes      : 28
[+] ADsPath                            : LDAP://CN=WS1,CN=Computers,DC=castle,DC=lab
[+] PasswordSettings                   : Never expires
[+] AccountDisabled                    : FALSE

+-------------------------------------------------------------------+
    """
    parsed_objects = Brc4LdapSentinelParser.parse_data(data)

    assert len(parsed_objects) == 1
    assert 'operatingsystem' in parsed_objects[0].keys()
    assert 'operatingsystem' in BloodHoundComputer(parsed_objects[0]).Properties.keys()


def test_parse_lower_data_computer():
    data = """[+] accountdisabled                    : false

+-------------------------------------------------------------------+
[+] objectclass                        : top; person; organizationalperson; user; computer
[+] cn                                 : ws1
[+] distinguishedname                  : cn=ws1,cn=computers,dc=castle,dc=lab
[+] instancetype                       : 4
[+] whencreated                        : 3/1/2023 5:33:52 pm
[+] whenchanged                        : 3/1/2023 5:34:27 pm
[+] usncreated                         : high: 0 low: 12880
[+] usnchanged                         : high: 0 low: 12894
[+] name                               : ws1
[+] objectguid                         : {7fe62e98-aa0f-4da0-98dc-80b22ed80b24}
[+] useraccountcontrol                 : 4096
[+] badpwdcount                        : 0
[+] codepage                           : 0
[+] countrycode                        : 0
[+] badpasswordtime                    : value not set
[+] lastlogoff                         : value not set
[+] lastlogon                          : 3/7/2023 10:14:50 am
[+] localpolicyflags                   : 0
[+] pwdlastset                         : 3/1/2023 9:33:52 am
[+] primarygroupid                     : 515
[+] objectsid                          : s-1-5-21-4033075623-2380760593-384075220-1104
[+] accountexpires                     : never expires
[+] logoncount                         : 23
[+] samaccountname                     : ws1$
[+] samaccounttype                     : 805306369
[+] operatingsystem                    : windows 10 pro n
[+] operatingsystemversion             : 10.0 (19045)
[+] dnshostname                        : ws1.castle.lab
[+] serviceprincipalname               : restrictedkrbhost/ws1; host/ws1; restrictedkrbhost/ws1.castle.lab; host/ws1.castle.lab
[+] objectcategory                     : cn=computer,cn=schema,cn=configuration,dc=castle,dc=lab
[+] iscriticalsystemobject             : false
[+] dscorepropagationdata              : 1/1/1601
[+] lastlogontimestamp                 : 3/1/2023 9:34:27 am
[+] msds-supportedencryptiontypes      : 28
[+] adspath                            : ldap://cn=ws1,cn=computers,dc=castle,dc=lab
[+] passwordsettings                   : never expires
[+] accountdisabled                    : false

+-------------------------------------------------------------------+
    """
    parsed_objects = Brc4LdapSentinelParser.parse_data(data)
    ad = ADDS()
    ad.import_objects(parsed_objects)

    assert len(parsed_objects) == 1
    assert 'operatingsystem' in parsed_objects[0].keys()
    assert 'operatingsystem' in BloodHoundComputer(parsed_objects[0]).Properties.keys()
    assert len(ad.computers) == 1


def test_parse_data_computer_data_missing_dn():
    data = """[+] AccountDisabled                    : FALSE

+-------------------------------------------------------------------+
[+] objectClass                        : top; person; organizationalPerson; user; computer
[+] cn                                 : WS1
[+] instanceType                       : 4
[+] whenCreated                        : 3/1/2023 5:33:52 PM
[+] whenChanged                        : 3/1/2023 5:34:27 PM
[+] uSNCreated                         : high: 0 low: 12880
[+] uSNChanged                         : high: 0 low: 12894
[+] name                               : WS1
[+] objectGUID                         : {7FE62E98-AA0F-4DA0-98DC-80B22ED80B24}
[+] userAccountControl                 : 4096
[+] badPwdCount                        : 0
[+] codePage                           : 0
[+] countryCode                        : 0
[+] badPasswordTime                    : Value not set
[+] lastLogoff                         : Value not set
[+] lastLogon                          : 3/7/2023 10:14:50 AM
[+] localPolicyFlags                   : 0
[+] pwdLastSet                         : 3/1/2023 9:33:52 AM
[+] primaryGroupID                     : 515
[+] objectSid                          : S-1-5-21-4033075623-2380760593-384075220-1104
[+] accountExpires                     : Never expires
[+] logonCount                         : 23
[+] sAMAccountName                     : WS1$
[+] sAMAccountType                     : 805306369
[+] operatingSystem                    : Windows 10 Pro N
[+] operatingSystemVersion             : 10.0 (19045)
[+] dNSHostName                        : ws1.castle.lab
[+] servicePrincipalName               : RestrictedKrbHost/WS1; HOST/WS1; RestrictedKrbHost/ws1.castle.lab; HOST/ws1.castle.lab
[+] objectCategory                     : CN=Computer,CN=Schema,CN=Configuration,DC=castle,DC=lab
[+] isCriticalSystemObject             : FALSE
[+] dSCorePropagationData              : 1/1/1601
[+] lastLogonTimestamp                 : 3/1/2023 9:34:27 AM
[+] msDS-SupportedEncryptionTypes      : 28
[+] ADsPath                            : LDAP://CN=WS1,CN=Computers,DC=castle,DC=lab
[+] PasswordSettings                   : Never expires
[+] AccountDisabled                    : FALSE

+-------------------------------------------------------------------+
    """
    parsed_objects = Brc4LdapSentinelParser.parse_data(data)
    ad = ADDS()
    ad.import_objects(parsed_objects)

    assert len(parsed_objects) == 1
    # this test is failing - should distinguishedname be required?
    assert len(ad.computers) == 0


# This test case currently is not possible with BRc4,
# since all attributes are returned by default

'''
def test_parse_mininal_data_computer():
    data = """[+] accountdisabled                    : false

+-------------------------------------------------------------------+
[+] distinguishedname                  : cn=ws1,cn=computers,dc=castle,dc=lab
[+] objectsid                          : s-1-5-21-4033075623-2380760593-384075220-1104
[+] samaccounttype                     : 805306369

+-------------------------------------------------------------------+
    """
    parsed_objects = Brc4LdapSentinelParser.parse_data(data)
    ad = ADDS()
    ad.import_objects(parsed_objects)

    assert len(parsed_objects) == 1
    assert len(ad.computers) == 1
'''

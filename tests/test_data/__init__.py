import os 
import pytest 
from bofhound.parsers import LdapSearchBofParser

TEST_DATA_DIR = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 
            "..",
            "test_data"
        )
)

# LdapSearchPY Fixtures
@pytest.fixture
def ldapsearchpy_standard_file_516():
    yield os.path.join(TEST_DATA_DIR, "ldapsearchpy_logs/ldapsearch_516-objects.log")


# LdapSearchBOF Fixtures
@pytest.fixture
def ldapsearchbof_standard_file_257():
    yield os.path.join(TEST_DATA_DIR, "ldapsearchbof_logs/beacon_257-objects.log")


@pytest.fixture
def ldapsearchbof_standard_file_202():
    yield os.path.join(TEST_DATA_DIR, "ldapsearchbof_logs/beacon_202.log")


@pytest.fixture
def testdata_ldapsearchbof_beacon_257_objects():
    log_file = os.path.join(TEST_DATA_DIR, "ldapsearchbof_logs/beacon_257-objects.log")
    yield LdapSearchBofParser.parse_file(log_file)


@pytest.fixture
def testdata_ldapsearchbof_beacon_202_objects():
    log_file = os.path.join(TEST_DATA_DIR, "ldapsearchbof_logs/beacon_202.log")
    yield LdapSearchBofParser.parse_file(log_file)


# BRc4 LDAP Sentinel Fixtures
@pytest.fixture
def brc4ldapsentinel_standard_file_252():
    yield os.path.join(TEST_DATA_DIR, "brc4_ldap_sentinel_logs/badger_no_acl_252_objects.log")
import re
import codecs
import logging
from datetime import datetime as dt

# If field is empty, DO NOT WRITE IT TO FILE!

class Brc4LdapSentinelParser():
    # BRC4 LDAP Sentinel currently only queries attribute=* and objectClass 
    # is always the top result. May need to be updated in the future.
    START_BOUNDARY = '[+] objectclass                        :'
    END_BOUNDARY = '+-------------------------------------------------------------------+'

    FORMATTED_TS_ATTRS = ['lastlogontimestamp', 'lastlogon', 'lastlogoff', 'pwdlastset', 'accountexpires', 'whencreated', 'whenchanged']
    BRACKETED_ATTRS = ['objectguid']
    SEMICOLON_DELIMITED_ATTRS = ['serviceprincipalname', 'memberof', 'member', 'objectclass']

    def __init__(self):
        pass #self.objects = []

    @staticmethod
    def parse_file(file):

        with codecs.open(file, 'r', 'utf-8') as f:
            return Brc4LdapSentinelParser.parse_data(f.read())

    @staticmethod
    def parse_data(contents):
        parsed_objects = []
        current_object = None
        in_result_region = False

        in_result_region = False

        lines = contents.splitlines()
        for line in lines:

            if len(line) == 0:
                continue

            is_start_boundary_line = Brc4LdapSentinelParser._is_start_boundary_line(line)
            is_end_boundary_line = Brc4LdapSentinelParser._is_end_boundary_line(line)

            if not in_result_region and not is_start_boundary_line:
                continue

            if is_start_boundary_line:
                if not in_result_region:
                    in_result_region = True

                current_object = {}

            elif is_end_boundary_line:
                parsed_objects.append(current_object)
                in_result_region = False
                current_object = None
                continue

            data = line.split(': ')

            try:
                data = line.split(':', 1)
                attr = data[0].replace('[+]', '').strip().lower()
                value = data[1].strip()

                # BRc4 formats some timestamps for us that we need to revert to raw values
                if attr in Brc4LdapSentinelParser.FORMATTED_TS_ATTRS:
                    if value.lower() in ['never expires', 'value not set']:
                        continue
                    timestamp_obj = dt.strptime(value, '%m/%d/%Y %I:%M:%S %p')
                    value = int((timestamp_obj - dt(1601, 1, 1)).total_seconds() * 10000000)
                
                # BRc4 formats some attributes with surroudning we need to remove {} 
                if attr in Brc4LdapSentinelParser.BRACKETED_ATTRS:
                    value = value[1:-1]

                # BRc4 delimits some list-esque attributes with semicolons
                # when our BH models expect commas
                if attr in Brc4LdapSentinelParser.SEMICOLON_DELIMITED_ATTRS:
                    value = value.replace('; ', ', ')

                # BRc4 puts the trustDirection attribute within securityidentifier
                if attr == 'securityidentifier' and 'trustdirection' in value.lower():
                    trust_direction = value.lower().split('trustdirection ')[1]
                    current_object['trustdirection'] = trust_direction
                    value = value.split('trustdirection: ')[0]
                    continue

                current_object[attr] = value

            except Exception as e:
                logging.debug(f'Error - {str(e)}')

        return parsed_objects


    @staticmethod
    def _is_start_boundary_line(line):
        # BRc4 seems to always have objectClass camelcased, but we'll use lower() just in case
        if line.lower().startswith(Brc4LdapSentinelParser.START_BOUNDARY):
            return True
        return False


    @staticmethod
    def _is_end_boundary_line(line):
        if line == Brc4LdapSentinelParser.END_BOUNDARY:
            return True
        return False
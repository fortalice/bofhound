import re
import base64
import codecs

from io import BytesIO
from bloodhound.ad.utils import ADUtils
from bloodhound.enumeration.acls import parse_binary_acl, SecurityDescriptor
from bloodhound.enumeration.acls import ACL, ACCESS_ALLOWED_ACE, ACCESS_MASK, ACE, ACCESS_ALLOWED_OBJECT_ACE, build_relation, has_extended_right, EXTRIGHTS_GUID_MAPPING
import logging

from bofhound.ad.models import BloodHoundDomain, BloodHoundComputer, BloodHoundUser, BloodHoundGroup, BloodHoundSchema

# If field is empty, DO NOT WRITE IT TO FILE!

class LdapSearchBofParser():
    RESULT_DELIMITER = "-"
    RESULT_BOUNDARY_LENGTH = 20
    _COMPLETE_BOUNDARY_LINE = -1

    def __init__(self):
        pass #self.objects = []

    @staticmethod
    def parse_file(file):

        with codecs.open(file, 'r', 'utf-8') as f:
            return LdapSearchBofParser.parse_data(f.read())

    @staticmethod
    def parse_data(contents):
        parsed_objects = []
        current_object = None
        in_result_region = False
        previous_attr = None

        in_result_region = False

        data = re.sub(r'\n\n\d{2}\/\d{2} (\d{2}:){2}\d{2} UTC \[output\]\nreceived output:\n', '', contents)

        lines = data.splitlines()
        for line in lines:
            is_boundary_line = LdapSearchBofParser._is_boundary_line(line)

            if (not in_result_region and
                  not is_boundary_line):
                continue

            if (is_boundary_line
                  and is_boundary_line != LdapSearchBofParser._COMPLETE_BOUNDARY_LINE):
                while True:
                    try:
                        next_line = next(lines)[1]
                        remaining_length = LdapSearchBofParser._is_boundary_line(next_line, is_boundary_line)

                        if remaining_length:
                            is_boundary_line = remaining_length
                            if is_boundary_line == LdapSearchBofParser._COMPLETE_BOUNDARY_LINE:
                                break
                    except:
                        # probably ran past the end of the iterable
                        break

            # BEGIN FIX - bofhound crashes if it encounters an cobaltstrike task strings while parsing the ldapsearch data.

            # If a user queues multiple commands while ldapsearch is running, the ldapresults may contain nested cobaltstrike output
            # example: CobaltStrike logs queued task input between responses from the ldapsearch BOF

            #nTSecurityDescriptor: B64ENCODEDBINARYDATAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
            #09/21 15:01:34 UTC [input] <user> ldapsearch "(&(objectClass=group)(name=Domain Users))" *,ntsecuritydescriptor 1 192.168.1.1 "DC=DOMAIN,DC=local"
            #09/21 15:01:34 UTC [output]
            #Running ldapsearch (T1018, T1069.002, T1087.002, T1087.003, T1087.004, T1482)
            #
            #09/21 15:01:34 UTC [task] <T1018, T1069.002, T1087.002, T1087.003, T1087.004, T1482> Running ldapsearch (T1018, T1069.002, T1087.002, T1087.003, T1087.004, T1482)
            #09/21 15:01:41 UTC [output]
            #received output:
            #BACKHALFOFNTSECURITYDESCRIPTOR==
            #name: Domain Admins

            badPatterns = [ "^$",                           # Empty Line
            "^\\d\\d/\\d\\d \\d\\d:\\d\\d:\\d\\d UTC ?",    # CobaltStrike queued command output: MM/DD HH:MM:SS UTC [input|task]
            "^Running ldapsearch ?",                        # BOF Output
            "^received output"                              # Start of next response
            ]

            if (is_boundary_line):
                if not in_result_region:
                    in_result_region = True
                elif current_object is not None:
                    # self.store_object(current_object)
                    parsed_objects.append(current_object)
                current_object = {}
                continue
            elif re.match("^(R|r)etr(e|i)(e|i)ved \\d+ results?", line):
                #self.store_object(current_object)
                parsed_objects.append(current_object)
                in_result_region = False
                current_object = None
                continue
            elif any (re.match(regex, line) for regex in badPatterns):
                logging.debug('Skipping badPattern match in_result_region: %s', line)
                continue
            #   END FIX - bofhound crashes if it encounters an cobaltstrike task strings while parsing the ldapsearch data.

            data = line.split(': ')

            try:
                # If we previously encountered a control message, we're probably still in the old property
                if len(data) == 1:
                    if previous_attr is not None:
                        value = current_object[previous_attr] + line
                else:
                    data = line.split(':')
                    attr = data[0].strip().lower()
                    value = ''.join(data[1:]).strip()
                    previous_attr = attr

                current_object[attr] = value

            except Exception as e:
                logging.debug(f'Error - {str(e)}')

        return parsed_objects


    # Returns one of the following integers:
    #    0 - This is not a boundary line
    #   -1 - This is a complete boundary line
    #    n - The remaining characters needed to form a complete boundary line
    @staticmethod
    def _is_boundary_line(line, length=RESULT_BOUNDARY_LENGTH):
        line = line.strip()
        chars = set(line)

        if len(chars) == 1 and chars.pop() == LdapSearchBofParser.RESULT_DELIMITER:
            if len(line) == length:
                return -1
            elif len(line) < length:
                return LdapSearchBofParser.RESULT_BOUNDARY_LENGTH - len(line)

        return 0 # Falsey

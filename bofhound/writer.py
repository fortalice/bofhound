import os
import json
import codecs
import datetime
import logging
from zipfile import ZipFile
from pathlib import PurePath, Path
from bofhound import console
from bofhound.ad.models import BloodHoundDomain, BloodHoundComputer, BloodHoundUser, BloodHoundGroup, BloodHoundSchema

class BloodHoundWriter():
    files = []
    ct = None

    @staticmethod
    def write(out_dir='.', domains=None, computers=None, users=None,
          groups=None, ous=None, gpos=None, trusts=None, trustaccounts=None, 
          common_properties_only=True, zip_files=False):

        os.makedirs(out_dir, exist_ok=True)
        BloodHoundWriter.ct = BloodHoundWriter.timestamp()

        if domains is not None:
            # print(BloodHoundSchema.ObjectTypeGuidMap)
            with console.status(" [bold] Writing domains to JSON...\n", spinner="aesthetic"):
                BloodHoundWriter.write_domain_file(out_dir, domains, common_properties_only)

        if computers is not None:
            with console.status(" [bold] Writing computers to JSON...\n", spinner="aesthetic"):
                BloodHoundWriter.write_computers_file(out_dir, computers, common_properties_only)

        if users is not None:
            with console.status(" [bold] Writing users to JSON...\n", spinner="aesthetic"):
                BloodHoundWriter.write_users_file(out_dir, users, common_properties_only)

        if groups is not None:
            with console.status(" [bold] Writing groups to JSON...\n", spinner="aesthetic"):
                BloodHoundWriter.write_groups_file(out_dir, groups, common_properties_only)

        if ous is not None:
            with console.status(" [bold] Writing OUs to JSON...\n", spinner="aesthetic"):
                BloodHoundWriter.write_ous_file(out_dir, ous, common_properties_only)

        if gpos is not None:
            with console.status(" [bold] Writing GPOs to JSON...\n", spinner="aesthetic"):
                BloodHoundWriter.write_gpos_file(out_dir, gpos, common_properties_only)

        if trusts is not None:
            BloodHoundWriter.write_trusts_file(out_dir, trusts, common_properties_only)

        if trustaccounts is not None:
            BloodHoundWriter.write_trustaccounts_file(out_dir, trustaccounts, common_properties_only)

        if out_dir == ".":
            logging.info(f'JSON files written to current directory')
        else:
            logging.info(f'JSON files written to {out_dir}')

        if zip_files:
            zip_name = PurePath(out_dir, f"bloodhound_{BloodHoundWriter.ct}.zip")
            with ZipFile(zip_name, "w") as zip:
                for bh_file in BloodHoundWriter.files:
                    zip.write(bh_file, bh_file.name)
                    Path(bh_file).unlink()
            logging.info(f'Files compressed into {zip_name}')



    @staticmethod
    def write_domain_file(out_dir, domains, common_properties_only):
        if len(domains) == 0:
            return

        datastruct = {
            "data": [],
            "meta": {
                "type": "domains",
                "count": 0,
                "methods": 0,
                "version":4
            }
        }

        for domain in domains:
            datastruct['data'].append(domain.to_json(common_properties_only))
            datastruct['meta']['count'] += 1

        out_file = PurePath(out_dir, f'domains_{BloodHoundWriter.ct}.json')
        BloodHoundWriter.files.append(out_file)
        with codecs.open(out_file, 'w', 'utf-8') as f:
            json.dump(datastruct, f)

    @staticmethod
    def write_computers_file(out_dir, computers, common_properties_only):
        if len(computers) == 0:
            return

        datastruct = {
            "data": [],
            "meta": {
                "type": "computers",
                "count": 0,
                "methods": 0,
                "version":4
            }
        }

        for computer in computers:
            datastruct['data'].append(computer.to_json(common_properties_only))
            datastruct['meta']['count'] += 1

        out_file = PurePath(out_dir, f'computers_{BloodHoundWriter.ct}.json')
        BloodHoundWriter.files.append(out_file)
        with codecs.open(out_file, 'w', 'utf-8') as f:
            json.dump(datastruct, f)


    @staticmethod
    def write_users_file(out_dir, users, common_properties_only):
        if len(users) == 0:
            return

        datastruct = {
            "data": [],
            "meta": {
                "type": "users",
                "count": 0,
                "methods": 0,
                "version":4
            }
        }

        for user in users:
            datastruct['data'].append(user.to_json(common_properties_only))
            datastruct['meta']['count'] += 1

        out_file = PurePath(out_dir, f'users_{BloodHoundWriter.ct}.json')
        BloodHoundWriter.files.append(out_file)
        with codecs.open(out_file, 'w', 'utf-8') as f:
            json.dump(datastruct, f)


    @staticmethod
    def write_groups_file(out_dir, groups, common_properties_only):
        if len(groups) == 0:
            return

        datastruct = {
            "data": [],
            "meta": {
                "type": "groups",
                "count": 0,
                "methods": 0,
                "version": 4
            }
        }

        for group in groups:
            datastruct['data'].append(group.to_json(common_properties_only))
            datastruct['meta']['count'] += 1

        out_file = PurePath(out_dir, f'groups_{BloodHoundWriter.ct}.json')
        BloodHoundWriter.files.append(out_file)
        with codecs.open(out_file, 'w', 'utf-8') as f:
            json.dump(datastruct, f)

    
    @staticmethod
    def write_ous_file(out_dir, ous, common_properties_only):
        if len(ous) == 0:
            return

        datastruct = {
            "data": [],
            "meta": {
                "type": "ous",
                "count": 0,
                "methods": 0,
                "version": 4
            }
        }

        for ou in ous:
            datastruct['data'].append(ou.to_json(common_properties_only))
            datastruct['meta']['count'] += 1

        out_file = PurePath(out_dir, f'ous_{BloodHoundWriter.ct}.json')
        BloodHoundWriter.files.append(out_file)
        with codecs.open(out_file, 'w', 'utf-8') as f:
            json.dump(datastruct, f)


    @staticmethod
    def write_gpos_file(out_dir, gpos, common_properties_only):
        if len(gpos) == 0:
            return

        datastruct = {
            "data": [],
            "meta": {
                "type": "gpos",
                "count": 0,
                "methods": 0,
                "version": 4
            }
        }

        for gpo in gpos:
            datastruct['data'].append(gpo.to_json(common_properties_only))
            datastruct['meta']['count'] += 1

        out_file = PurePath(out_dir, f'gpos_{BloodHoundWriter.ct}.json')
        BloodHoundWriter.files.append(out_file)
        with codecs.open(out_file, 'w', 'utf-8') as f:
            json.dump(datastruct, f)


    @staticmethod
    def write_trusts_file(out_dir, trusts, common_properties_only):
        pass


    @staticmethod
    def write_trustaccounts_file(out_dir, trustaccounts, common_properties_only):
        pass

    @staticmethod
    def timestamp():
        ct = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        return ct

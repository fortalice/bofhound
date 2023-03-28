# Changelog
## [0.2.0] - 03/28/2023
### Added
- New parser to support parsing LDAP Sentinel data from BRc4 logs

### Changed
- Modified logic for how group memberships are determined
    - Prior method was iterate through DNs in groups' `member` attribute and adding objects with matching DNs
    - Since BRc4 does not store DNs in the `member` attibute, added iteration over objects' `memberOf` attribute and add to groups with matching DN (i.e. membership is now calculated from both sides of relationship)

## [v0.1.2] - 2/10/2023
### Changed
- Updated ACL parsing function to current version BloodHound.py
- Updated `typer` and `bloodhound-python` dependencies
- Added the `memberof` attrbute to the common properties displayed for users, computers and groups

## [v0.1.1] - 8/11/2022
### Fixed
- Bug where domain trusts queried more than once would appear duplicated in the BH UI

## [v0.1.0] - 6/9/2022
### Added
- Parsing support for Group Policy Objects
- Parsing support for Organizational Unit objects
- Parsing support for Trusted Domain objects

### Fixed
- Bug causing crash when handling non-base64 encoded SchemaIDGUID/nTSecurityDescriptor attributes

## [v0.0.1] - 5/9/2022
### Added
- Prepped for initial release and PyPI package
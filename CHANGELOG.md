
# CHANGELOG

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add new parameter to manage CSS class of aknowledgement in the request form.
- Add support of I18N for all module components.
- Add new parameters to show or hide the sensitivity filter in the request form.
- Add the ability to manage multiple permissions simultaneously.
- Merge module `gn_module_permissions_requests` in this module `gn_module_permrequests`
- Create `pr_permrequests` schema
- Add new notifications
- Add `tsconfig.sample.json` file to help developers work from outside the GeoNature directory.

### Changed

- Merge table `gn_permissions.t_permissions_requests` to `pr_permissions_requests.t_permissions_requests`
-


## [0.1.0] - 2024-10-29

### Added

- First functional backend version of this module.
- Add table `t_permissions_requests` in `gn_permissions` schema
- Add avaiblable permissions for this module
- Add notificaitons and their templates for this module

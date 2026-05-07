
# CHANGELOG

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
(also see [the french translation](https://keepachangelog.com/fr/1.1.0/))
and this project respects [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased]

## [0.4.0] - 2026-05-07

### Added

- Add possibility to load custom geojson file instead of use predefined geographical areas.
- Add new configuration parameter (`ALLOW_CUSTOM_AREA`) to authorize loading of custom geojson file.
- Add ability to define multiple permissions (by default R + E) in the configuration file.
- Add `fr` translation for new features.
- Add `en` translation for all features.
- Add doc for new config parameters : `ALLOW_CUSTOM_AREA` and `PERMISSIONS_TO_CREATE`.

### Changed

- Taxon field is no longer mandatory  in permission request form.
- Valid taxon names are now displayed in taxa field.
- Improve the display of selected taxon names using `chips`.
- Updating a validated permission request now resets the validation status.

### Fixed

- Fixed display of selected taxon names when editing a permission request.

## [0.3.0] - 2026-05-05

### Added

- Add new parameter to manage CSS class of aknowledgement in the request form.
- Add support of I18N for all module components.
- Add new parameters to show or hide the sensitivity filter in the request form.
- Add the ability to manage multiple permissions simultaneously.
- Add `tsconfig.sample.json` file to help developers work from outside the GeoNature directory.

### Changed

- Changed of the initial Alembic revision to include several permissions on each request.
  BREAKING CHANGE: downgrade database with Alembic `geonature db downgrade permrequests@base`
  before update this module.

### Fixed

- Fixed spacing in the `VALIDATION_UPDATE` notification template.

## [0.2.0] - 2026-04-17

### Added

- Merge module `gn_module_permissions_requests` in this module `gn_module_permrequests`.
- Create `pr_permrequests` schema.
- Add new notifications.

### Changed

- Merge table `gn_permissions.t_permissions_requests` to `pr_permissions_requests.t_permissions_requests`.
- Changed main table name in the initial Alembic revision.
  BREAKING CHANGE : downgrade database with Alembic `geonature db downgrade permrequests@base`
  before update this module.


## [0.1.0] - 2024-10-29

### Added

- First functional backend version of this module.
- Add table `t_permissions_requests` in `gn_permissions` schema.
- Add avaiblable permissions for this module.
- Add notificaitons and their templates for this module.

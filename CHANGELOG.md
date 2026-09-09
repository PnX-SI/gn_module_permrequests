# CHANGELOG

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
(also see [the french translation](https://keepachangelog.com/fr/1.1.0/))
and this project respects [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased]

## [1.0.2] - 2026-09-09

### Fixed

- Retain all features of uploaded GeoJSON (see [#3](https://github.com/PnX-SI/gn_module_permrequests/issues/3)). Add unit test for this case.
- Translate to english all comments in backend source code.

## [1.0.1] - 2026-07-30

### Fixed

- Maintain compatibility with Python 3.9, as GeoNature 2.17 is compatible.
- Fixed the Angular template syntax which was incompatible with the Angular analyzer and caused an error during installation, but which was imposed by Prettier.

## [1.0.0] - 2026-06-29

### Added

- The `SCOPE_FILTER` section parameter has a new parameter `DISPLAY_ENABLED` to display or not the field _Scope_ in the permission request form. `DEFAULT_VALUE` was also added to define the default value of this field.
- The `PERMISSIONS_DURATION` section parameter has two new parameters: `DEFAULT_DAYS` to define the number of days to set by default in the permission duration field, and `MAX_DAYS` to define the maximum number of days after the current date that can be selected in the date picker.
- Add a dynamic form section to the permission request form. The parameter `DYNAMIC_FORM` was added in the configuration file to manage the list of form sections and the order in which they are displayed. Data are stored in the `additional_data` field of the permission requests table.
- Add possibility with `ENABLE_CONVENTION` parameter to show a convention dialog when the permission request form is submitted. The text of the [default convention](frontend/assets/templates/convention.default.tpl.html) can be overridden.
- Add `TAXA_FILTER` section parameter to define the display or not (`DISPLAY_ENABLED`) for taxon filter, the minimum rank of names (`RANK_MIN`) and the taxon identifier field to use (`VALUE_FIELD_NAME`).
- Add required field indicator (a red asterisk) in permission request form.
- Documentation about the new parameters was added in [README.md file](README.md#paramètres).
- Add downgrade to custom areas Alembic migration file. WARNING: a downgrade destroys data added by users.
- Add VSCode extensions recommendations and default settings for developers. With Ruff, the Python imports are automatically sorted.
- Add a first version of the AGENTS.md file to the root of this module as well as a section in the main README.md file.

### Changed

- Parameter `ALLOWED_SCOPES` was renamed to `ALLOWED_VALUES` and included in a new configuration section parameter (`SCOPE_FILTER`).
- Replace the component used to select taxa with a component that behaves the same way as the one used for geographical zones.
- By default, the `cd_ref` of taxa selected is used to define the permissions instead of `cd_nom` in order to avoid the use of synonym names with the synthese permission taxa filter.
- Improve the actions buttons on the permission request form by adding tooltips. Use the term "Send" (to the validators) instead of "Save" to make the action more explicit.
- Use Ruff instead of Black but with the same parameters.
- The GitHub Actions for Pytest and linting are now fully operational. The Pytest action directly uses the GeoNature workflow, and the linting action uses the Prettier and Ruff formatters.

### Fixed

- Correctly apply Prettier on frontend source code and Ruff on backend source code.
- Correct Editor Config syntax.
- Fix all Pytest tests.

## [0.4.0] - 2026-05-07

### Added

- Add possibility to load custom geojson file instead of using predefined geographical areas.
- Add new configuration parameter (`ALLOW_CUSTOM_AREA`) to authorize loading of custom geojson file.
- Add ability to define multiple permissions (by default R + E) in the configuration file.
- Add `fr` translation for new features.
- Add `en` translation for all features.
- Add doc for new config parameters : `ALLOW_CUSTOM_AREA` and `PERMISSIONS_TO_CREATE`.

### Changed

- Taxon field is no longer mandatory in permission request form.
- Valid taxon names are now displayed in taxa field.
- Improve the display of selected taxon names using `chips`.
- Updating a validated permission request now resets the validation status.

### Fixed

- Fixed display of selected taxon names when editing a permission request.

## [0.3.0] - 2026-05-05

### Added

- Add new parameter to manage CSS class of acknowledgement in the request form.
- Add support of I18N for all module components.
- Add new parameters to show or hide the sensitivity filter in the request form.
- Add the ability to manage multiple permissions simultaneously.
- Add `tsconfig.sample.json` file to help developers work from outside the GeoNature directory.

### Changed

- Changed the initial Alembic revision to include several permissions on each request.
  BREAKING CHANGE: downgrade database with Alembic `geonature db downgrade permrequests@base`
  before updating this module.

### Fixed

- Fixed spacing in the `VALIDATION_UPDATE` notification template.

## [0.2.0] - 2026-04-17

### Added

- Merge module `gn_module_permissions_requests` in this module `gn_module_permrequests`.
- Create `pr_permrequests` schema.
- Add new notifications.

### Changed

- Merge table `gn_permissions.t_permissions_requests` to `pr_permissions_requests.t_permissions_requests`.
- Changed main table name in the initial Alembic revision.
  BREAKING CHANGE: downgrade database with Alembic `geonature db downgrade permrequests@base`
  before update this module.

## [0.1.0] - 2024-10-29

### Added

- First functional backend version of this module.
- Add table `t_permissions_requests` in `gn_permissions` schema.
- Add available permissions for this module.
- Add notifications and their templates for this module.

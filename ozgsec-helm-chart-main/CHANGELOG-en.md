# Changelog

All significant changes to this project are documented in this file.

## [Unreleased]

## [1.3.3] - 2024-11-04

New packet available: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-helm-chart/-/packages/10445 mit sha256 sum: `7d41c58a9c4510f570302c998b8404931330e91e76190df098349499959aceb4  ozgsec-1.3.3.tgz`

### Changed

- The Web Frontend has been updated to version 1.2.0.
- The Best Practice Scanner has been updated to version 1.1.0.
- The dependencies have been updated.

### Added

- Feature flag to disable Keycloak.
- Feature flag to disable the dashboard function.
- Feature flag to disable InfluxDB.
- RabbitMQ-Connection-Retries parameters have been added.

### Fixed

- Bug fix using helm in version >1.3.0 ([#5](https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-helm-chart/-/issues/5))
- Minor fixes in the documentation

## [1.2.0] - 2024-05-14

New packet available: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-helm-chart/-/packages/6281 with sha256 sum: `445f0215a3d7acf5363e7965ab80d18c83d2152633925bd097cce94e2b23fd75  ozgsec-1.2.0.tgz`

### Changed

- The Web Frontend has been updated to version 1.0.2.
- The Best Practice Scanner has been updated to version 1.0.1.
- The dependencies (InfluxDB, RabbitMQ, Redis, Postgres) have been updated.

### Added

- Installation instructions for using the Helm chart have been added.
- Repo maintenance: DCO (Developer Certificate of Origin) for contributions
- Repo maintenance: English translation of various documents (README, CONTRIBUTING, etc.)

### Fixed

- Minor corrections have been made to the descriptive files.

## [1.1.0] - 2024-05-06

New package available: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-helm-chart/-/packages/6160 with sha256 sum: `97480e4bb4a6ba00c1ff82ecce41e5d6eaa11269cb963da1d153d13e178a29fa  ozgsec-1.1.0.tgz`

### Changed

- The delay of Keycloak's liveness and readiness probes has been increased to 80 seconds to give the application enough time for DB migration.
- The dependencies (InfluxDB, RabbitMQ, Redis, Postgres) have been updated.

### Added

- German version of the licence text added.
- Added contact details for reporting security vulnerabilities.

### Fixed

- Minor corrections in the installation notes (NOTES.txt) have been made.

## [1.0.0] - 2024-05-03

_Initial Public Version_

## General notes

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

[Unreleased]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-helm-chart/-/compare/v1.3.3...HEAD
[1.3.3]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-helm-chart/-/compare/v1.2.0...v1.3.3
[1.2.0]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-helm-chart/-/compare/v1.1.0...v1.2.0
[1.1.0]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-helm-chart/-/compare/v1.0.0...v1.1.0
[1.0.0]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-helm-chart/-/compare/main...v1.0.0
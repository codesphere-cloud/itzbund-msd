# Changelog

All significant changes to this project are documented in this file.

## [Unreleased]

## [1.1.0] - 2024-05-14

New image tag: `v1.1.0` with digest `sha256:6ceb0be0a9a7a3be01b8003b7ab472280651bd1bce3d4916f700a7fb511e1b29`

Image signature: `registry.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-keycloak:sha256-6ceb0be0a9a7a3be01b8003b7ab472280651bd1bce3d4916f700a7fb511e1b29.sig`

Signed SBOM: `registry.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-keycloak:sha256-6ceb0be0a9a7a3be01b8003b7ab472280651bd1bce3d4916f700a7fb511e1b29.att`

### Added

- Repo maintenance: English translation of various documents (README, CONTRIBUTING, etc.)
- Repo maintenance: licence scanning for dependencies in CI/CD pipeline
- Repo maintenance: DCO (Developer Certificate of Origin) for contributions
- German version of the licence text

### Changed

- Dependencies updated
- Keycloak image updated to version 24.0.4

### Fixed

- Minor bugs have been fixed

## [1.0.0] - 2024-04-29

_Initial Public Version_

New image-tag: `v1.0.0` with digest `sha256:8b5d11e73fa583ef1d41497b2260ad11e437738c123dc0ae6431ada77e7ef631`

## Allgemeine Hinweise

Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
und dieses Projekt hält sich an die [Semantische Versionierung](https://semver.org/spec/v2.0.0.html).

You can find the public key for verifying the image and SBOM signatures here: [cosign.pub](https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-keycloak/-/blob/main/cosign.pub)

[Unreleased]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-keycloak/-/compare/v1.1.0...HEAD
[1.1.0]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-keycloak/-/compare/v1.0.0...v1.1.0
[1.0.0]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-keycloak/-/compare/main...v1.0.0
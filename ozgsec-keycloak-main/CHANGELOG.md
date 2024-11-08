# Changelog

Alle nennenswerten Änderungen an diesem Projekt werden in dieser Datei dokumentiert.

_[English version available](./CHANGELOG-en.md)_

## [Unreleased]

## [1.1.0] - 2024-05-14

Neues Image-Tag: `v1.1.0` mit Digest `sha256:6ceb0be0a9a7a3be01b8003b7ab472280651bd1bce3d4916f700a7fb511e1b29`

Image-Signatur: `registry.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-keycloak:sha256-6ceb0be0a9a7a3be01b8003b7ab472280651bd1bce3d4916f700a7fb511e1b29.sig`

Signierte SBOM: `registry.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-keycloak:sha256-6ceb0be0a9a7a3be01b8003b7ab472280651bd1bce3d4916f700a7fb511e1b29.att`

### Added

- Repo-Pflege: Englische Übersetzung verschiedener Dokumente (README, CONTRIBUTING, etc.)
- Repo-Pflege: License-Scanning für Abhängigkeiten in CI/CD-Pipeline
- Repo-Pflege: DCO (Developer Certificate of Origin) für Beiträge
- Deutschsprachige Version des Lizenztextes

### Changed

- Dependencies aktualisiert
- Keycloak-Image auf Version 24.0.4 aktualisiert

### Fixed

- Kleinere Fehler wurden behoben

## [1.0.0] - 2024-04-29

_Initial Public Version_

Neues Image-Tag: `v1.0.0` mit Digest `sha256:8b5d11e73fa583ef1d41497b2260ad11e437738c123dc0ae6431ada77e7ef631`

## Allgemeine Hinweise

Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
und dieses Projekt hält sich an die [Semantische Versionierung](https://semver.org/spec/v2.0.0.html).

Sie finden den öffentlichen Schlüssel zur Überprüfung der Image- und SBOM-Signaturen hier: [cosign.pub](https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-keycloak/-/blob/main/cosign.pub)

[Unreleased]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-keycloak/-/compare/v1.1.0...HEAD
[1.1.0]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-keycloak/-/compare/v1.0.0...v1.1.0
[1.0.0]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-keycloak/-/compare/main...v1.0.0
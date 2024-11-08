# Changelog

Alle nennenswerten Änderungen an diesem Projekt werden in dieser Datei dokumentiert.

_[English Version available](./CHANGELOG-en.md)_

## [Unreleased]

## [1.0.1] - 2024-05-14

Neues Image-Tag: `v1.0.1` mit Digest `sha256:7e0409041dba5c9f0018fb4372d9d063927bede43e1d22783ea6d5140b193638`

Image-Signatur: `registry.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner:sha256-7e0409041dba5c9f0018fb4372d9d063927bede43e1d22783ea6d5140b193638.sig`

Signierte SBOM: `registry.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner:sha256-7e0409041dba5c9f0018fb4372d9d063927bede43e1d22783ea6d5140b193638.att`

### Added

- Repo-Pflege: Englische Übersetzung verschiedener Dokumente (README, CONTRIBUTING, etc.)
- Repo-Pflege: License-Scanning für Abhängigkeiten in CI/CD-Pipeline
- Repo-Pflege: DCO (Developer Certificate of Origin) für Beiträge
- OpenAPI Spezifikation für die REST-API des Scanners
- Deutsche Übersetzung des Lizenztextes
- Security-Advisory Issue Template

### Changed

- Dependencies aktualisiert

### Fixed

- Kleinere Fehler in der Dokumentation behoben
- Das Log-Level des Scanners kann wieder über die Umgebungsvariable `LOG_LEVEL` gesteuert werden

## [1.0.0] - 2024-04-29

_Initial Public Version_

Neues Image-Tag: `v1.0.0` mit digest `sha256:4f8f6c491dbfb107aa23f451b2a0e497d52b9f851bc1aed5f80c0cb36fe851a6`

Image-Signatur: `registry.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner:sha256-4f8f6c491dbfb107aa23f451b2a0e497d52b9f851bc1aed5f80c0cb36fe851a6.sig`

Signierte SBOM: `registry.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner:sha256-4f8f6c491dbfb107aa23f451b2a0e497d52b9f851bc1aed5f80c0cb36fe851a6.att`

## Allgemeine Hinweise

Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
und dieses Projekt hält sich an die [Semantische Versionierung](https://semver.org/spec/v2.0.0.html).

Sie finden den öffentlichen Schlüssel zur Überprüfung der Image- und SBOM-Signaturen hier: [cosign.pub](https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/-/blob/main/cosign.pub)

[Unreleased]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/-/compare/v1.1.0...HEAD
[1.0.1]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/-/compare/v1.0.0...v1.0.1
[1.0.0]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/-/compare/main...v1.0.0
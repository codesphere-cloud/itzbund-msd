# Changelog

Alle nennenswerten Änderungen an diesem Projekt werden in dieser Datei dokumentiert.

_[English version available](./CHANGELOG-en.md)_

## [Unreleased]

### Added

- Repo-Pflege: Englische Übersetzung verschiedener Dokumente (README, CONTRIBUTING, etc.)
- Repo-Pflege: License-Scanning für Abhängigkeiten in CI/CD-Pipeline
- Repo-Pflege: DCO (Developer Certificate of Origin) für Beiträge

### Changed

- Dependencies aktualisiert (patch-level)
- Update zu node:20.13.1

## [1.0.1] - 2024-05-03

New image-tag: `v1.0.1` with digest `sha256:cc062c4dcf378cfbc72a0b6b479b041a8e52f5c005d69b623923307e1c6c5e9b`

Image-Signature: `registry.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-web-frontend:sha256-cc062c4dcf378cfbc72a0b6b479b041a8e52f5c005d69b623923307e1c6c5e9b.sig`

Signed SBOM: `registry.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-web-frontend:sha256-cc062c4dcf378cfbc72a0b6b479b041a8e52f5c005d69b623923307e1c6c5e9b.att`

### Added

- Init-Container Image (nicht distroless) ist nun verfügbar

### Fixed

- Einige Tests wurden korrigiert
- Kleinere Fehler wurden behoben

## [1.0.0] - 2024-04-29

_Initial Public Version_

New image-tag: `v1.0.0` with digest `sha256:bcf2dc751dc7551548b736f6f73cae25db990a61a31489f5d0e90ed0d886e4b2`

Image-Signature: `registry.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-web-frontend:sha256-bcf2dc751dc7551548b736f6f73cae25db990a61a31489f5d0e90ed0d886e4b2.sig`

Signed SBOM: `registry.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-web-frontend:sha256-bcf2dc751dc7551548b736f6f73cae25db990a61a31489f5d0e90ed0d886e4b2.att`

## Allgemeine Hinweise

Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
und dieses Projekt hält sich an die [Semantische Versionierung](https://semver.org/spec/v2.0.0.html).

Sie finden den öffentlichen Schlüssel zur Überprüfung der Image- und SBOM-Signaturen hier: [cosign.pub](https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-web-frontend/-/blob/main/cosign.pub)

[Unreleased]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-web-frontend/-/compare/v1.0.1...HEAD
[1.0.1]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-web-frontend/-/compare/v1.0.0...v1.0.1
[1.0.0]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-web-frontend/-/compare/main...v1.0.0
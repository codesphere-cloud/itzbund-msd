# Changelog

Alle nennenswerten Änderungen an diesem Projekt werden in dieser Datei dokumentiert.

_[English version available](./CHANGELOG-en.md)_

## [Unreleased]

## [1.3.3] - 2024-11-04

Neues Packet verfügbar: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-helm-chart/-/packages/10445 mit sha256 sum: `7d41c58a9c4510f570302c998b8404931330e91e76190df098349499959aceb4  ozgsec-1.3.3.tgz`

### Changed

- Das Web Frontend wurde auf die Version 1.2.0 aktualisiert.
- Der Best Practice Scanner wurde auf die Version 1.1.0 aktualisiert.
- Die Abhängigkeiten wurden aktualisiert.

### Added

- Feature-Flag um Keycloak zu deaktivieren.
- Feature-Flag um die Dashboard-Funktion zu deaktivieren.
- Feature-Flag um InfluxDB zu deaktivieren.
- RabbitMQ-Connection-Retries Parameter wurden hinzugefügt.

### Fixed

- Bug-Fix unter Verwedung von helm in Version >1.3.0 ([#5](https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-helm-chart/-/issues/5))
- Kleinere Fixes in der Dokumentation

## [1.2.0] - 2024-05-14

Neues Packet verfügbar: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-helm-chart/-/packages/6281 mit sha256 sum: `445f0215a3d7acf5363e7965ab80d18c83d2152633925bd097cce94e2b23fd75  ozgsec-1.2.0.tgz`

### Changed

- Das Web Frontend wurde auf die Version 1.0.2 aktualisiert.
- Der Best Practice Scanner wurde auf die Version 1.0.1 aktualisiert.
- Die Abhängigkeiten (InfluxDB, RabbitMQ, Redis, Postgres) wurden aktualisiert.

### Added

- Installationshinweise für die Verwendung des Helm-Charts wurden ergänzt.
- Repo-Pflege: DCO (Developer Certificate of Origin) für Beiträge
- Repo-Pflege: Englische Übersetzung verschiedener Dokumente (README, CONTRIBUTING, etc.)

### Fixed

- Kleinere Korrekturen in den beschreibenden Dateien wurden vorgenommen.

## [1.1.0] - 2024-05-06

Neues Packet verfügbar: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-helm-chart/-/packages/6160 mit sha256 sum: `97480e4bb4a6ba00c1ff82ecce41e5d6eaa11269cb963da1d153d13e178a29fa  ozgsec-1.1.0.tgz`

### Changed

- Die Verzögerung der Liveness- und Readiness-Probes von Keycloak wurde auf 80 Sekunden erhöht, um der Anwendung genug Zeit für die DB-Migration zu geben.
- Die Abhängigkeiten (InfluxDB, RabbitMQ, Redis, Postgres) wurden aktualisiert.

### Added

- Deutsche Version des Lizenztextes ergänzt.
- Kontaktdaten für die Meldung von Sicherheitslücken ergänzt.

### Fixed

- Kleinere Korrekturen in den Installationshinweisen (NOTES.txt) wurden vorgenommen.

## [1.0.0] - 2024-05-03

_Initial Public Version_

## Allgemeine Hinweise

Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
und dieses Projekt hält sich an die [Semantische Versionierung](https://semver.org/spec/v2.0.0.html).

[Unreleased]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-helm-chart/-/compare/v1.3.3...HEAD
[1.3.3]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-helm-chart/-/compare/v1.2.0...v1.3.3
[1.2.0]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-helm-chart/-/compare/v1.1.0...v1.2.0
[1.1.0]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-helm-chart/-/compare/v1.0.0...v1.1.0
[1.0.0]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-helm-chart/-/compare/main...v1.0.0
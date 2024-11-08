# Changelog

All significant changes to this project are documented in this file.

## [Unreleased]

## [1.0.1] - 2024-05-14

New image tag: `v1.0.1` with digest `sha256:7e0409041dba5c9f0018fb4372d9d063927bede43e1d22783ea6d5140b193638`

Image-Signatur: `registry.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner:sha256-7e0409041dba5c9f0018fb4372d9d063927bede43e1d22783ea6d5140b193638.sig`

Signierte SBOM: `registry.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner:sha256-7e0409041dba5c9f0018fb4372d9d063927bede43e1d22783ea6d5140b193638.att`

### Added

- Repo maintenance: English translation of various documents (README, CONTRIBUTING, etc.)
- Repo maintenance: licence scanning for dependencies in CI/CD pipeline
- Repo maintenance: DCO (Developer Certificate of Origin) for contributions
- OpenAPI specification for the REST API of the scanner
- German translation of the licence text
- Security-Advisory Issue Template

### Changed

- Dependencies updated

### Fixed

- Minor errors in the documentation fixed
- The log level of the scanner can be controlled via the environment variable `LOG_LEVEL` again

## [1.0.0] - 2024-04-29

_Initial Public Version_

New image tag: `v1.0.0` with digest `sha256:4f8f6c491dbfb107aa23f451b2a0e497d52b9f851bc1aed5f80c0cb36fe851a6`

Image signature: `registry.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner:sha256-4f8f6c491dbfb107aa23f451b2a0e497d52b9f851bc1aed5f80c0cb36fe851a6.sig`

Signed SBOM: `registry.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner:sha256-4f8f6c491dbfb107aa23f451b2a0e497d52b9f851bc1aed5f80c0cb36fe851a6.att`

## General notes

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

You can find the public key for verifying the image and SBOM signatures here: [cosign.pub](https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/-/blob/main/cosign.pub)

[Unreleased]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/-/compare/v1.1.0...HEAD
[1.0.1]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/-/compare/v1.0.0...v1.0.1
[1.0.0]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/-/compare/main...v1.0.0
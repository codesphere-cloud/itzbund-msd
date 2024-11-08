# Changelog

All significant changes to this project are documented in this file.

## [Unreleased]

### Added

- Repo care: English translation of various documents (README, CONTRIBUTING, etc.)
- Repo care: Licence scanning for dependencies in CI/CD pipeline
- Repo care: DCO (Developer Certificate of Origin) for contributions

### Changed

- Dependencies updated (patch-level)
- Update to node:20.13.1

## [1.0.1] - 2024-05-03

New image-tag: `v1.0.1` with digest `sha256:cc062c4dcf378cfbc72a0b6b479b041a8e52f5c005d69b623923307e1c6c5e9b`

Image-Signature: `registry.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-web-frontend:sha256-cc062c4dcf378cfbc72a0b6b479b041a8e52f5c005d69b623923307e1c6c5e9b.sig`

Signed SBOM: `registry.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-web-frontend:sha256-cc062c4dcf378cfbc72a0b6b479b041a8e52f5c005d69b623923307e1c6c5e9b.att`

### Added

- Init container image (not distroless) is now available

### Fixed

- Some tests have been corrected
- Minor bugs have been fixed

## [1.0.0] - 2024-04-29

_Initial Public Version_

New image-tag: `v1.0.0` with digest `sha256:bcf2dc751dc7551548b736f6f73cae25db990a61a31489f5d0e90ed0d886e4b2`

Image-Signature: `registry.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-web-frontend:sha256-bcf2dc751dc7551548b736f6f73cae25db990a61a31489f5d0e90ed0d886e4b2.sig`

Signed SBOM: `registry.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-web-frontend:sha256-bcf2dc751dc7551548b736f6f73cae25db990a61a31489f5d0e90ed0d886e4b2.att`

## General notes

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

You can find the public key for verifying the image and SBOM signatures here: [cosign.pub](https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-web-frontend/-/blob/main/cosign.pub)

[Unreleased]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-web-frontend/-/compare/v1.0.1...HEAD
[1.0.1]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-web-frontend/-/compare/v1.0.0...v1.0.1
[1.0.0]: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-web-frontend/-/compare/main...v1.0.0
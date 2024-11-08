<div align="center">
    <img src="./docs/assets/scanner.png" alt="OZG Security Scanner" width="192" height="192">
</div>

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/8955/badge)](https://www.bestpractices.dev/projects/8955)

**Contents / Quick navigation**

[[_TOC_]]

# OZG Security Challenge - Best Practice Scanner

In this repository, you will find the Best Practice Scanner, which was developed as part of the OZG Security Challenge. The Best Practice Scanner is a tool that makes it possible to check the IT security and the implementation of best practices of websites.

## Background

With public administration becoming more digital, the importance of information security is growing. Citizens and companies expect the state to protect their personal information with high levels of IT security. The [Federal Ministry of the Interior and Community (BMI)](https://www.bmi.bund.de/DE/startseite/startseite-node.html) would therefore like to further promote the increase in IT security during the implementation of the OZG and has launched the ‘OZG Security Challenge 2023’ in cooperation with the [Federal Office for Information Security (BSI)](https://www.bsi.bund.de/DE/Home/home_node.html). Within this scope, the ‘OZG Security Quick Test’ and the associated ‘Best Practice Scanner’ component were developed.

## Features

- Checking the degree of implementation of the following best practices/security measures (**Beta**):
  - Responsible Disclosure: Reporting vulnerabilities before publication
  - Transport Layer Security (TLS) 1.3: Current encryption of communication between citizens and the OZG service
  - Deactivate TLS 1.0 & 1.1: Deactivate outdated encryption
  - HTTP Strict Transport Security (HSTS): Ensure encrypted communication between citizens and the OZG service
  - Domain Name System Security Extensions (DNSSEC): Secure linking of internet address and server address
  - Resource Public Key Infrastructure (RPKI): Protection against unauthorised redirection of data traffic

- Testing the degree of implementation of the following best practices/security measures (**Alpha**, the tests may be faulty):
  - Certificate Authority Authorisation (CAA)
  - Certificate Transparency Logs
  - Content Security Policy (CSP)
  - X-Content-Type-Options
  - HSTS preload
  - HTTP to HTTPS forwarding
  - IPv6 support
  - Matching of the host name in the certificate
  - No mixed content
  - Certificate has not been revoked
  - Secure session cookie
  - Use of strong cipher suites
  - Use of secure key exchange procedures (planned, not yet implemented)
  - Use of a strong private key
  - Use of strong signature procedures
  - Sub-resource integrity
  - Availability of TLS 1.2
  - Validation of the certificate
  - Validation of the certificate chain
  - X-Frame-Options
  - X-XSS protection
  - DNS-based Authentication of Named Entities (DANE)
  - DomainKeys Identified Mail (DKIM)
  - Domain-based Message Authentication, Reporting, and Conformance (DMARC)
  - Sender Policy Framework (SPF)
  - STARTTLS
  - Availability of an English version of the website

### API in SARIF format

The Best Practice Scanner provides an API that outputs the results in SARIF format. The SARIF format is a standard format for the output of static analysis results. It is supported by many tools and can be used in various tools for further analysis and visualisation.

An OpenAPI specification of the API can be found in [openapi.yaml](./docs/api/openapi.yaml).

Example of a call: `curl http://localhost:8080/\?target\=example.com`

You can find an example response in the [example-response.json](./docs/api/example-response.json).

### Monitoring
By default, the application provides metrics through a Prometheus `/metrics` endpoint. The following key metrics are collected:

- Scan Duration: Tracks the duration of each scan in seconds.
- Success or Failure Counts: Monitors the total number of successful or failed scans.
- Unscannable Checks: Tracks the number of unscannable items found during scans.

#### Prometheus Monitoring
Metrics are exposed on the `/metrics` endpoint, which can be scraped by Prometheus for monitoring and alerting purposes.

#### InfluxDB Monitoring

To enable InfluxDB monitoring, set the environment variable `METRICS=influx`. When this is enabled, the following environment variables must be configured:

- INFLUX_URL: The URL of your InfluxDB instance.
- INFLUX_TOKEN: The authentication token for InfluxDB.
- INFLUX_ORG: The organization in InfluxDB.
- INFLUX_BUCKET: The bucket where metrics will be stored.

Once configured, metrics will be sent to your InfluxDB instance instead of Prometheus.

## Collaboration

Would you like to participate in the further development? You are welcome to actively contribute to this repository, e.g. with suggestions for changes (merge requests) or with questions or suggestions. Further information can be found here: [CONTRIBUTING-en.md](./CONTRIBUTING-en.md).

## Local quick start

1. clone the repository: `git clone git@gitlab.opencode.de:bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner.git`
2. create your local configuration: `cp .env.example .env`
3. start the necessary services: `docker-compose up -d` (optional, standalone mode)
4. start the scanner: `make`
5. call the scanner: `curl http://localhost:8080/\?target\=example.com`

#### Deactivating checks (optional)

Individual checks of the scanner can be deactivated or activated. To do this, the check can be commented in or out in the `config.yaml` file.

- `cp config.example.yaml config.yaml`

#### Prerequisites

- Docker must be installed. (optional, standalone mode)
- Docker-Compose must be installed. (optional, standalone mode)
- Make must be installed.
- Golang must be installed.

## Standalone mode

The scanner can be used in standalone mode. If the InfluxDB (monitoring), RabbitMQ (queue) and Redis (cache) services are not configured or accessible, the scanner falls into standalone mode. The Redis cache is then replaced by an in-memory cache.

## Licence

This project is licensed under the [EUPL-1.2](./LICENSE.md) licence.

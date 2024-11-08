<div align="center">
    <img src="./docs/assets/scanner.png" alt="OZG Security Scanner" width="192" height="192">
</div>

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/8955/badge)](https://www.bestpractices.dev/projects/8955)
![CI/CD Pipeline Status](https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner/badges/main/pipeline.svg)

**Inhalte / Schnellnavigation**

[[_TOC_]]

_[English version available](./README-en.md)_

# OZG Security Challenge - Best Practice Scanner

In diesem Repository finden Sie den Best Practice Scanner, der im Rahmen der OZG-Security-Challenge entwickelt wurde. Der Best Practice Scanner ist ein Tool, das es ermöglicht, die IT-Sicherheit und die Umsetzung von Best Practices von Webseiten zu überprüfen.

## Hintergrund

Mit der zunehmenden Digitalisierung der öffentlichen Verwaltung steigt die Bedeutung der zugrundeliegenden Informationssicherheit. Bürgerinnen, Bürger und Unternehmen erwarten, dass der Staat vertrauensvoll mit ihren persönlichen Daten umgeht und diese durch ein hohes Maß an IT-Sicherheit schützt. Das [Bundesministerium des Innern und für Heimat (BMI)](https://www.bmi.bund.de/DE/startseite/startseite-node.html) möchte daher die Steigerung der IT-Sicherheit bei der OZG-Umsetzung weiter vorantreiben und hat in Zusammenarbeit mit dem [Bundesamt für Sicherheit in der Informationstechnik (BSI)](https://www.bsi.bund.de/DE/Home/home_node.html) die „OZG-Security-Challenge 2023“ ins Leben gerufen. In diesem Rahmen wurde der „OZG-Security-Schnelltest“ und die hier vorliegende zugehörige „Best Practice Scanner“-Komponente entwickelt.

## Features

- Prüfung des Umsetzungsgrades der folgenden Best Practices/ Sicherheitsmaßnahmen (**Beta**):
  - Responsible Disclosure: Meldung von Schwachstellen vor Veröffentlichung
  - Transport Layer Security (TLS) 1.3: Aktuelle Verschlüsselung der Kommunikation zwischen Bürgerinnen, Bürgern und OZG-Dienst
  - TLS 1.0 & 1.1 deaktivieren: Veraltete Verschlüsselung deaktivieren
  - HTTP Strict Transport Security (HSTS): Sicherstellung verschlüsselter Kommunikation zwischen Bürgerinnen, Bürgern und OZG-Dienst
  - Domain Name System Security Extensions (DNSSEC): Sichere Verknüpfung von Internetadresse und Serveradresse
  - Resource Public Key Infrastructure (RPKI): Schutz vor nicht autorisierter Umleitung von Datenverkehr

- Prüfung des Umsetzungsgrades der folgenden Best Practices/ Sicherheitsmaßnahmen (**Alpha**, die Tests können fehlerhaft sein):
  - Certificate Authority Authorization (CAA)
  - Certificate Transparency Logs
  - Content Security Policy (CSP)
  - X-Content-Type-Options
  - HSTS Preload
  - HTTP zu HTTPS Weiterleitung
  - IPv6 Support
  - Übereinstimmung des Hostnames im Zertifikat
  - Kein Mixed content
  - Zertifikat wurde nicht widerrufen
  - Secure session cookie
  - Verwendung starker Cipher Suites
  - Verwendung sicherer Schlüsselaustauschverfahren (geplant, noch nicht implementiert)
  - Verwendung eines starken privaten Schlüssels
  - Verwendung von starken Signaturverfahren
  - Subresource Integrity
  - Verfügbarkeit von TLS 1.2
  - Validierung des Zertifikats
  - Validierung der Zertifikatskette
  - X-Frame-Options
  - X-XSS-Protection
  - DNS-based Authentication of Named Entities (DANE)
  - DomainKeys Identified Mail (DKIM)
  - Domain-based Message Authentication, Reporting and Conformance (DMARC)
  - Sender Policy Framework (SPF)
  - STARTTLS
  - Verfügbarkeit einer englischen Version der Webseite

### API im SARIF-Format

Der Best Practice Scanner bietet eine API, die die Ergebnisse im SARIF-Format ausgibt. Das SARIF-Format ist ein Standardformat für die Ausgabe von statischen Analyseergebnissen. Es wird von vielen Tools unterstützt und kann in verschiedenen Tools zur weiteren Analyse und Visualisierung verwendet werden.

Eine OpenAPI Spezifikation der API finden Sie in der [openapi.yaml](./docs/api/openapi.yaml).

Beispiel eines Aufrufs: `curl http://localhost:8080/\?target\=example.com`

Sie finden eine Beispiel-Antwort in der [example-response.json](./docs/api/example-response.json).

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

## Mitarbeit

Möchten Sie sich an der Weiterentwicklung beteiligen? Bringen Sie sich gerne aktiv, z. B. mit Änderungsvorschlägen (Merge Requests) oder durch Anwendungsfragen bzw. Vorschläge hier in diesem Repository ein. Weitere Informationen dazu finden Sie hier: [CONTRIBUTING.md](./CONTRIBUTING.md).

## Lokaler Schnellstart

1. Clonen Sie das Repository: `git clone git@gitlab.opencode.de:bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner.git`
2. Legen Sie Ihre lokale Konfiguration an: `cp .env.example .env`
3. Starten Sie die notwendigen Dienste: `docker-compose up -d` (optional, standalone Modus)
4. Starten Sie den Scanner: `make`
5. Rufen Sie den Scanner auf: `curl http://localhost:8080/\?target\=example.com`

#### Deaktivieren von Checks (optional)

Es können einzelne Checks des Scanners de- bzw. aktiviert werden. Dazu kann der Check in der Datei `config.yaml` aus- bzw. einkommentiert werden.

- `cp config.example.yaml config.yaml`

#### Vorraussetzungen

- Es muss Docker installiert sein. (optional, standalone Modus)
- Es muss Docker-Compose installiert sein. (optional, standalone Modus)
- Es muss Make installiert sein.
- Es muss Golang installiert sein.

## Standalone Modus

Der Scanner kann in einem standalone Modus verwendet werden. Wenn die Dienste InfluxDB (Monitoring), RabbitMQ (Queue) und Redis (Cache) nicht konfiguriert bzw. erreichbar sind, fällt der Scanner in den standalone Modus. Der Redis Cache wird dann durch einen In-Memory-Cache ersetzt.

## Lizenz

Dieses Projekt ist lizenziert unter der [EUPL-1.2](./LICENSE.md) Lizenz.

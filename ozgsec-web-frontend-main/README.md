<div align="center">
    <img src="./docs/assets/frontend.png" alt="OZG Security Frontend" width="192" height="192">
</div>

**Inhalte / Schnellnavigation**

[[_TOC_]]

_[English version available](./README-en.md)_

# OZG Security Challenge - Web Frontend

In diesem Repository finden Sie das Web Frontend, welches im Rahmen der OZG-Security-Challenge entwickelt wurde. Das Frontend stellt die Ergebnisse des [Best Practice Scanner](https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner) (ein Tool, das es ermöglicht, die IT-Sicherheit und die Umsetzung von Best Practices von Webseiten zu überprüfen) dar. 

### Hintergrund

Mit der zunehmenden Digitalisierung der öffentlichen Verwaltung steigt die Bedeutung der zugrundeliegenden Informationssicherheit. Bürgerinnen, Bürger und Unternehmen erwarten, dass der Staat vertrauensvoll mit ihren persönlichen Daten umgeht und diese durch ein hohes Maß an IT-Sicherheit schützt. Das [Bundesministerium des Innern und für Heimat (BMI)](https://www.bmi.bund.de/DE/startseite/startseite-node.html) möchte daher die Steigerung der IT-Sicherheit bei der OZG-Umsetzung weiter vorantreiben und hat in Zusammenarbeit mit dem [Bundesamt für Sicherheit in der Informationstechnik (BSI)](https://www.bsi.bund.de/DE/Home/home_node.html) die „OZG-Security-Challenge 2023“ ins Leben gerufen. In diesem Rahmen wurde der „OZG-Security-Schnelltest“ und die hier vorliegende zugehörige „Web Frontend“-Komponente entwickelt.

## Features
- Self-Service Prüfung des Umsetzungsgrades der folgenden Best Practices (**Beta**):
  - Responsible Disclosure: Meldung von Schwachstellen vor Veröffentlichung
  - Transport Layer Security (TLS) 1.3: Aktuelle Verschlüsselung der Kommunikation zwischen Bürgerinnen, Bürgern und OZG-Dienst
  - TLS 1.0 & 1.1 deaktivieren: Veraltete Verschlüsselung deaktivieren
  - HTTP Strict Transport Security (HSTS): Sicherstellung verschlüsselter Kommunikation zwischen Bürgerinnen, Bürgern und OZG-Dienst
  - Domain Name System Security Extensions (DNSSEC): Sichere Verknüpfung von Internetadresse und Serveradresse
  - Resource Public Key Infrastructure (RPKI): Schutz vor nicht autorisierter Umleitung von Datenverkehr

-  Erklärungen und Hinweise zur Umsetzung der IT-Sicherheitsmaßnahmen ([Onepager](https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-web-frontend/-/tree/main/public/one-pager)), aufbereitet mit einer „Management Summary“, einer „Erläuterung für Onlinedienst-Verantwortliche“ und einem „Technischen Umsetzungsansatz“.

Folgende Features sind nur nach Registrierung und Login erreichbar:

- Kontinuierliche Überprüfung von hinterlegten Webseiten

- Dashboards zur Visualisierung der Ergebnisse

- Verwalten von Domains in Gruppen 

- Teilen von Auswertungen einer Gruppe (read-only link Sharing)

- API zur Integration in bestehende Systeme ([OpenAPI Spezifikation](./docs/api/openapi.yaml))

Hier finden Sie weitere Erläuterungen und Screenshots: [Erläuterungen der Features](./docs/features.md)

## Konfiguration der Anwendung
Einige Features sind mittels Feature Flags deaktivierbar. Ohne weitere Einstellungen sind alle Features aktiv.

- Die Features die nur nach Registrierung und Login erreichbar sind, können über das Feature Flag `NEXT_PUBLIC_DISABLE_DASHBOARD` aktiviert und deaktiviert werden.
- Der Button, der für das manuelle Aktualisieren des Website-Scan-Resultats verwendet wird, kann über das Feature Flag `NEXT_PUBLIC_DISABLE_REFRESH` aktiviert und deaktiviert werden.
- Die URl zum Impressum ist über den Parameter `NEXT_PUBLIC_IMPRINT_URL` konfigurierbar. Ist diese nicht gesetzt, so wird standardmäßig die Seite hinter `/impressum` aufgerufen.

## Mitarbeit

Möchten Sie sich an der Weiterentwicklung beteiligen? Bringen Sie sich gerne aktiv, z. B. mit Änderungsvorschlägen (Merge Requests) oder durch Anwendungsfragen bzw. Vorschläge hier in diesem Repository ein. Weitere Informationen dazu finden Sie hier: [CONTRIBUTING.md](./CONTRIBUTING.md).

## Lizenz

Dieses Projekt ist lizenziert unter der [EUPL-1.2](./LICENSE) Lizenz.
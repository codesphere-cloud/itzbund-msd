## Lokaler Schnellstart

1. Clonen Sie das Repository: `git clone git@gitlab.opencode.de:bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-web-frontend.git`
2. Legen Sie Ihre lokale Konfiguration an: `cp .env.example .env.local`
3. Starten Sie die notwendigen Dienste: `docker-compose up -d`
4. Installieren Sie die Abhängigkeiten: `npm install`
5. Erstellen Sie die Datenbank: `DATABASE_URL=postgres://<user>:<pass>@<host>:<port>/<db> npx prisma migrate dev`
6. Starten Sie das Frontend im Entwicklungsmodus: `npm run dev`
7. Rufen Sie das Frontend in Ihrem Browser auf: [http://localhost:3000](http://localhost:3000)

#### Voraussetzungen

- Es muss Docker installiert sein.
- Es muss Docker-Compose installiert sein.
- Es muss NodeJS und npm installiert sein.

## Helm-Chart für Kubernetes

Es steht ein Helm-Chart für das Deployment [hier](https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-helm-chart) zur Verfügung.

## Umgebungsvariablen

Sie finden die zur Verfügung stehenden Umgebungsvariablen in der [.env.example](../.env.example).

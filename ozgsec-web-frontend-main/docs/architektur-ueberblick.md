## Architektur-Überblick

![Architektur](./assets/architektur.png)

Das Scann-System umfasst verschiedene Komponenten. Wesentlich ist hierbei der „Best Practice Scanner“ welcher die eigentliche Prüfaufgabe übernimmt. Das Frontend übernimmt die Aufgabe der erleichterten Benutzer:innen-Interaktion sowie Berechnung und Darstellung von Statistiken. Das Frontend ist an eine Postgres-Datenbank angebunden und speichert z. B. die von Benutzer:innen angelegten Domain-Gruppen und die dazu gehörenden Scan-Ergebnisse je Scan-Intervall. Das Frontend ist für das Scheduling der kontinuierlichen Scans verantwortlich und reiht Scan-Ziele entsprechend in eine RabbitMQ-Queue ein. Der „Best Practice Scanner“ ist auf horizontale Skalierung ausgelegt und bezieht seine Scan-Ziele aus dieser RabbitMQ-Queue. Der Scanner kann allerdings auch in einem standalone Modus und über eine HTTP-API verwendet werden. Verschiedene Ergebnisse (z. B. zu RPKI, gültig für ganze Subnetze) werden von dem Scanner in einer Redis Datenbank gecacht. 

Das Benutzermanagement wird auf Basis der Open-Source-Software Keycloak durchgeführt. 
# Sicherheitspolitik

_[English version available](./SECURITY-en.md)_

## Versionen

Die neuesten Patches und die aktuellste Software werden unter dem Tag-Schema `:main-<commit-short-hash>-<unix-timestamp>` des Container-Images veröffentlicht. Daher werden die neuesten Sicherheitsupdates zuerst auf einem solchen Tag veröffentlicht. Für den produktiven Einsatz gibt es regelmäßig ein versioniertes Container-Image (Tag).

Ältere Tags müssen manuell aktualisiert werden, da wir normalerweise kein aktualisiertes Image für ein bestehendes Tag veröffentlichen; dies wird nur im Falle von _schweren_ Sicherheitslücken gemacht.

## Melden einer Sicherheitslücke

Sie können eine Schwachstelle oder Anomalie an das Entwicklungsteam melden. Dadurch wird das Verfahren der koordinierten Offenlegung von Sicherheitslücken eingeleitet. Das Team wird sich dann bemühen, wenn möglich innerhalb einer Woche Sicherheitspatches zu entwickeln. Die Schwachstelle wird dann im Zuge der Veröffentlichung bekannt gemacht. Wenn Sie es wünschen, können Sie auch als Reporter veröffentlicht werden.

* Sie können Ihre Meldung an die folgende E-Mail-Adresse senden: [ozgsec@bmi.bund.de](mailto:ozgsec@bmi.bund.de)

* Sie können auch ein [vertrauliches Issue in diesem Repository erstellen](https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-web-frontend/-/issues/new?issue[confidential]=on&issuable_template=security-advisory).

* Alternativ können Sie an die folgende E-Mail-Adresse eine verschlüsselte E-Mail senden:

```text
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Contact: mailto:ozgsec@neuland-homeland.de
Expires: 2024-12-31T23:00:00.000Z
Encryption: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-web-frontend/-/blob/main/public/ozgsec@neuland-homeland.de-0x52AC2F9AABDD3852-pub.asc
Preferred-Languages: en, de
Canonical: https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-web-frontend/-/blob/main/public/.well-known/security.txt
-----BEGIN PGP SIGNATURE-----

iQJPBAEBCAA5FiEEf6UQ6m1bQE+kne3dUqwvmqvdOFIFAmYrdecbHG96Z3NlY0Bu
ZXVsYW5kLWhvbWVsYW5kLmRlAAoJEFKsL5qr3ThS8XIP/ikENYTN4AJaCL0ueNCd
+MDqE2dRnllULpcrnmWnpei356o7rs1f0ssaQNuUeOlhypnzQ6Iy0yHPXxJj7UWF
UU4kdjQvqKA1otckcCT3kBf2vExHy3nwuFkKyCmj/F2QgwEaIDxXBUR0o9kFdVzN
WWXe6VTenLNKK4e3j/oP6/nX43lmFTo/0FcF009Jj0hAIIeozwUx0pp7k/HOsWe7
FXZTh2STwwd44w0SjgVX8CKaJagaUt+1bav46dMOVyFKq1RdhlDZ+o8kojwd+XOG
Q5YwDw9S280DgIXVTqDucKvzy4I5Iu/t692061IcnuCzWF9h44PaO9S7qF7jFeS0
z8koE4xV8LOijahbvv3kJ5RGRPBVxzTMpYa58hdrrlUXIVu6cQyqB2Kl6jMnztyH
g0dGERfFp9/JLJBvjSJScTxGojOS9932MsqArnuu/JFtLYAZWPAFtku/CwycZxIk
uaj+YM5j+e8fbPnpv4clC5+qy/LIgNqCMkcBfRGWIndmVdI5XFIYlbWqvfTI4dIj
ILu2ehkTcbep7DwYMNsIgJtVB49S0iaytv4Kr5Vugch5L4n/pUS1r0E7Te2uA6qZ
TGmOilqw3FHHOdJX1EGsdm+JUXC5XRR3hDrP3tJamND0iToS+bge9niPse0ItuHb
hIJXJiyJbW9WrhVUbS6Ng78q
=vSyi
-----END PGP SIGNATURE-----
```

*Text based on: [DMS](https://github.com/docker-mailserver/docker-mailserver/blob/master/SECURITY.md)*
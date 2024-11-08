# Security policy

## Versions

The latest patches and the latest software are published under the `:main-<commit-short-hash>-<unix-timestamp>` tag scheme of the container image. The latest security updates are therefore published on such a tag first. A versioned container image (tag) is regularly available for productive use.

Older tags need to be updated manually, as we normally do not release an updated image for an existing tag; this is only done in case of _severe_ security vulnerabilities.

## Reporting a vulnerability

You can report a vulnerability or anomaly to the development team. This will initiate the process of coordinated vulnerability disclosure. The team will then endeavour to develop security patches within a week if possible. The vulnerability will then be publicised as part of the release. If you wish, you can also be published as a reporter.

* You can send your report to the following e-mail address: [ozgsec@bmi.bund.de](mailto:ozgsec@bmi.bund.de)

* You can also create a [confidential issue in this repository](https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-web-frontend/-/issues/new?issue[confidential]=on&issuable_template=security-advisory-en).

* Alternatively, you can send an encrypted email to the following email address:

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
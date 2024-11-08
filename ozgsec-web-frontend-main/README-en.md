<div align="center">
    <img src="./docs/assets/frontend.png" alt="OZG Security Frontend" width="192" height="192">
</div>

**Contents / Quick navigation**

[[_TOC_]]

# OZG Security Challenge - Web Frontend

In this repository, you will find the web frontend that was developed as part of the OZG Security Challenge. The frontend presents the results of the [Best Practice Scanner](https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-best-practice-scanner) (a tool that makes it possible to check the IT security and implementation of best practices of websites). 

### Background

With public administration becoming more digital, the importance of information security is growing. Citizens and companies expect the state to protect their personal information with high levels of IT security. The [Federal Ministry of the Interior and Community (BMI)](https://www.bmi.bund.de/DE/startseite/startseite-node.html) would therefore like to further promote the increase in IT security during the implementation of the OZG and has launched the ‘OZG Security Challenge 2023’ in cooperation with the [Federal Office for Information Security (BSI)](https://www.bsi.bund.de/DE/Home/home_node.html). Within this scope, the ‘OZG Security Quick Test’ and the associated ‘Web Frontend’ component were developed.

## Features
- Self-service check of the degree of implementation of the following best practices (**Beta**):
  - Responsible Disclosure: Reporting vulnerabilities before publication
  - Transport Layer Security (TLS) 1.3: Current encryption of communication between citizens and the OZG service
  - Deactivate TLS 1.0 & 1.1: Deactivate outdated encryption
  - HTTP Strict Transport Security (HSTS): Ensure encrypted communication between citizens and the OZG service
  - Domain Name System Security Extensions (DNSSEC): Secure linking of internet address and server address
  - Resource Public Key Infrastructure (RPKI): Protection against unauthorised redirection of data traffic

- Explanations and instructions for implementing the IT security measures ([One-pagers](https://gitlab.opencode.de/bmi/ozg-rahmenarchitektur/ozgsec/ozgsec-web-frontend/-/tree/main/public/one-pager)), prepared with a ‘Management Summary’, an ‘Explanation for Online Service Managers’ and a ‘Technical Implementation Approach’.

Following features are only available after registration and login:

- Continuous review of stored websites

- Dashboards for visualising the results

- Manage domains in groups

- Sharing analyses of a group (read-only link sharing)

- API for integration into existing systems ([OpenAPI Spec](./docs/api/openapi.yaml))

You can find further explanations and screenshots here: [Explanations of the features](./docs/features.md)


## Configuration of the Application
Some features can be deactivated by using feature flags. Without further configuration all features are active.

- Features that are only available with an account can be deactivated by using the feature flag `NEXT_PUBLIC_DISABLE_DASHBOARD`.
- The button for updating the website scan report manually can be deactivated by using the feature flag `NEXT_PUBLIC_DISABLE_REFRESH`.
- The URI that redirects to the imprint can be configured with `NEXT_PUBLIC_IMPRINT_URL`. The default path is: `/impressum`.


## Collaboration

Would you like to participate in the further development? You are welcome to contribute actively, e.g. with change proposals (merge requests) or by submitting application questions or suggestions here in this repository. Further information can be found here: [CONTRIBUTING-en.md](./CONTRIBUTING-en.md).

## Licence

This project is licensed under the [EUPL-1.2](./LICENSE) licence.

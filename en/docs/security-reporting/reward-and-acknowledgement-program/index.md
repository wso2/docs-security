---
title: Reward and Acknowledgement Program
category: security-reporting
version: 2.2
---

# Reward and Acknowledgement Program

<p class="doc-info">Version: 2.2</p>
___

WSO2 maintains a reward and acknowledgement programme to recognise security researchers who responsibly disclose vulnerabilities in WSO2-owned software products. This page describes the scope, qualifying and non-qualifying findings, rewards, and rules. To submit a finding for reward consideration, follow the [Vulnerability Reporting Guidelines]({{#base_path#}}/security-reporting/vulnerability-reporting-guidelines/).

## Products and services in scope

The programme covers the following products and services:

* [WSO2 API Manager](https://wso2.com/api-management/)
* [WSO2 Identity Server](https://wso2.com/identity-and-access-management)
* [WSO2 Enterprise Integrator](https://wso2.com/integration)
* [Ballerina](https://ballerina.io/) — limited to the scope defined in [ballerina.io/security-policy](https://ballerina.io/security-policy/)
* [Choreo](https://wso2.com/choreo/)
* [Asgardeo](https://wso2.com/asgardeo/)

Only the [latest released version](http://wso2.com/products/carbon/release-matrix/) of each product is in scope, and only if its release date falls within the last three years. Any other live deployment of a WSO2 product, and any WSO2-operated website (e.g. wso2.com), is out of scope.

## Qualifying vulnerabilities

Any security issue with moderate or higher impact on the confidentiality, integrity, or availability of an in-scope product or service. Common qualifying categories:

* SQL or LDAP injection
* Cross-site scripting (XSS)
* Broken authentication or authorisation
* Broken session management
* Remote code execution
* OS command execution
* XML external entity (XXE) or XML entity expansion
* Path traversal
* Insecure direct object references
* Confidential information leakage (credentials, PII)

Impact assessment is at WSO2's discretion.

## Non-qualifying vulnerabilities

Reports in the following categories are reviewed but typically do not qualify for a reward:

* Denial of service (DoS) or distributed denial of service (DDoS)
* Logout cross-site request forgery (CSRF)
* Missing CSRF token in login forms
* Cross-domain referer leakage
* Self-XSS
* Missing `HttpOnly` flag on cookies
* SSL/TLS configuration issues
* Missing HTTP security headers
* Account enumeration
* Lack of rate limiting or brute-force protection
* DNS-related issues
* Automated-scanner output, theoretical findings, or "best-practice" reports without a proof of concept
* Out-of-date third-party libraries or frameworks without a proof of concept
* Findings in third-party assets, demos, staging, or other domains not owned by WSO2
* Non-critical information leakage (server identification, stack traces)

A finding in one of these categories may still qualify if the security impact justifies it.

## Rewards

Once the reported issue is fixed and announced to customers and the community, and subject to the reporter's consent, WSO2:

1. Lists the reporter on the [Security Hall of Fame]({{#base_path#}}/security-reporting/reward-and-acknowledgement-program/hall-of-fame/).
2. Sends a certificate of appreciation.
3. Provides a **USD 50 reward**, either as an Amazon gift voucher (any Amazon storefront) or a PayPal transfer, at the reporter's choice.

Disclosure and announcement timing — which determine when the reward is issued — are documented in [Vulnerability Management Process]({{#base_path#}}/security-processes/vulnerability-management-process/).

## Rules

* Rewards are granted only to the **first** person to responsibly disclose a previously unknown issue.
* WSO2 issues a first response within seven days. A fix may take up to 90 days depending on severity, with additional time required to announce the fix to customers and the community across all affected product versions.
* Public posts that violate responsible disclosure, or that reflect negatively on the programme or the WSO2 brand, disqualify the reporter from reward consideration.
* All security testing must be carried out against a standalone WSO2 product running locally or a deployment owned by the reporter.
* All communications about a report must use the channels documented in [Report Security Issues]({{#base_path#}}/security-reporting/report-security-issues/).
* The decision to issue a reward and to provide credit is at WSO2's discretion.

## Reporting a finding for reward consideration

Submit the finding through the channels in [Vulnerability Reporting Guidelines]({{#base_path#}}/security-reporting/vulnerability-reporting-guidelines/), and include:

- [x] Vulnerable WSO2 product(s) and version(s).
- [x] List of URL(s) and affected parameter(s).
- [x] Browser, operating system, or app version where applicable.
- [x] Self-assessed impact.
- [x] Steps to exploit the vulnerability.
- [x] Any proposed solution.

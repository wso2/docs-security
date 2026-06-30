---
title: Reward and Acknowledgement Program
category: security-reporting
version: 3.0
---

# Reward and Acknowledgement Program

<p class="doc-info">Version: 3.0</p>
___

WSO2 maintains a reward and acknowledgement program to recognize security researchers who responsibly disclose vulnerabilities in WSO2-owned software products. A finding qualifies for reward consideration when it has a demonstrated security impact on the confidentiality, integrity, or availability of an in-scope product or service; severity is assessed by WSO2 using [CVSS v3.1](https://www.first.org/cvss/specification-document). To submit a finding, follow the [Vulnerability Reporting Guidelines]({{#base_path#}}/security-reporting/vulnerability-reporting-guidelines/).

## Products and services in scope

The program covers the following WSO2 products and services.

* API Platform
* Identity Platform
* Integration Platform
* Developer Platform

Internal staging environments, demo sites, WSO2-operated websites (e.g. wso2.com), and any customer-owned deployment of WSO2 software are out of scope.

## Non-qualifying findings

Reports in the following categories are reviewed but typically do not qualify for a reward under this program. WSO2 may still address these findings as security improvements or hardening work where appropriate; reward eligibility is a separate decision from whether the finding is fixed.

**Findings without demonstrated security impact:**

* Network-level or volumetric denial-of-service (DoS / DDoS) attacks against WSO2 services or infrastructure. (Application-level DoS caused by a specific product code path **is** in scope as a product vulnerability; report it with reproduction steps against a self-hosted instance, not against a cloud service.)
* Self-XSS, where the payload can only be triggered by the same user who introduces it.
* Clickjacking and tabnabbing without a demonstrated security impact.
* Cross-site request forgery (CSRF) on actions without significant security impact demonstrated.
* Cross-domain referer leakage without exposure of sensitive data.
* Findings without a working proof of concept that demonstrates the security impact.
* Out-of-date third-party libraries or frameworks without a proof of concept against an in-scope product.
* Server identification headers, stack-trace exposure, and software version disclosure on their own. These are fixed when reported but do not earn a reward unless they enable a higher-impact exploit.

**Hardening and configuration recommendations** without demonstrated exploit:

* Missing or weak HTTP security headers (CSP, HSTS, X-Frame-Options, Permissions-Policy, and similar).
* SSL/TLS configuration weaknesses (cipher-suite preference, protocol versions, HSTS preload, certificate transparency).
* Missing `Secure`, `HttpOnly`, or `SameSite` flags on cookies that do not carry session or authentication state.
* Lack of rate limiting or brute-force protection on non-authentication endpoints.
* DNS or email-authentication misconfiguration (SPF, DKIM, DMARC, NS records) on WSO2 domains, unless it enables practical impersonation.

**Out of scope by policy:**

* Social-engineering or phishing attempts against WSO2 employees, customers, partners, or community members.
* Physical attacks against WSO2 offices, infrastructure, or personnel.
* Findings in third-party assets, demos, staging environments, or domains not owned by WSO2.

A finding in one of these categories may still qualify for a reward if the demonstrated security impact justifies it.

## Rewards

Once the reported issue is fixed and announced to customers and the community, and subject to the reporter's consent, WSO2:

1. Lists the reporter on the [Security Hall of Fame]({{#base_path#}}/security-reporting/reward-and-acknowledgement-program/hall-of-fame/).
2. Sends a certificate of appreciation.
3. Provides a monetary reward, either as an Amazon gift voucher (any Amazon storefront) or a PayPal transfer, at the reporter's choice. The amount depends on the severity of the confirmed finding:

    | Severity            | CVSS Score    | Reward  |
    | :------------------ | :------------ | :------ |
    | Critical            | 9.0 to 10.0   | USD 500 |
    | High                | 7.0 to 8.9    | USD 250 |
    | Medium              | 4.0 to 6.9    | USD 100 |
    | Low                 | 3.9 or below  | USD 50  |

Disclosure and announcement timing (which determine when the reward is issued) are documented in [Vulnerability Management Process]({{#base_path#}}/security-processes/vulnerability-management-process/).

## Rules

* Rewards are granted only to the **first** person to responsibly disclose a previously unknown issue.
* WSO2 issues a first response within seven days. A fix may take up to 90 days depending on severity, with additional time required to announce the fix to customers and the community across all affected product versions.
* Public posts that violate responsible disclosure, or that reflect negatively on the program or the WSO2 brand, disqualify the reporter from reward consideration.
* Security testing must be carried out against a self-hosted WSO2 product on infrastructure you control, a deployment owned by you, or your own tenant within a WSO2 cloud service. Test only in ways that do not affect other tenants or shared infrastructure. Denial-of-service or resource-exhaustion testing, fuzzing at scale, and attempts to access other tenants' data are not permitted against cloud services. Where a finding in a cloud service can be reproduced against the self-hosted equivalent product, do that before reporting.
* All communications about a report must use the channels documented in [Report Security Issues]({{#base_path#}}/security-reporting/report-security-issues/).
* The decision to issue a reward and to provide credit is at WSO2's discretion.

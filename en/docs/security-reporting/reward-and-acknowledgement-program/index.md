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

The programme covers the following WSO2 products and services.

**Self-managed software products** — latest released version, within three years of release. Supported versions are documented in the [WSO2 Support Matrix](https://wso2.com/products/support-matrix/).

* [WSO2 API Manager](https://wso2.com/api-management/)
* [WSO2 Identity Server](https://wso2.com/identity-and-access-management/)
* [WSO2 Integrator](https://wso2.com/integration/) — Micro Integrator (MI), Streaming Integrator (SI), and Business Integrator (BI)
* [Ballerina](https://ballerina.io/) — limited to the scope defined in [ballerina.io/security-policy](https://ballerina.io/security-policy/)

**Cloud services** — the current production deployment.

* [Choreo](https://wso2.com/choreo/)
* [Asgardeo](https://wso2.com/asgardeo/)
* [Bijira](https://wso2.com/api-platform/) — WSO2's SaaS API management offering
* [Devant](https://wso2.com/integration-platform/) — WSO2's SaaS integration platform offering

Internal staging environments, demo sites, WSO2-operated websites (e.g. wso2.com), and any customer-owned deployment of WSO2 software are out of scope.

## Qualifying vulnerabilities

A security issue qualifies for reward consideration when it has a moderate or higher impact on the confidentiality, integrity, or availability of an in-scope product or service. Common qualifying categories:

* Remote code execution (RCE)
* OS command injection
* SQL injection
* LDAP injection
* Server-side request forgery (SSRF)
* XML external entity (XXE) or XML entity expansion
* Insecure deserialisation
* Path traversal and arbitrary file read or write
* Authentication or session-management bypass
* Privilege escalation
* Broken object-level authorisation, also known as insecure direct object references (IDOR / BOLA)
* Cross-site scripting (XSS) — reflected, stored, or DOM-based
* Confidential information leakage (credentials, tokens, personally identifiable information)

Impact assessment is at WSO2's discretion.

## Non-qualifying vulnerabilities

Reports in the following categories are reviewed but typically do not qualify for a reward.

**Low-impact or theoretical findings:**

* Denial of service (DoS) and distributed denial of service (DDoS).
* Self-XSS (requires the victim to paste content into their own browser).
* Clickjacking and tabnabbing without a demonstrated security impact.
* Cross-site request forgery (CSRF) on logout, on login forms, or on other actions without significant security impact.
* Cross-domain referer leakage without exposure of sensitive data.
* Open redirects without a chained security impact (e.g., credential disclosure or token theft).
* Account or username enumeration on login, registration, or password-reset endpoints.
* Findings produced by automated scanners, or theoretical / "best-practice" reports without a working proof of concept.
* Out-of-date third-party libraries or frameworks without a proof of concept against an in-scope product.
* Non-critical information leakage (server identification headers, stack traces, software version disclosure).

**Configuration and hardening recommendations** (without a demonstrated exploit):

* Missing or weak HTTP security headers (CSP, HSTS, X-Frame-Options, Permissions-Policy, and similar).
* SSL/TLS configuration weaknesses (cipher-suite preference, protocol versions, HSTS preload, certificate-transparency).
* Missing `Secure`, `HttpOnly`, or `SameSite` flags on cookies that do not carry session or authentication state.
* Lack of rate limiting or brute-force protection on non-authentication endpoints.
* DNS or email-authentication misconfiguration (SPF, DKIM, DMARC, NS records) on WSO2 domains, unless it enables practical impersonation.

**Out of scope by policy:**

* Social-engineering or phishing attempts against WSO2 employees, customers, partners, or community members.
* Physical attacks against WSO2 offices, infrastructure, or personnel.
* Findings in third-party assets, demos, staging environments, or domains not owned by WSO2.

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

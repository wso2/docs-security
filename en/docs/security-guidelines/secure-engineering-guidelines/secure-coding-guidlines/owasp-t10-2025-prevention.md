---
title: OWASP Top 10 - 2025 Prevention
category: security-guidelines
version: 1.0
---

# OWASP Top 10 - 2025 Prevention
<p class="doc-info">Version: 1.0</p>
___

This section maps the OWASP Top 10 - 2025 categories to prevention techniques that should be followed by WSO2 engineers when designing, building, and operating WSO2 products and services.

## A01 - 2025 - Broken Access Control
In OWASP Top 10 - 2025, the following vulnerabilities are discussed under Broken Access Control.

* **Path Traversal / Insecure Direct Object References**: Please refer to [General Recommendations for Secure Coding - Path Traversal]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#path-traversal) section.
* **Missing Function Level Access Control**: Please refer to [General Recommendations for Secure Coding - Missing Function Level Access Control]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#missing-function-level-access-control) section.
* **Server-Side Request Forgery (SSRF)**: SSRF, previously a standalone category in 2021, is now treated as a Broken Access Control failure. Please refer to [General Recommendations for Secure Coding - Server Side Request Forgery (SSRF)]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#server-side-request-forgery-ssrf) section.
* **Cross-Origin Resource Sharing (CORS) Misconfiguration**: Please refer to [General Recommendations for Secure Coding - Cross-Origin Resource Sharing]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#cross-origin-resource-sharing) section.
* **Cross-Site Request Forgery (CSRF)**: Please refer to [General Recommendations for Secure Coding - Cross-Site Request Forgery (CSRF)]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#cross-site-request-forgery-csrf) section.
* **Unvalidated Redirects and Forwards**: Please refer to [General Recommendations for Secure Coding - Unvalidated Redirects and Forwards]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#unvalidated-redirects-and-forwards) section.


## A02 - 2025 - Security Misconfiguration
In OWASP Top 10 - 2025, the following vulnerabilities are discussed under Security Misconfiguration.

* **Security Misconfiguration (general)**: Please refer to [General Recommendations for Secure Coding - Security Misconfiguration]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#security-misconfiguration) section.
* **XML External Entity (XXE)**: Please refer to [General Recommendations for Secure Coding - XML External Entity (XXE)]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#xml-external-entity-xxe) section.
* **Missing or Weak Security HTTP Headers**: Please refer to [General Recommendations for Secure Coding - Security Related HTTP Headers]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#security-related-http-headers) section.
* **ClickJacking / Cross Frame Scripting**: Please refer to [General Recommendations for Secure Coding - ClickJacking and Cross Frame Scripting]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#clickjacking-and-cross-frame-scripting) section.
* **Insecure Cookie Attributes**: Please refer to [General Recommendations for Secure Coding - Securing Cookies]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#securing-cookies) section.


## A03 - 2025 - Software Supply Chain Failures
OWASP Top 10 - 2025 expands the 2021 "Vulnerable and Outdated Components" category into broader supply chain risk: dependency vulnerabilities, malicious or compromised packages, dependency confusion, and build-pipeline integrity.

* **Dependency vulnerabilities**: Please refer to [General Recommendations for Secure Coding - Using Known Vulnerable Components]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#using-known-vulnerable-components) section.
* **Supply chain controls (exact pinning, lock files, manifest guards, signed releases, SBOM, registry trust)**: Please refer to [General Recommendations for Secure Coding - Software Supply Chain Failures]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#software-supply-chain-failures) section. The section also references the [WSO2 incident clarifications]({{#base_path#}}/security-announcements/incident-clarifications/) that demonstrate why these controls matter.


## A04 - 2025 - Cryptographic Failures
In OWASP Top 10 - 2025, the following vulnerabilities are discussed under Cryptographic Failures.

* **Approved algorithms, TLS baseline, key management, encryption at rest, JWT signing and verification**: Please refer to [General Recommendations for Secure Coding - Cryptographic Failures]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#cryptographic-failures) section.
* **Heap Inspection Attacks (sensitive data in memory)**: Please refer to [General Recommendations for Secure Coding - Heap Inspection Attacks]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#heap-inspection-attacks) section.
* **Privacy Violation - Password AutoComplete**: Please refer to [General Recommendations for Secure Coding - Privacy Violation - Password AutoComplete]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#privacy-violation-password-autocomplete) section.
* **Random Number Generation**: Please refer to [General Recommendations for Secure Coding - Random Number Generation]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#random-number-generation) section.
* **Secure Cookie Attributes (encrypted transport, HttpOnly, Secure)**: Please refer to [General Recommendations for Secure Coding - Securing Cookies]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#securing-cookies) section.


## A05 - 2025 - Injection
In OWASP Top 10 - 2025, the following vulnerabilities are discussed under Injection. Note that Cross-Site Scripting (XSS) is folded back into Injection in the 2025 list.

* **SQL Injection**: Please refer to [General Recommendations for Secure Coding - SQL Injection]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#sql-injection) section.
* **LDAP Injection**: Please refer to [General Recommendations for Secure Coding - LDAP Injection]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#ldap-injection) section.
* **OS Command Injection**: Please refer to [General Recommendations for Secure Coding - OS Command Injection]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#os-command-injection) section.
* **Cross-Site Scripting (XSS)**: Please refer to [General Recommendations for Secure Coding - Cross-Site Scripting (XSS)]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#cross-site-scripting-xss) section.
* **HTTP Response Splitting (CRLF Injection)**: Please refer to [General Recommendations for Secure Coding - HTTP Response Splitting (CRLF Injection)]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#http-response-splitting-crlf-injection) section.
* **Log Injection / Log Forging (CRLF Injection)**: Please refer to [General Recommendations for Secure Coding - Log Injection / Log Forging (CRLF Injection)]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#log-injection-log-forging-crlf-injection) section.


## A06 - 2025 - Insecure Design
In OWASP Top 10 - 2025, the following vulnerabilities are discussed under Insecure Design.

* **Threat modeling, secure defaults, business-logic discipline, rate limiting, trust boundaries**: Please refer to [General Recommendations for Secure Coding - Insecure Design]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#insecure-design) section. The section also references the [WSO2 Secure Software Development Process]({{#base_path#}}/security-processes/secure-software-development-process/) for the STRIDE-LM design review requirements.
* **Insecure Deserialization (a design-level trust failure)**: Please refer to [General Recommendations for Secure Coding - Insecure Deserialization]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#insecure-deserialization) section.
* **Unrestricted File Upload (design-level input boundary)**: Please refer to [General Recommendations for Secure Coding - Unrestricted File Upload]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#unrestricted-file-upload) section.


## A07 - 2025 - Authentication Failures
In OWASP Top 10 - 2025, the following vulnerabilities are discussed under Authentication Failures.

* **Password policy, password hashing, MFA, account lockout, credential stuffing defences, OAuth 2.0 / OIDC pitfalls (PKCE, state, nonce, redirect URI, refresh token rotation, alg confusion)**: Please refer to [General Recommendations for Secure Coding - Authentication Failures]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#authentication-failures) section.
* **Session Hijacking**: Please refer to [General Recommendations for Secure Coding - Session Hijacking]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#session-hijacking) section.
* **Session Fixation**: Please refer to [General Recommendations for Secure Coding - Session Fixation]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#session-fixation) section.
* **Session Prediction**: Please refer to [General Recommendations for Secure Coding - Session Prediction]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#session-prediction) section.


## A08 - 2025 - Software or Data Integrity Failures
In OWASP Top 10 - 2025, the following vulnerabilities are discussed under Software or Data Integrity Failures.

* **Signed release artefacts, container digest pinning, CI/CD workflow integrity, webhook and auto-update verification**: Please refer to [General Recommendations for Secure Coding - Software and Data Integrity Failures]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#software-and-data-integrity-failures) section. The supply-chain side overlaps with A03 — see [Software Supply Chain Failures]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#software-supply-chain-failures).
* **Insecure Deserialization**: Please refer to [General Recommendations for Secure Coding - Insecure Deserialization]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#insecure-deserialization) section.
* **Trusting components without integrity verification**: Please refer to [General Recommendations for Secure Coding - Using Known Vulnerable Components]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#using-known-vulnerable-components) section.


## A09 - 2025 - Logging & Alerting Failures
In OWASP Top 10 - 2025, the category previously named "Security Logging and Monitoring Failures" is renamed "Logging & Alerting Failures".

* **Insufficient Logging and Monitoring**: Please refer to [General Recommendations for Secure Coding - Insufficient logging and Monitoring]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#insufficient-logging-and-monitoring) section.
* **Log Injection / Log Forging**: Please refer to [General Recommendations for Secure Coding - Log Injection / Log Forging (CRLF Injection)]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#log-injection-log-forging-crlf-injection) section.


## A10 - 2025 - Mishandling of Exceptional Conditions
OWASP Top 10 - 2025 introduces this new category, covering failures in how applications handle errors, exceptions, and unexpected states — including fail-open behaviours, exception messages that leak internals, and missed cleanup of resources.

Please refer to [General Recommendations for Secure Coding - Mishandling of Exceptional Conditions]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-secure-coding/#mishandling-of-exceptional-conditions) section. It covers catch-block discipline, fail-secure defaults for security decisions, sanitised error responses at REST/SOAP boundaries, resource cleanup with `try`-with-resources and Carbon's `PrivilegedCarbonContext` tenant flow, exception logging, and Go-specific guidance on `panic`/`recover`, error wrapping with `%w`, and `defer`-based cleanup.

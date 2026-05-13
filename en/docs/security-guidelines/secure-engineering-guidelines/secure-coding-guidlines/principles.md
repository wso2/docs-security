---
title: Secure Coding Principles
category: security-guidelines
version: 1.0
---

# Secure Coding Principles

<p class="doc-info">Version: 1.0</p>
___

This document is the joint, language-agnostic statement of the security principles every WSO2 engineer is expected to apply, and the public references every engineer is expected to know. It does not repeat material that is already well covered by OWASP, IETF, NIST, or other authoritative bodies — it points to them.

Stack-specific guidance lives in two sibling documents:

* [Java stack secure coding guide]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/java-stack/) — for the established Java-based products, framed around the constraints of working inside a 10+ year codebase.
* [Go stack secure coding guide]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/go-stack/) — for the new Go-based products, framed around the freedom of greenfield code.

The [OWASP Top 10 - 2025 Prevention]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/owasp-t10-2025-prevention/) page maps each 2025 category to the relevant entries here and in the two stack guides.

## Principles WSO2 commits to

These are the rules every WSO2 engineer applies, regardless of the language, framework, or product they work in.

1. **Defence in depth.** Never rely on a single layer. Authentication at the gateway *and* at the service. Encryption in transit *and* at rest. Input validation *and* output encoding. If one control is bypassed, the next one still holds the line.
2. **Fail secure.** On any exception during a security-relevant decision (authentication, authorisation, signature verification, integrity check, license check), the operation must default to deny. Initialise the decision variable to the safe value before the `try` block; never set it to the permissive value inside `catch`.
3. **Least privilege.** Every component, service account, token, role, and database user holds the minimum permissions it needs to do its job. New permissions are added only with explicit justification.
4. **Deny by default.** New code paths default to deny. Allowing access is explicit. The same rule applies to network rules, CORS, container capabilities, CI workflow permissions, and feature flags.
5. **Secure by default.** Risky features ship disabled. Operators opt in to enable them in production. Defaults must be safe to deploy unchanged.
6. **Validate at trust boundaries, re-check at the data layer.** Inputs crossing into a higher trust zone are re-validated on entry. Tenant identity is carried in context and re-checked at the data layer — never inferred from caller input.
7. **Separate authentication from authorisation.** Authentication establishes *who*. Authorisation decides *what they can do*. Both must run on every protected request, and the authorisation check must default to deny.
8. **Audit and observability.** Every security-relevant decision — authentication attempt, authorisation failure, lockout, token issue, key rotation, permission change — emits a structured log event with a correlation identifier. Never log secrets, full tokens, or personal data.
9. **No security through obscurity.** A defence that depends on the attacker not knowing how it works is not a defence. Design assuming the code, configuration, and deployment topology are public.
10. **Treat configuration as code.** Security-relevant settings (algorithms, ciphers, lockout thresholds, rate limits, CORS allow-lists) are version-controlled, reviewed, and validated in CI. Changes go through code review, not a console.

## External references every engineer should know

These are the public bodies of work WSO2 builds on. Read them once; refer to them often. The stack-specific guides cite specific entries from these where they apply.

### General application security

* [OWASP Top 10 (latest)](https://owasp.org/Top10/) — the canonical list of web-application risk categories.
* [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/) — the assertion-by-assertion checklist; WSO2 products target Level 2 by default, Level 3 for security products.
* [OWASP Proactive Controls](https://owasp.org/www-project-proactive-controls/) — the developer-facing companion to the Top 10.
* [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) — per-topic implementation guides (authn, authz, crypto, XSS, SQLi, CSRF, session, logging, file upload, etc.).
* [CWE Top 25](https://cwe.mitre.org/top25/) — the weakness-identifier list that pairs with the OWASP Top 10.

### Identity, authentication, and OAuth

* [NIST SP 800-63 — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/) — authoritative for password policy, MFA, identity proofing, federation.
* [RFC 6749 — OAuth 2.0 Framework](https://datatracker.ietf.org/doc/html/rfc6749) and [RFC 6750 — Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750).
* [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636).
* [RFC 8252 — OAuth 2.0 for Native Apps](https://datatracker.ietf.org/doc/html/rfc8252).
* [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/rfc9700).
* [RFC 7519 — JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519) and [RFC 8725 — JWT BCP](https://datatracker.ietf.org/doc/html/rfc8725).
* [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html).

### Cryptography and transport

* [NIST SP 800-52 — TLS Guidelines](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final).
* [NIST SP 800-131A — Algorithm Transitions](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final).
* [NIST SP 800-57 — Key Management](https://csrc.nist.gov/projects/key-management).
* [Mozilla TLS configuration generator](https://ssl-config.mozilla.org/) — the practical baseline.
* [RFC 8446 — TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446).

### Supply chain and build integrity

* [SLSA — Supply-chain Levels for Software Artifacts](https://slsa.dev/) — the framework WSO2 measures release pipelines against.
* [OWASP Software Component Verification Standard (SCVS)](https://owasp.org/www-project-software-component-verification-standard/).
* [OpenSSF Best Practices](https://www.bestpractices.dev/).
* [CycloneDX SBOM specification](https://cyclonedx.org/) and [SPDX](https://spdx.dev/).

### Logging and incident response

* [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).
* [CWE-703 — Improper Check or Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/703.html).

## Framework alignment

The principles above and the stack-specific guides primarily map to:

* [OWASP Top 10 - 2025]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/owasp-t10-2025-prevention/)
* [OWASP API Security Top 10 - 2023]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/owasp-api-top10-2023-prevention/)

The OWASP Cheat Sheet Series, Proactive Controls, CWE, NIST SP 800-series, IETF RFCs (9700, 8725, 7636, 8594), and SLSA are cited inline in this document and the stack guides where they apply.

## WSO2 internal references

* [WSO2 Secure Software Development Process]({{#base_path#}}/security-processes/secure-software-development-process/) — when threat modelling is required, what design reviews look like.
* [WSO2 Vulnerability Management Process]({{#base_path#}}/security-processes/vulnerability-management-process/).
* [WSO2 Cloud Security Process]({{#base_path#}}/security-processes/cloud-security-process/).
* [Security Reporting]({{#base_path#}}/security-reporting/report-security-issues/) — responsible disclosure and the reward program.
* [WSO2 incident clarifications]({{#base_path#}}/security-announcements/incident-clarifications/) — concrete examples of how supply-chain and other industry incidents play out against WSO2's defensive posture.

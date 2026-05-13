---
title: OWASP API Security Top 10 - 2023 Prevention
category: security-guidelines
version: 2.0
---

# OWASP API Security Top 10 - 2023 Prevention

<p class="doc-info">Version: 2.0</p>
___

This page maps the [OWASP API Security Top 10 - 2023](https://owasp.org/API-Security/editions/2023/en/0x00-header/) categories to the [Secure Coding Guide]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/). The API list complements (it does not replace) the [OWASP Top 10 - 2025 Prevention]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/owasp-t10-2025-prevention/) mapping.

| # | Category | Section in the Secure Coding Guide |
|---|---|---|
| API1 | Broken Object Level Authorization | [Object-level access control (IDOR)]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#object-level-access-control-idor) |
| API2 | Broken Authentication | [Authentication Failures]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#authentication-failures) |
| API3 | Broken Object Property Level Authorization | [Object property-level access control (mass assignment)]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#object-property-level-access-control-mass-assignment) |
| API4 | Unrestricted Resource Consumption | [Pagination, list limits, and resource ceilings]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#pagination-list-limits-and-resource-ceilings) |
| API5 | Broken Function Level Authorization | [Missing Function Level Access Control]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#missing-function-level-access-control) |
| API6 | Unrestricted Access to Sensitive Business Flows | [Sensitive business flows and anti-automation]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#sensitive-business-flows-and-anti-automation) |
| API7 | Server Side Request Forgery | [Server Side Request Forgery (SSRF)]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#server-side-request-forgery-ssrf) |
| API8 | Security Misconfiguration | [Security Misconfiguration]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#security-misconfiguration) |
| API9 | Improper Inventory Management | [API inventory, versioning, deprecation]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#api-inventory-versioning-deprecation) |
| API10 | Unsafe Consumption of APIs | [Unsafe consumption of upstream APIs]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#unsafe-consumption-of-upstream-apis) |

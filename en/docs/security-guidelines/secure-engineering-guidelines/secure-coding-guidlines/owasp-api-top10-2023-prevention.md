---
title: OWASP API Security Top 10 - 2023 Prevention
category: security-guidelines
version: 1.0
---

# OWASP API Security Top 10 - 2023 Prevention

<p class="doc-info">Version: 1.0</p>
___

This page maps the [OWASP API Security Top 10 - 2023](https://owasp.org/API-Security/editions/2023/en/0x00-header/) categories to WSO2's stack-specific secure-coding guides. The API list complements (it does not replace) the [OWASP Top 10 - 2025 Prevention]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/owasp-t10-2025-prevention/) mapping; categories that overlap with the web-application list are cross-referenced.

For each category, follow the link into the stack guide that applies to the codebase you are working in.

## API1:2023 - Broken Object Level Authorization

* Java stack: [Object-level access control (IDOR)]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/java-stack/#object-level-access-control-idor)
* Go stack: [Broken Access Control]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/go-stack/#broken-access-control) (object-level enforcement covered inline)

## API2:2023 - Broken Authentication

* Java stack: [Authentication Failures]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/java-stack/#authentication-failures)
* Go stack: [Authentication Failures]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/go-stack/#authentication-failures)

## API3:2023 - Broken Object Property Level Authorization

* Java stack: [Object property-level access control (mass assignment)]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/java-stack/#object-property-level-access-control-mass-assignment)
* Go stack: [Object property-level access control (mass assignment)]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/go-stack/#object-property-level-access-control-mass-assignment)

## API4:2023 - Unrestricted Resource Consumption

* Java stack: [Pagination, list limits, and resource ceilings]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/java-stack/#insecure-design) (rate-limiting + pagination)
* Go stack: [Pagination, list limits, and resource ceilings]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/go-stack/#insecure-design)

## API5:2023 - Broken Function Level Authorization

* Java stack: [Missing Function Level Access Control]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/java-stack/#missing-function-level-access-control)
* Go stack: [Broken Access Control]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/go-stack/#broken-access-control) (function-level enforcement covered inline)

## API6:2023 - Unrestricted Access to Sensitive Business Flows

* Java stack: [Sensitive business flows and anti-automation]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/java-stack/#sensitive-business-flows-and-anti-automation)
* Go stack: [Sensitive business flows and anti-automation]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/go-stack/#sensitive-business-flows-and-anti-automation)

## API7:2023 - Server Side Request Forgery

* Java stack: [Server Side Request Forgery (SSRF)]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/java-stack/#server-side-request-forgery-ssrf)
* Go stack: [Broken Access Control]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/go-stack/#broken-access-control) (SSRF covered inline)

## API8:2023 - Security Misconfiguration

* Java stack: [Security Misconfiguration]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/java-stack/#security-misconfiguration)
* Go stack: [Security Misconfiguration]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/go-stack/#security-misconfiguration)

## API9:2023 - Improper Inventory Management

* Java stack: [API inventory, versioning, deprecation]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/java-stack/#api-inventory-versioning-deprecation)
* Go stack: [API inventory, versioning, deprecation]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/go-stack/#api-inventory-versioning-deprecation)

## API10:2023 - Unsafe Consumption of APIs

* Java stack: [Unsafe consumption of upstream APIs]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/java-stack/#unsafe-consumption-of-upstream-apis)
* Go stack: [Unsafe consumption of upstream APIs]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/go-stack/#unsafe-consumption-of-upstream-apis)

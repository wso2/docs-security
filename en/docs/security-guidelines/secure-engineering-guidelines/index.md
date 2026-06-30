---
title: Secure Engineering Guidelines
category: security-guidelines
---

# Secure Engineering Guidelines

This section is the entry point to the secure engineering practices WSO2 engineers apply when building WSO2 products. It covers the canonical secure-coding guide, configuration references for the headers and tools that enforce the security posture in production, and the analysis tools that run in CI.

## Secure coding

* [WSO2 Secure Coding Guidelines]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/introduction/): the entry page for the secure coding guides.
* [Secure Coding Guide]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/): the canonical guide, organized by OWASP Top 10 - 2025 categories with stack-specific implementation in content tabs.
* [React Secure Coding Guide]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-react-secure-coding/) covers frontend-specific guidance.

## Configuration references

* [HTTP Security Headers, Configuration Reference]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/security-related-http-headers/): a practical "how to apply" companion covering Carbon/Tomcat, Go middleware, reverse proxy, Kubernetes ingress, and WSO2 API Gateway.
* [OWASP CSRFGuard]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/owasp-csrf-guard/): CSRF token validation configuration for Carbon Java applications.

## Analysis tools

* [Static Code Analysis]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/static-code-analysis-using-findsecuritybugs/): SAST tooling for Java (SpotBugs + Find Security Bugs) and Go (`gosec`, `staticcheck`), plus Semgrep / CodeQL for codebase-specific rules.
* [Dynamic Analysis with OWASP ZAP]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/dynamic-analysis-with-owasp-zap/) covers running ZAP against deployed WSO2 products.
* [Dependency Vulnerability Analysis]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/external-dependency-analysis-analysis-using-owasp-dependency-check/): Dependency Check for Java, `govulncheck` for Go, and `npm audit` for JavaScript.

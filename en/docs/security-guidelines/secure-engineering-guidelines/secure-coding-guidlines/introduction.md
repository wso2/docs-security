---
title: Secure Coding Guidelines
category: security-guidelines
version: 3.0
---

# Secure Coding Guidelines
<p class="doc-info">Version: 3.0</p>
___

## Introduction

This section is the entry point to the **Secure Coding Guidelines** that WSO2 Engineers follow while implementing WSO2 products and applications. The guidelines exist to make sure WSO2 products and applications are inherently secure, by codifying the practices that apply throughout the Software Development Life Cycle.

The guidelines are split by engineering stack, because the Java/Carbon-based products and the new Go-based products live under different constraints. Start with the principles document, then read the stack guide that applies to the codebase you are working in.

* [Secure Coding Principles](principles.md)

     Language-agnostic principles every WSO2 engineer applies, plus the public references (OWASP, NIST, RFCs, SLSA) every engineer is expected to know. Read this first.

* [Java Stack Secure Coding Guide](java-stack.md)

     WSO2-specific secure coding guidance for the established Java-based products (the Carbon-framework codebase). Reflects the constraints of working inside a long-running codebase: existing helpers, existing conventions, cross-bundle constraints.

* [Go Stack Secure Coding Guide](go-stack.md)

     WSO2-specific secure coding guidance for the new Go-based products. Reflects greenfield expectations: adopt the modern pattern by default.

* [General Recommendations for React Secure Coding](general-recommendations-for-react-secure-coding.md)

     Secure coding best practices for React frontends.

* [OWASP Top 10 - 2025 Prevention](owasp-t10-2025-prevention.md)

     Maps the OWASP Top 10 - 2025 categories to the matching sections in the Java and Go stack guides.

* [OWASP API Security Top 10 - 2023 Prevention](owasp-api-top10-2023-prevention.md)

     Maps the OWASP API Security Top 10 - 2023 categories to the matching sections in the Java and Go stack guides.

* [Tooling Recommendations for Secure Coding](tooling-recommendations-for-secure-coding.md)

     Documentation on security-related tooling used within WSO2 and recommendations for such tools in the engineering process.

---
title: Choreo Security Bulletin – H1 2026
category: security-announcements
published: "2026-09-23"
version: "1.0.0"
---

# Choreo Security Bulletin – H1 2026

<p class="doc-info">Published: 2026-09-23</p>
<p class="doc-info">Version: 1.0.0</p>

### BULLETIN ID  
CHO-SB-2026-H1

### SCOPE  
This bulletin summarizes security vulnerabilities addressed during the H1 of 2026 for Choreo.

### VULNERABILITIES ADDRESSED

| Reference ID | Title | Severity | Summary |
|--------------|-------|----------|---------|
| CHO-2026-001 | Cross-Organization IDOR in Applications API | High | An Insecure Direct Object Reference (IDOR) vulnerability in the Choreo Applications API allowed a user to access another organization’s application and OAuth credential information by supplying that application’s ID while using a token bound to their own organization. The affected endpoints did not consistently validate application ownership or organization membership, potentially exposing consumer keys and secrets and allowing unauthorized modification of application credentials. The affected API endpoints were remediated to correctly enforce application and organization-level authorization checks, preventing cross-organization access. |
| CHO-2026-002 | Envoy Admin API Exposure via Gateway SSRF | Critical | A Server-Side Request Forgery (SSRF) vulnerability in the Choreo Connect Gateway allowed a user with API creation privileges to configure a backend pointing to the local Envoy Admin interface, exposing administrative operations through a deployed API proxy. This could allow gateway disruption, including shutting down or draining Envoy listeners, as well as disclosure of internal Envoy configuration information. The exposed Envoy Admin endpoint was removed from the Choreo gateway, eliminating the vulnerable access path. Broader SSRF protections preventing unsafe backend targets such as loopback, link-local, and internal addresses from being configured were identified as follow-up hardening. |
| CHO-2026-003 | API Manager Authentication Bypass Leading to Remote Code Execution | Critical | An authentication bypass vulnerability in Choreo Product APIM allowed an unauthenticated attacker to use a forged HS256 JWT to bypass Admin API authentication. This could provide access to sensitive API Manager configuration and enable privilege escalation through self-registration, which could then be chained with a previously identified Rhino ClassShutter bypass to achieve remote code execution. The separately reported RS256 static-keystore attack was confirmed not to affect Choreo because it does not use the default Docker keystore. The HS256 issue was remediated by changing the authentication flow so failed or unsupported JWT signatures are rejected instead of being silently passed to the next interceptor, with invalid requests returning `401 Unauthorized`. |
| CHO-2026-004 | Arbitrary File Download via API Import | Critical | An arbitrary file download vulnerability was reported in the API import/export flow of WSO2 API Manager, where crafted API documentation metadata could be used to reference local files. The issue was investigated against Choreo Product API Manager, Bijira, and Devant and was determined not to be exploitable in these products because their organization and tenancy model differs from standard API Manager. In Choreo, imported documentation was stored under `carbon.super` rather than the requesting organization, preventing the user from retrieving the targeted file content. Reproducing the reported attack required modifying the product code to change this behavior, confirming that the vulnerability was not exploitable in the deployed product. As a precaution, Nginx-level controls were also applied to block the affected Publisher API routes in the Choreo AWS and Azure control planes. |
| CHO-2026-005 | Stored XSS in Markdown Rendering Leading to Account Takeover | High | A stored Cross-Site Scripting (XSS) vulnerability in Choreo’s Markdown rendering flow allowed malicious HTML/JavaScript embedded in a linked repository’s `README.md` file to execute when users viewed the project home page. This could expose browser session data and potentially enable account takeover, including against privileged users. The issue was remediated by hardening the Markdown rendering flow to prevent execution of unsafe embedded content. |
| CHO-2026-006 | Loss of Operation-Level Scopes During Component Promotion | Low | A security issue in Choreo BYOC promotion caused operation-level scopes and permissions to be lost when certain components were promoted, resulting in scope metadata not being propagated correctly to Choreo API Manager. This could cause runtime requests with a valid access token to bypass the intended operation-level scope validation. The remediation included rolling affected components back to known-good revisions and applying a Choreo Console fix that restored scope propagation and validation for both BYOC and Ballerina service components. Follow-up impact analysis confirmed that no external customers were affected. |

### CREDITS  
Choreo product team would like to thank all internal and external researchers for responsibly disclosing the above issues.

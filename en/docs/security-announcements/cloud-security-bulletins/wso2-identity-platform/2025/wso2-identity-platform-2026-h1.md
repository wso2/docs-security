---
title: WSO2 Identity Platform Security Bulletin – H1 2026
category: security-announcements
version: "1.0.0"
---

# WSO2 Identity Platform Security Bulletin – H1 2026

<p class="doc-info">Published: July 4, 2026</p>
<p class="doc-info">Version: 1.0.0</p>

### BULLETIN ID  
ASG-SB-2026-H1

### SCOPE  
This bulletin summarizes security vulnerabilities addressed during the H1 of 2026 for WSO2 Identity Platform.

### VULNERABILITIES ADDRESSED

| Reference ID | Title | Severity | Summary |
|--------------|-------|----------|---------|
| CVE-2026-31431 | Linux Kernel Privilege Escalation Vulnerability | Low | The "Copy Fail" vulnerability materializes as a logic flaw within the Linux kernel’s crypto subsystem, specifically affecting the `algif_aead` and `AF_ALG` interfaces. This flaw allows an unprivileged local user to perform controlled writes into page cache memory, which can be exploited to modify setuid binaries, resulting in full privilege escalation from a standard user to root. |
| ASG-2026-001 | Remote Code Execution via Layout Configuration in Branding API | Critical | The vulnerability stems from insufficient input validation within the html content field of the layout configuration used by the Branding API. The exploit allows attackers to submit a malicious remote URL via the Branding API (POST or PUT), which the system then stores. When a user subsequently loads the tenant login page, the system attempts to resolve the layout, fetching and deserializing the attacker-controlled content, which results in code execution. |
| ASG-2026-002 | Cross-Site Scripting (XSS) in WSO2 Identity Platform Custom Layout Feature | Medium | The WSO2 Identity Platform Custom Layout feature has a reported XSS vulnerability (ID #FID008) that could enable full account takeovers of users and organizations. The vulnerability, initially assessed with higher severity, was later mutually rated at 6.4. Since its discovery in 2025, teams have debated remediation strategies, including restricting custom layouts to enterprise tiers or configuring custom domains. As of July 2026, the issue remains open as the team evaluates alternative solutions and awaits a final business decision on the implementation path. |
| CVE-2026-42945 | Heap Buffer Overflow in NGINX `ngx_http_rewrite_module` | Critical | The vulnerability, NGINX Rift (CVE-2026-42945), is a critical heap buffer overflow in NGINX's `ngx_http_rewrite_module` with a CVSS score of 9.2. Discovered after 18 years, this flaw allows unauthenticated attackers to trigger a crash or achieve Remote Code Execution (RCE) via crafted HTTP requests. The exploit is deterministic and affects configurations where unnamed PCRE captures interact with specific rewrite, if, or set directives. Because the architecture allows attackers to retry without cost, it poses a severe risk to all NGINX deployments. |
| ASG-2026-003 | Multiple Vulnerabilities in ingress-nginx Ingress Controller | High | The ingress-nginx Ingress Controller for Kubernetes contained several vulnerabilities, including NGINX configuration injection, potential arbitrary code execution, secrets exposure, and denial of service. The Admission Controller component was exposed without authentication, allowing attackers to inject malicious NGINX configurations or AdmissionReview requests. These issues impacted ingress-nginx versions prior to v1.13.7 and v1.14.3. Remediation required identifying affected deployments and upgrading them to patched versions (v1.13.7 or later, or v1.14.3 or later) to secure the clusters. |
| ASG-2026-004 | Identity Server SQL Injection Vulnerability via Sessions API | High | An SQL injection vulnerability was identified in the WSO2 Identity Server within the `GET /api/users/v1/sessions` endpoint. This issue stems from the improper handling of user-supplied filter data, allowing attackers to manipulate SQL queries. By crafting specific inputs, an attacker could potentially extract sensitive data, including session information, from the database. The vulnerability has been confirmed, and a fix has been developed and deployed for affected environments like WSO2 Identity Platform. WSO2 versions 6.0.0 and above, as well as 5.10.0, were impacted, while earlier versions like 5.11.0 and APIM products remained unaffected. |
| ASG-2026-005 | Token Revocation Failure for Sub-Organization Users Upon Role Update | High | The vulnerability involves a token revocation failure affecting sub-organization and B2B SaaS application users. When role updates are performed for these users in WSO2 Identity Platform or WSO2 Identity Server, their existing access tokens are not correctly revoked. This occurs due to an incorrect user resolution during the revocation flow, causing tokens to remain active after users are removed from application roles. The team identified the root cause, implemented fixes, updated the security advisory, and deployed the necessary patches to production. |
| ASG-2026-006 | Broken Object Level Authorization (BOLA) in Push Authenticator Device APIs | Medium | The security vulnerability (HK177) allows authenticated users to read or delete push authenticator device records belonging to other users, even across different tenants. This occurs because the APIs lack proper authorization checks, failing to verify if the requesting user owns the device. An attacker exploiting this could unregister a victim's device, locking them out of push authentication. To remediate this, the team recommended enforcing API-level validation to verify device ownership and implementing tenant-level validation at the database query level to ensure access is restricted to authorized users. |

### CREDITS  
WSO2 Identity Platform thanks all internal and external researchers for responsibly disclosing the above issues.

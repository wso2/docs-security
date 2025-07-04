---
title: Asgardeo Security Bulletin – H1 2025
category: security-announcements
published: "2025-07-04"
version: "1.0.0"
---

# Asgardeo Security Bulletin – H1 2025

<p class="doc-info">Published: 2025-07-04</p>
<p class="doc-info">Version: 1.0.0</p>

### BULLETIN ID  
ASG-SB-2025-H1

### SCOPE  
This bulletin summarizes security vulnerabilities addressed during the H1 of 2025 for Asgardeo.

### VULNERABILITIES ADDRESSED

| Reference ID | Title | Severity | Summary |
|--------------|-------|----------|---------|
| ASG-2025-001 | Tokens not revoked on role unassignment | High | Access tokens continued to work after the user’s role was removed or the consuming app’s role was deleted. |
| ASG-2025-002 | Multi-tenant bypass via conditional auth function | High | Multi-attribute login functions could be triggered across tenant boundaries. |
| ASG-2025-003 | Tokens valid post admin removal in suborg | Medium | Tokens of removed admins in sub-orgs remained valid. |
| ASG-2025-004 | Clickjacking in Console and My Account | Medium | UI could be embedded via iframes, potentially tricking users into unintended actions. |
| ASG-2025-005 | Root org registration abuse | High | Attacker could register a root org using another user’s email and enumerate root orgs of unrelated users. |
| ASG-2025-006 | Username logged on auth failure | Low | Username values were exposed in logs during authentication failures. |
| ASG-2025-007 | Auth code not revoked on password update | Medium | Authorization codes continued to be valid after a user changed their password. |
| CVE-2025-24813 | Apache Tomcat RCE / Info Disclosure | Critical | Upstream vulnerability affecting embedded Tomcat. Patched to latest version. |
| ASG-2025-008 | NGINX “IngressNightmare” | Critical | Vulnerabilities in ingress configuration leading to potential unauthorized access or routing bypass. CVE-2025-1974, CVE-2025-24514, CVE-2025-1097, CVE-2025-1098, CVE-2025-24513 |
| ASG-2025-009 | Access Token retrieval via ‘code token’ flow | High | Improper validation allowed tokens to be issued under improper flow conditions. |

### CREDITS  
Asgardeo thanks all internal and external researchers for responsibly disclosing the above issues.

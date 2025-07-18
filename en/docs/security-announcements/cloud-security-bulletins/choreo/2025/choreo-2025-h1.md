---
title: Choreo Security Bulletin – H1 2025
category: security-announcements
published: "2025-07-15"
version: "1.0.0"
---


# Choreo Security Bulletin – H1 2025

<p class="doc-info">Published: 2025-07-15</p>
<p class="doc-info">Version: 1.0.0</p>

### BULLETIN ID  
CHO-SB-2025-H1

### SCOPE  
This bulletin summarizes security vulnerabilities addressed during the H1 of 2025 for Choreo.

### VULNERABILITIES ADDRESSED

| Reference ID | Title | Severity | Summary |
|--------------|-------|----------|---------|
| CHO-2025-001 | Insecure Trust of id_token in Token Exchange Flow Leading to Potential Account Takeover in Choreo | Medium | Choreo STS trusts the id_token during token exchange to issue access tokens. Since id_tokens can be exposed via OIDC logout flows, this can lead to account takeover if an attacker obtains a valid id_token. |
| CHO-2025-002 | Email Exposure in Access Logs via Query Parameter in User Invitation Delete API | Medium | User email is getting logged in access logs due to email is passed as a query parameter in the user invitation delete API. |
| CHO-2025-003 | Tokens from Removed Key Manager Application Still Authorized in Choreo | Critical | JWT tokens issued by a previously configured Key Manager application in Asgardeo remain valid even after the application is removed from a Choreo service. This allows continued access to APIs using old tokens, which poses a security risk and contradicts expected token invalidation behavior upon Key Manager changes. |
| CHO-2025-004 | Unauthorized Git Credential Creation by Low-Privileged User | Medium | Low-privileged users can add Git credentials to the organization, which should not be permitted by design. Although this does not directly affect the security posture (as Viewers cannot build or deploy), it violates the principle of least privilege and could allow setup of misleading or unverified Git sources. |
| CHO-2025-005 | Git Credential Modification Causing Build Disruption | Medium | Low-privileged users are able to update existing Git credentials. While the modification doesn’t affect already running services, it can cause build failures if those credentials are used in a component rebuild, disrupting availability. This is a CI/CD pipeline risk that stems from improper privilege enforcement and could result in temporary denial of service for updates. |
| CHO-2025-006 | NGINX “IngressNightmare” | Critical | Vulnerabilities in ingress configuration leading to potential unauthorized access or routing bypass. CVE-2025-1974, CVE-2025-24514, CVE-2025-1097, CVE-2025-1098, CVE-2025-24513 |

### CREDITS  
Choreo product team would like to thank all internal and external researchers for responsibly disclosing the above issues.


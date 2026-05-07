---
title: Asgardeo Security Bulletin – H2 2025
category: security-announcements
version: "1.0.0"
---

# Asgardeo Security Bulletin – H2 2025

<p class="doc-info">Published: 2026-05-06</p>
<p class="doc-info">Version: 1.0.0</p>

### BULLETIN ID  
ASG-SB-2025-H2

### SCOPE  
This bulletin summarizes security vulnerabilities addressed during the H2 of 2025 for Asgardeo.

### VULNERABILITIES ADDRESSED

| Reference ID | Title | Severity | Summary |
|--------------|-------|----------|---------|
| CVE-2025-48976 | Vulnerable Library Present in Asgardeo | High | Allocation of resources for multipart headers with insufficient limits enabled a DoS vulnerability in Apache Commons FileUpload. This issue affects Apache Commons FileUpload from 1.0 before 1.6 and from 2.0.0-M1 before 2.0.0-M4. Users are recommended to upgrade to versions 1.6 or 2.0.0-M4, which fix the issue. |
| ASG-2025-010 | Potential broken authorization via Attribute Configurations | Low | The Attribute Configurations controls offered via the Console application are applicable only to the UI profiles, while the backend APIs continue to follow the standard schema mutability. |
| ASG-2025-011 | Locked users can successfully log in through Magic Link authenticator | Medium | Without proper account state checks, locked users may still be able to authenticate using Magic Links or Pass Keys. This could result in unintended access to restricted accounts. |
| ASG-2025-012 | DoS vulnerability in SMS OTP flow in Asgardeo | Medium | The process for sending an SMS runs in the same thread that serves the client request. Since there are a limited number of threads, configuring a slow or delayed endpoint for the SMS provider and continuously sending authentication requests can block those threads, potentially causing degraded performance or server unresponsiveness. |
| ASG-2025-013 | Reflected URL Injection (User-Initiated Open Redirect) in Recovery portal | Medium | The callback parameter value is directly injected into a `<a href="...">` attribute without proper validation. While the application does not perform an automatic HTTP 3xx redirect, the maliciously crafted URL is embedded in a link on the trusted domain. |
| ASG-2025-014 | DoS via adaptive script in Asgardeo | High | Once the vulnerable adaptive script is planted, OOM would kill the pods leading to a service unavailability. |
| ASG-2025-015 | Email enumeration using login with EmailTOTP flow | Low | By enumerating the user on the platform, malicious users can use that against targeted attacks. |
| ASG-2025-016 | Reflected XSS in Authentication Endpoint | Medium | Reflected XSS impacts include session hijacking, leading to account takeover, credential theft through fake login pages, redirection to malicious sites, or data exfiltration and modification. |
| ASG-2025-017 | Text Injection Vulnerabilities in Authentication Endpoints - `device.do` & `hyprlogin.jsp` | Medium | Delivers unwanted messages to users under the Asgardeo domain. |
| ASG-2025-018 | Deletion of secret types using Secret Type Management API results in deletion of all associated secrets across all organizations, leading to potential service downtime in flows where secrets are configured | Medium | An attacker can register an Asgardeo organization and then delete all the secrets defined for a given secret type in all organizations using the Secret Type Management API. This can lead to downtimes for other Asgardeo customers who are using secrets in their organizations in different flows such as authentication and integrations until the customers configure the same secrets again. |
| ASG-2025-019 | Improper token invalidation for users in disabled secondary userstores | Medium | Tokens issued for users in disabled userstores remain valid and usable until expiry. This undermines administrator intent to immediately revoke access tied to decommissioned userstores. Users from a disabled userstore can continue accessing APIs, leading to unauthorized or prolonged access. This weakens policy enforcement and creates security blind spots. |
| ASG-2025-020 | Improper token invalidation when disabling an application | Medium | Tokens issued through a now-disabled application remain valid until expiry. This means administrators cannot immediately cut off access for applications that are disabled. An attacker or malicious user holding such a token can continue accessing an end application even though the application has been explicitly disabled at the Asgardeo level. This undermines administrator intent, weakens security policy enforcement, and could lead to unauthorized or prolonged access. |
| ASG-2025-021 | Risk of Phishing via Magic Link Redirect Manipulation | High | A vulnerability in the magic link flow could allow an attacker to trigger a legitimate email from the trusted system while redirecting the user to an attacker-controlled phishing page. Since the email appears authentic, users may be tricked into entering credentials, sharing sensitive information, or downloading malicious content. Successful exploitation could lead to credential theft, account takeover, tenant data exposure, and further social engineering attacks. |
| ASG-2025-022 | Improper token invalidation for sub-organization tokens when parent application is disabled | Medium | Access tokens issued for sub-organizations may remain valid for approximately 15 minutes after the parent application is disabled. During this grace period, users or compromised tokens may continue accessing protected resources despite the administrative action. This delays enforcement of access revocation, weakens administrator control, and could allow temporary unauthorized access after an application has been disabled. |
| ASG-2025-023 | Cross-Tenant Email OTP triggering and Username Enumeration | Medium | A flaw in the OTP flow could allow attackers to repeatedly trigger OTP emails for users within a targeted tenant. While not critical on its own, this could help attackers confirm registered user email addresses, support phishing or social engineering attempts, harass users with repeated emails, or create large-scale email delivery delays. If abused at scale, it may impact OTP delivery reliability and damage customer trust in the SaaS platform. |
| ASG-2025-024 | Phone Number Exposure and User Enumeration via SMS Provider Webhook | Medium | A flaw in the SMS OTP flow could allow an attacker to use their own SMS provider configuration and webhook to determine whether a victim exists in the system. If the victim exists, the webhook may be triggered and expose the victim's phone number. This could enable username enumeration, privacy exposure, and follow-up phishing or social engineering attacks targeting confirmed users. |
| ASG-2025-025 | DoS vulnerability with user sessions API | Medium | The `/api/users/v1/sessions` endpoint was found to place significant load on the Asgardeo session database when invoked repeatedly due to a heavy backend query. |
| ASG-2025-026 | Active credential exposure from Shai-Hulud supply chain attack | Critical | The Shai-Hulud 2.0 worm infects npm packages to steal cloud credentials and GitHub tokens. It establishes persistent access via self-hosted GitHub Actions runners and spreads automatically through CI/CD pipelines. |

### CREDITS  
Asgardeo thanks all internal and external researchers for responsibly disclosing the above issues.

---
title: WSO2 API Platform Security Bulletin – H2 2025
category: security-announcements
published: "2026-04-08"
version: "1.0.0"
---

# WSO2 API Platform Security Bulletin – H2 2025

<p class="doc-info">Published: 2026-04-08</p>
<p class="doc-info">Version: 1.0.0</p>

### BULLETIN ID  
APIP-SB-2025-H2

### SCOPE  
This bulletin summarizes security vulnerabilities addressed during the H2 of 2025 for WSO2 API Platform.

### VULNERABILITIES ADDRESSED

| Reference ID | Title | Severity | Summary |
|--------------|-------|----------|---------|
|APIP-2025-001 | Scope Configuration Limitation | Medium | The default Security Token Service (STS) provided with the platform does not support application-bound scope authorization. This means that scopes cannot be restricted or validated based on a specific application when using the internal key manager.<br/> To enable application-level scope authorization, you must integrate an external key manager that provides this functionality.

### CREDITS  
WSO2 API Platform product team would like to thank all internal and external researchers for responsibly disclosing the above issues.


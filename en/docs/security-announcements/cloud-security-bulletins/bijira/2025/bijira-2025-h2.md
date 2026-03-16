---
title: Bijira Security Bulletin – H2 2025
category: security-announcements
published: "2025-10-01"
version: "1.0.0"
---

# Bijira Security Bulletin – H2 2025

<p class="doc-info">Published: 2025-10-01</p>
<p class="doc-info">Version: 1.0.0</p>

### BULLETIN ID  
BIJ-SB-2025-H2

### SCOPE  
This bulletin summarizes security vulnerabilities addressed during the H2 of 2025 for Bijira.

### VULNERABILITIES ADDRESSED

| Reference ID | Title | Severity | Summary |
|--------------|-------|----------|---------|
| BIJ-2025-001 | Scope Configuration Limitation | Medium | The default Security Token Service (STS) provided with the platform does not support application-bound scope authorization. This means that scopes cannot be restricted or validated based on a specific application when using the internal key manager.<br/> To enable application-level scope authorization, you must integrate an external key manager that provides this functionality.

### CREDITS  
Bijira product team would like to thank all internal and external researchers for responsibly disclosing the above issues.


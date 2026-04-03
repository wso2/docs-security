---
title: Axios NPM Supply Chain Compromise
category: security-announcements
---

# Axios NPM Supply Chain Compromise
<p class="doc-info">Version: 1.0</p>
<p class="doc-info">Published: April 3, 2026</p>
<p class="doc-info">Last Updated: April 3, 2026</p>
<p class="doc-info">WSO2 impacted: Yes</p>
<p class="doc-info">Evidence of compromise: No</p>
<p class="doc-info">Customers impacted: No (Unless potential exposure conditions are met)</p>
<p class="doc-info">Customer actions required: No (Unless potential exposure conditions are met)</p>
---

### Reported Incident
On March 30, 2026, a security incident was reported involving malicious versions of the Axios HTTP client library: specifically, axios@1.14.1 and axios@0.30.4. These versions were published to npm through a compromised maintainer account and included a hidden dependency, plain-crypto-js@4.2.1. This dependency executes a post-installation script that served as a cross-platform remote-access trojan dropper for macOS, Windows, and Linux. The malicious packages were modified to exfiltrate sensitive information, including authentication tokens and configuration details from developer environments and pipelines.

### Impact on WSO2 Products and Deployments
Following the reported incident, the WSO2 Security Team immediately collaborated with the engineering teams to review the Axios versions used across WSO2 products and services. In addition, developer machines, build environments, and WSO2-managed deployments were examined for indicators of compromise, and no evidence of impact was found.

WSO2 official product release artifacts rely on pinned dependencies defined in the package-lock.json file. Our assessment confirmed that these artifacts did not resolve to any of the malicious Axios versions associated with the incident.

#### Potential Exposure Conditions
Exposure may be possible only in cases where deployments were modified from the official release baseline. This includes scenarios in which:

* a semantic versioning range, such as ^0.30.0, was specified in the package.json file instead of an exact version, and npm install was executed; or
* npm update was executed during the incident window between March 31, 2026, 00:21 UTC and 03:15 UTC.
In such cases, a malicious version may have been resolved unintentionally.

#### Recommended Action
For customized deployments, WSO2 recommends pinning the Axios version in package.json to the exact version recorded in the corresponding package-lock.json file. This helps prevent unintended resolution to compromised versions.

#### Conclusion
Based on this analysis, WSO2 products and services deployed using unmodified official release artifacts are not affected by this supply chain attack. Customers using unmodified official release artifacts are likewise not impacted.

### References
[^1]: [https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)

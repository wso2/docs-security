---
title: SolarWinds SUNBURST breach
category: security-announcements
published: January 5, 2021
wso2_impacted: "No"
evidence_of_compromise: "No"
customer_action_required: "No"
---

### Reported Vulnerability
Solarwinds Orion (with Web Console WPM 2019.4.1, and Orion Platform HF4 or NPM HF2 2019.4) allows remote attackers to execute arbitrary code via a defined event[^1][^2][^3].


### Impact on WSO2 Products and Deployments
WSO2 does not use Solarwinds components other than Solarwinds Pingdom which is not affected by the published security advisory[^2]. Hence, WSO2 products and services have not been affected by the Solarwinds product related vulnerabilities or exploits. 

Solarwinds Pingdom is a cloud based website monitoring platform which WSO2 uses in order to monitor the organization's public facing website metrics such as uptime.


### References
[^1]: [https://www.cve.org/CVERecord?id=CVE-2020-14005](https://www.cve.org/CVERecord?id=CVE-2020-14005)
[^2]: [https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-solarwinds-orion-could-allow-for-arbitrary-code-execution_2020-166/](https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-solarwinds-orion-could-allow-for-arbitrary-code-execution_2020-166/)
[^3]: [https://www.solarwinds.com/securityadvisory](https://www.solarwinds.com/securityadvisory)

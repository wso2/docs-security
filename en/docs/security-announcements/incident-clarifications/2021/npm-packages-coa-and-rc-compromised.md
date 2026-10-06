---
title: NPM packages coa and rc Compromised
category: security-announcements
published: November 10, 2021
wso2_impacted: "No"
evidence_of_compromise: "No"
customer_action_required: "No"
---

### Reported Incident
NPM package **coa** and **rc** poissonate security breach were identified on November 4, 2021. In addition, The security advisories[^1][^2] were published on November 4, 2021.

WSO2 uses the coa and rc Javascript libraries in multiple WSO2 products and services. 


### Impact on WSO2 Products and Deployments
As the incident reported, the WSO2 Security and Compliance team immediately coordinated an effort with engineering teams to identify if any WSO2 product or service uses the compromised Javascript libraries versions.

As per the detailed analysis, it's been confirmed that WSO2 products and services are not using the vulnerable versions of coa and rc. 

Thereby confirming that WSO2 or WSO2 customers are not impacted by the said vulnerability.


### Security Controls against supply chain attacks
* All the PRs will be reviewed and Merged. During this process, if there were any sensitive data on the PRs those will be removed.
* All packages/ artifacts will undergo both Static and Dynamic application testing phases prior to production releases.


### References
[^1]: [https://github.com/advisories/GHSA-73qr-pfmq-6rp8](https://github.com/advisories/GHSA-73qr-pfmq-6rp8)
[^2]: [https://github.com/advisories/GHSA-g2q5-5433-rhrf](https://github.com/advisories/GHSA-g2q5-5433-rhrf)

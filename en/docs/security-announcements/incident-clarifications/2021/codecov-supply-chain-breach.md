---
title: Codecov supply chain breach
category: security-announcements
published: May 31, 2021
wso2_impacted: "Yes"
evidence_of_compromise: "No"
customer_action_required: "No"
---

### Reported Incident
**Codecov's** breach which was announced on April 15, 2021. In addition, Codecov updated the initial security notifications with Indicators of compromise (IOC) on April 29, 2021.


### Impact on WSO2 Products and Deployments
WSO2 uses Codecov to determine the code coverage for the certain public repositories. 

The WSO2 security team coordinated the rotation of credentials and tokens as per the guidance of Codecov on April 15, 2021. 

There was no evidence of compromise was detected, and we don’t expect any impacts to WSO2 products or services.


### Security Controls against supply chain attacks
* We have not integrated sensitive private repositories with code coverage tools.
* All the PRs will be reviewed and Merged. During this process, if there were any sensitive data on the PRs those will be removed.
* All packages/ artifacts will undergo both Static and Dynamic application testing phases prior to production releases.


### References
[^1]: [https://about.codecov.io/security-update/](https://about.codecov.io/security-update/)

---
title: NPM package UA-Parser-JS Compromised
category: cves-and-incidents
---

# NPM package UA-Parser-JS Compromised

<p class="doc-info">WSO2 impacted: No</p>
<p class="doc-info">Evidence of compromise: No</p>
<p class="doc-info">Customers actions required: No</p>
---

### Reported Incident
NPM package **UA-Parser-JS** poissonate security breach was identified on October 22, 2021. In addition, The security advisory [1] was published on October 23, 2021.

WSO2 uses the ua-parser-js Javascript library in multiple WSO2 products and services. 


### Impact on WSO2 Products and Deployments
As the incident reported, the WSO2 Security and Compliance team immediately coordinated an effort with engineering teams to identify if any WSO2 product or service uses the compromised Javascript library version.

As per the detailed analysis, it's been confirmed that WSO2 products and services are not using the vulnerable version of ua-parser-js. 

Thereby confirming that WSO2 or WSO2 customers are not impacted by the said vulnerability.


### Security Controls against supply chain attacks
* All the PRs will be reviewed and Merged. During this process if there were any sensitive data on the PRs those will be removed.
* All packages/ artifacts will undergo both Static and Dynamic application testing phases prior to production releases.


### References
[1] [https://github.com/advisories/GHSA-pjwm-rvh2-c87w](https://github.com/advisories/GHSA-pjwm-rvh2-c87w)
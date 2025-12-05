---
title: NPM Supply Chain Attack - Shai-Hulud 2.0
category: security-announcements
---

# NPM Supply Chain Attack - Shai-Hulud 2.0
<p class="doc-info">Version: 1.0</p>
<p class="doc-info">Published: December 5, 2025</p>
<p class="doc-info">Last Updated: December 5, 2025</p>
<p class="doc-info">WSO2 impacted: Yes</p>
<p class="doc-info">Evidence of compromise: Yes</p>
<p class="doc-info">Customers impacted: No</p>
<p class="doc-info">Customers actions required: No</p>
---

### Reported Incident
On November 21, 2025, we were made aware of a software supply chain attack affecting certain open-source NPM packages, referred to in the security community as "Shai-Hulud 2.0" [1]. This self-propagating worm is designed to extract developers’ secrets accessible to CI/CD pipelines, upload them to a public GitHub repository, and enable attackers to access them. It also repacks itself into available NPM packages and injects malicious payloads.
WSO2 primarily uses NPM (Node Package Manager) to manage dependencies and packages, and to build its JavaScript-based components and modern user interfaces (UIs).
### Impact on WSO2 Products and Deployments

As soon as this was reported, the WSO2 Security and Compliance team immediately coordinated with engineering teams to determine whether any WSO2 products or services used the affected NPM packages and to check whether end-user devices were affected.

It has been confirmed through detailed analysis that WSO2 products, services, and managed deployments are not affected. Therefore, WSO2 customers are not impacted by this incident.

However, two end-user devices were affected, which did not have a bearing on WSO2 products, services, or customer deployments. WSO2 has taken the necessary actions to remediate the impact by rotating credentials and eradicating the infection. 

### References

[^1]: [https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack#which-actions-should-security-teams-take-42](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack#which-actions-should-security-teams-take-42)
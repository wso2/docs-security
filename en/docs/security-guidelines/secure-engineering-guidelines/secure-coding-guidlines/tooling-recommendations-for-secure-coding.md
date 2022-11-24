---
title: Tooling Recommendations for Secure Coding
category: security-guidelines
published: October 22, 2018
version: 2.0
---

# Tooling Recommendations for Secure Coding
<p class="doc-info">Version: 2.0</p>
___

## Security Related Static Code Analysis 
Find Security Bugs[^2], FindBugs plugin is the recommended tool for performing static security analysis.

!!! tip hint important "WSO2 Document Reference"
    Further information on using OWASP Zed Attack Proxy (ZAP) with WSO2 recommended security policies are available in the [Engineering Guidelines - Tooling - Static Code Analysis using FindSecurityBugs](../static-code-analysis-using-findsecuritybugs.md) document.


## Security Related Dynamic Analysis
OWASP Zed Attack Proxy(ZAP)[^1] is the recommended tool for performing dynamic security analysis. 

!!! tip hint important "WSO2 Document Reference"
    Further information on using OWASP Zed Attack Proxy (ZAP) with WSO2 recommended security policies are available in the [Engineering Guidelines - Tooling - Dynamic Analysis with OWASP ZAP](../dynamic-analysis-with-owasp-zap.md) document.


## Dependency Vulnerability Analysis 
OWASP Dependency Check[^3] is the recommended tool for performing dependency vulnerability analysis.

!!! tip hint important "WSO2 Document Reference"
    Further information on using OWASP Dependency Check is documented at [Engineering Guidelines - External Dependency Analysis using OWASP Dependency Check](../external-dependency-analysis-analysis-using-owasp-dependency-check.md) document.


## References
[^1]: [https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)
[^2]: [http://find-sec-bugs.github.io/](http://find-sec-bugs.github.io/)
[^3]: [https://www.owasp.org/index.php/OWASP_Dependency_Check](https://www.owasp.org/index.php/OWASP_Dependency_Check)

---
title: Tooling Recommendations for Secure Coding
category: security-guidelines
published: October 22, 2018
---

# Tooling Recommendations for Secure Coding

## Security Related Static Code Analysis 
Find Security Bugs[^2], FindBugs plugin is the recommended tool for performing static security analysis.

!!! tip hint important "WSO2 Document Reference"
    Further information on using OWASP Zed Attack Proxy (ZAP) with WSO2 recommended security policies are available at [Engineering Guidelines - Tooling - Static Code Analysis using FindSecurityBugs]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/static-code-analysis-using-findsecuritybugs/) document.


## Security Related Dynamic Analysis
OWASP Zed Attack Proxy(ZAP)[^1] is the recommended tool for performing dynamic security analysis. 

!!! tip hint important "WSO2 Document Reference"
    Further information on using OWASP Zed Attack Proxy (ZAP) with WSO2 recommended security policies are available at [Engineering Guidelines - Tooling - Dynamic Analysis with OWASP ZAP]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/dynamic-analysis-with-owasp-zap/) document.


## Dependency Vulnerability Analysis 
OWASP Dependency Check[^3] is the recommended tool for performing dependency vulnerability analysis.

!!! tip hint important "WSO2 Document Reference"
    Further information on using OWASP Dependency Check is documented at [Engineering Guidelines - External Dependency Analysis using OWASP Dependency Check]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/external-dependency-analysis-analysis-using-owasp-dependency-check/) document.


## References
[^1]: [https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)
[^2]: [http://find-sec-bugs.github.io/](http://find-sec-bugs.github.io/)
[^3]: [https://www.owasp.org/index.php/OWASP_Dependency_Check](https://www.owasp.org/index.php/OWASP_Dependency_Check)

---
title: WSO2 Secure Coding Guidelines
category: secure-engineering
published: 22nd October 2018
version: 2.1
---
# WSO2 Secure Coding Guidelines
<p class="doc-info">Published: 22nd October 2018</p>
<p class="doc-info">Version: 2.1</p>
---

## 1. Introduction
This document summarizes the **Secure Coding Guidelines** that should be followed by WSO2 engineers while engineering WSO2 products, as well as applications used within the organization.

The purpose of this document is to increase the security awareness and make sure the products and the applications developed by WSO2 are inherently secure, by making sure security best practices are followed throughout the Software Development Life Cycle.


### 1.1 Organization of the Document


[OWASP Top 10 - 2017 Prevention](owasp-t10-2017-prevention.md) section of the document categorizes different attacks or security threats that engineers must focus on while engineering a product or an application. Prevention techniques are discussed in generic form, and there are sections that discuss programming language specific prevention techniques.

[OWASP Top 10 - 2013 Prevention](owasp-t10-2013-prevention.md) section of the document categorizes OWASP Top 10 2013 list of the most critical application security risks. But OWASP has updated its top 10 list in 2017. Please refer to OWASP Top 10 2017 for updated list.

[OWASP Mobile Top 10 Prevention](owasp-mobile-t10-prevention.md) section of the document categorizes different attacks or security threats that engineers must focus on while engineering mobile applications. Prevention techniques are discussed in generic form, and there are sections that discuss mobile platform specific prevention techniques.

[General Recommendations for Secure Coding](general-recommendations-for-secure-coding.md) section of the document discusses any security threats that are not captured within OWASP Top 10 and several generic recommendations that summarize prevention mechanisms which address multiple security threats. For example, the "Cryptographic Algorithms" section discusses general recommendations on selecting cryptographic algorithms, and sections such as "Security Related HTTP Headers" and "Securing Cookies", summarize prevention techniques used across preventing multiple attacks.

[Tooling Recommendations for Secure Coding](tooling-recommendations-for-secure-coding.md) section brings together all the documentations relevant to security related tooling used within WSO2, and recommendations relevant to usage of such tools in the engineering process.


### 1.2 Formatting of the Document

Formatting for **example incorrect usage**:

!!! bug error "Example Incorrect Usage"
    Code block goes here. Any highlight should use this formatting.{==Highlighting==}


Formatting for **example correct usage**:

!!! success check done "Example Correct Usage"
    Code block goes here. {==Any highlight should use this formatting.==}


Formatting for documenting items that require Platform Security Team's approval:

!!! danger error "Alert - Approval Required"
    If any component requires that, [example security control should be skipped], the use-case, as well as controls in place to provide required protection, must be reviewed and approved by Platform Security Team, before proceeding with the release of such component.


Formatting for documenting sample code blocks or sample code outputs used in explanations (not incorrect or correct usage samples, but general code or output used for explanations):

```
Code block or sample result of a program used in explanations.
```

Formatting for documenting example scenarios used in explanations:

!!! example
    User input is the API description. The user might have to add some special characters in the description. However, the application is not expecting any HTML syntax in the description.

    In the example scenario, output encoding will convert special characters to respective HTML character entity references.


Formatting for referencing to other documents owned by WSO2.

!!! tip hint important "WSO2 Document Reference"
    Further information on required changes and recommended configuration for WSO2 products as well as production deployments are available at "Example Document"[ref].


### 1.3 Revision History

| Version | Release Date | Contributors / Authors | Summary of Changes |
| ------- | ------------ | ---------------------- |------------------- |
| 1.0     | Jan 2016     | Kasun Balasuriya, [Dulanja Liyanage](https://wso2.com/about/team/dulanja-liyanage/),<br> [Prakhash Sivakumar](https://wso2.com/about/team/prakhash-sivakumar/), [Milinda Wickramasinghe](https://wso2.com/about/team/milinda-wickramasinghe/), <br> [Tharindu Edirisinghe](https://wso2.com/about/team/tharindu-edirisinghe/), [Malithi Edirisinghe](https://wso2.com/about/team/malithi-edirisinghe/),<br> [Rasika Perera](https://wso2.com/about/team/rasika-perera/), [Ayoma Wijethunga](https://wso2.com/about/team/ayoma-wijethunga/) | Initial version of Secure Coding Guidelines |
| 1.8     | May 28, 2017 | [Ayoma Wijethunga](https://wso2.com/about/team/ayoma-wijethunga/), [Tharindu Edirisinghe](https://wso2.com/about/team/tharindu-edirisinghe/ | Initial version of Secure Coding Guidelines - 2nd Edition |
| 1.8.1   | Nov 13, 2017 | [Ayoma Wijethunga](https://wso2.com/about/team/ayoma-wijethunga/) | Minor modification to XML External Entity (XXE) prevention sample. |
| 1.9     | Nov 16, 2017 | [Kasun Dharmadasa](https://wso2.com/about/team/kasun-dharmadasa/), [Ayoma Wijethunga](https://wso2.com/about/team/ayoma-wijethunga), [Charitha Goonetilleke](https://wso2.com/about/team/charitha-goonetilleke/) | Adding initial version of Secure Coding Guidelines for Mobile Applications |
| 2.0     | Sep 4, 2018  | [Mathuriga Thavarajah](https://wso2.com/about/team/mathuriga-thavarajah/), [Ayoma Wijethunga](https://wso2.com/about/team/ayoma-wijethunga) | Updating OWASP Top 10 list to OWASP Top 10 Application Security Risks - 2017 list |
| 2.1     | Oct 22, 2018 | [Kasun Dharmadasa](https://wso2.com/about/team/kasun-dharmadasa/)  | Adding the Zip Slip Vulnerability prevention |

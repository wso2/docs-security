---
title: Secure Coding Guidelines
category: security-guidelines
published: October 22, 2018
updated: August 09, 2022
version: 2.2
---

# Secure Coding Guidelines

<p class="doc-info">Published: October 22, 2018</p>
<p class="doc-info">Updated: August 09, 2022</p>
<p class="doc-info">Version: 2.2</p>
---

## Revision History

| Version | Release Date | Contributors / Authors | Summary of Changes |
| ------- | ------------ | ---------------------- |------------------- |
| 2.2     | Aug 09, 2022 | [Chathura Ranathunga](https://wso2.com/about/team/chathura-ranathunga/) | Changing the formatting and the structure of the document | 
| 2.1     | Oct 22, 2018 | [Kasun Dharmadasa](https://wso2.com/about/team/kasun-dharmadasa/)  | Adding the Zip Slip Vulnerability prevention |
| 2.0     | Sep 4, 2018  | [Mathuriga Thavarajah](https://wso2.com/about/team/mathuriga-thavarajah/), [Ayoma Wijethunga](https://wso2.com/about/team/ayoma-wijethunga) | Updating OWASP Top 10 list to OWASP Top 10 Application Security Risks - 2017 list |
| 1.9     | Nov 16, 2017 | [Kasun Dharmadasa](https://wso2.com/about/team/kasun-dharmadasa/), [Ayoma Wijethunga](https://wso2.com/about/team/ayoma-wijethunga), [Charitha Goonetilleke](https://wso2.com/about/team/charitha-goonetilleke/) | Adding initial version of Secure Coding Guidelines for Mobile Applications |
| 1.8.1   | Nov 13, 2017 | [Ayoma Wijethunga](https://wso2.com/about/team/ayoma-wijethunga/) | Minor modification to XML External Entity (XXE) prevention sample. |
| 1.8     | May 28, 2017 | [Ayoma Wijethunga](https://wso2.com/about/team/ayoma-wijethunga/), [Tharindu Edirisinghe](https://wso2.com/about/team/tharindu-edirisinghe/) | Initial version of Secure Coding Guidelines - 2nd Edition |
| 1.0     | Jan 2016     | Kasun Balasuriya, [Dulanja Liyanage](https://wso2.com/about/team/dulanja-liyanage/),<br> [Prakhash Sivakumar](https://wso2.com/about/team/prakhash-sivakumar/), [Milinda Wickramasinghe](https://wso2.com/about/team/milinda-wickramasinghe/), <br> [Tharindu Edirisinghe](https://wso2.com/about/team/tharindu-edirisinghe/), [Malithi Edirisinghe](https://wso2.com/about/team/malithi-edirisinghe/),<br> [Rasika Perera](https://wso2.com/about/team/rasika-perera/), [Ayoma Wijethunga](https://wso2.com/about/team/ayoma-wijethunga/) | Initial version of Secure Coding Guidelines |


## Introduction
This document summarizes the **Secure Coding Guidelines** that should be followed by WSO2 engineers while engineering WSO2 products, as well as applications used within the organization.

The purpose of this document is to increase the security awareness and make sure the products and the applications developed by WSO2 are inherently secure, by making sure security best practices are followed throughout the Software Development Life Cycle.


## Organization of the Document

[General Recommendations for Secure Coding](general-recommendations-for-secure-coding.md) section of the document discusses different attacks or security threats that engineers must focus on while engineering a product or an application. Prevention techniques are discussed in generic form, and there are sections that discuss programming language specific prevention techniques.

[OWASP Top 10 - 2017 Prevention](owasp-t10-2017-prevention.md) section of the document categorizes OWASP Top 10 2017 list of the most critical application security risks.

[OWASP Top 10 - 2013 Prevention](owasp-t10-2013-prevention.md) section of the document categorizes OWASP Top 10 2013 list of the most critical application security risks.

[OWASP Mobile Top 10 Prevention](owasp-mobile-t10-prevention.md) section of the document categorizes different attacks or security threats that engineers must focus on while engineering mobile applications. Prevention techniques are discussed in generic form, and there are sections that discuss mobile platform specific prevention techniques.

[Tooling Recommendations for Secure Coding](tooling-recommendations-for-secure-coding.md) section brings together all the documentations relevant to security related tooling used within WSO2, and recommendations relevant to usage of such tools in the engineering process.

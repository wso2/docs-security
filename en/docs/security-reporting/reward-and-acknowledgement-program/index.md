---
title: Reward and Acknowledgement Program
category: security-reporting
published: 14th Sep 2021
version: 2.1
---

# Reward and Acknowledgement Program

We have been recognizing the efforts of the security research community for helping us make WSO2 products safer. To honor all such external contributions, we maintain a reward and acknowledgement program for WSO2-owned software products. This document describes the various aspects of this program:


* [Products & Services in Scope](#products-services-in-scope)
* [Qualifying Vulnerabilities](#qualifying-vulnerabilities)
* [Non-qualifying Vulnerabilities](#non-qualifying-vulnerabilities)
* [Rewards and Acknowledgement](#rewards-and-acknowledgement)
* [Exceptions & Rules](#exceptions-rules)
* [Investigating and Reporting Bugs](#investigating-and-reporting-bugs)

### Products & Services in Scope
At this time, the scope of this program is limited to security vulnerabilities found on Choreo, Asgardeo and the software products developed by WSO2.

This includes the following:

* [WSO2 API Manager](https://wso2.com/api-management/)
* [WSO2 Identity Server](https://wso2.com/identity-and-access-management)
* [WSO2 Enterprise Integrator](https://wso2.com/integration)
* [Ballerina](https://ballerina.io/) (limited to the scope mentioned in [https://ballerina.io/security-policy/](https://ballerina.io/security-policy/))
* [Choreo](https://wso2.com/choreo/)
* [Asgardeo](https://wso2.com/asgardeo/)

Out of the above-listed products, only the [latest released version](http://wso2.com/products/carbon/release-matrix/) of each product is included in the scope of this program. In addition to that, the release date of the product version should be within 3 years from the date of the report.

!!! info
    Any other live deployment of a WSO2 product, or a website (e.g. wso2.com) would not be included in the scope of this program.


### Qualifying Vulnerabilities
Any security issue that has a moderate or higher security impact on the confidentiality, integrity, or availability of Choreo, Asgardeo, or a WSO2 product would be included in the scope of the program. 

Following are a few common issues that we typically consider for rewarding.

* SQL or LDAP Injection
* Cross-site Scripting (XSS)
* Broken authentication and authorization
* Broken session management
* Remote code execution
* OS command execution
* XML External Entity (XXE) or XML Entity Expansion
* Path traversal
* Insecure Direct Object References
* Confidential information leakages (such as credentials, PII)

!!! info
    Kindly note that the impact calculation is solely at the discretion of WSO2.


### Non-qualifying Vulnerabilities
We review reported security issues case-by-case. Generally, we do not consider the following common issues for rewarding.

* Denial of Service (DoS) or Distributed Denial of Service (DDoS) vulnerabilities
* Logout Cross-site Request Forgery (CSRF)
* Missing CSRF token in login forms
* Cross domain referer leakage
* Missing HttpOnly flags
* SSL/TLS related issues
* Missing HTTP security headers
* Account enumeration
* Brute-force Attacks
* Non-critical Information Leakages (such as server information, stack trace)

!!! info
    However, based on the security impact, we would still consider rewarding the issues from the above categories.


### Rewards and Acknowledgement
To show our appreciation, we provide a reward and an acknowledgement to eligible reporters after the reported issues are fixed and announced to the WSO2 customers and the community users.

!!! tip
    See our [Vulnerability Management Process](../../security-processes/vulnerability-management-process.md) for more details about how we disclose security vulnerabilities.

Based on the consent of the reporter, we will do the following:

1. Include the reporter's name on the [Security Hall of Fame](hall-of-fame.md) web page.
2. Email a certificate of appreciation to the reporter.
3. Provide one of the following preferred by the reporter: 
    1. Amazon gift voucher worth 50 USD (from: Amazon.com / Amazon.ca / Amazon.cn / Amazon.fr / Amazon.de / Amazon.in / Amazon.it / Amazon.co.jp / Amazon.co.uk / Amazon.es / Amazon.com.au)
    2. PayPal transfer worth 50 USD.


### Exceptions & Rules
The following exceptions and rules apply in this program:

* You will qualify for a reward only if you are the first person to responsibly disclose an unknown issue. 
* WSO2  has 7 days to provide the first response to the report. It could take up to 90 days to implement a fix based on the severity of the report, and further time might be needed to announce the fix to our customers and community users of all the affected product versions. WSO2 will keep the reporter up to date with the progress of the process. 
* Posting details or conversations about the report that violates responsible disclosure, or posting details that reflect negatively on the program and the WSO2 brand, will disqualify you from consideration for rewards and credits. 
* All security testing must be carried out in a standalone WSO2 product running locally or a hosted deployment owned by the reporter. 
* All communications must be conducted through security mailing lists only.
* Offering a reward or giving credits has to be entirely at WSO2’s discretion.


### Investigating and Reporting Bugs
If you have found a vulnerability, please contact us via channels mentioned in [WSO2 Security Vulnerability Reporting Guidelines](../vulnerability-reporting-guidelines.md).

A good bug report should include the following information at a minimum:

- [x] Vulnerable WSO2 product(s) and their version(s)
- [x] List of URL(s) and affected parameter(s)
- [x] Describe the browser, OS, and/or app version
- [x] Describe the self-assessed impact
- [x] Describe the steps to exploit the vulnerability
- [x] Any proposed solution

We thank you for helping us keep WSO2 products and services safe!

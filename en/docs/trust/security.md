# WSO2 Security Policy

This policy outlines the processes, best practices, and user responsibilities related to secure software development, vulnerability management, and the secure use of WSO2 products.

## Scope

WSO2 provides security fixes until the product reaches its End of Life (EOL).

For detailed information, please refer to the [WSO2 Support Matrix](https://wso2.com/products/support-matrix/) and [WSO2 Product Support Lifecycle](https://wso2.com/products/support-matrix/#:~:text=WSO2%20Product%20Support%20Lifecycle).


## Reporting Security Vulnerabilities

Please **do not submit security vulnerabilities through GitHub Issues or Discussions**.

**To responsibly disclose a vulnerability, please use our [official security reporting channels](https://security.docs.wso2.com/en/latest/security-reporting/)** in accordance with our [Reward and Acknowledgement Program](https://security.docs.wso2.com/en/latest/security-reporting/reward-and-acknowledgement-program/). All vulnerability disclosures must follow [Vulnerability Reporting Guidelines](https://security.docs.wso2.com/en/latest/security-reporting/vulnerability-reporting-guidelines/). The WSO2 team will contact you within 24 hours of submitting a vulnerability report.

## Secure Product Usage

To ensure a secure and compliant deployment, users are strongly advised to:
- Follow the [Security Guidelines for Production Deployment](https://security.docs.wso2.com/en/latest/security-guidelines/security-guidelines-for-production-deployment/) as well as other recommended best practices for the product features and specifications you are using.

- Stay current with supported product versions. Please refer to the [WSO2 Support Matrix](https://wso2.com/products/support-matrix/) for the list of supported products.

- Monitor [Security Announcements](https://security.docs.wso2.com/en/latest/security-announcements/) and take appropriate action to safeguard your product deployment.

## Secure Software Development Lifecycle (SSDLC)

WSO2 products are developed following WSO2’s [Secure Software Development Process](https://security.docs.wso2.com/en/latest/security-processes/secure-software-development-process/), which includes:

- All code changes are version-controlled, reviewed, and merged by authorized WSO2 engineers.

- WSO2 engineers follow the [Secure Engineering Guidelines](https://security.docs.wso2.com/en/latest/security-guidelines/secure-engineering-guidelines/).

- Product releases undergo [mandatory security checks](https://security.docs.wso2.com/en/latest/security-processes/secure-software-development-process/#mandatory-checks-during-releases), including [Static Application Security Testing (SAST)](https://security.docs.wso2.com/en/latest/security-processes/secure-software-development-process/#static-code-analysis), [Dynamic Application Security Testing (DAST)](https://security.docs.wso2.com/en/latest/security-processes/secure-software-development-process/#dynamic-analysis), and [Software Composition Analysis (SCA)](https://security.docs.wso2.com/en/latest/security-processes/secure-software-development-process/#third-party-dependency-analysis). The product teams ensure that products are released without any true positive vulnerabilities.

- SCA tools are integrated into product code bases and continuously scan for dependencies (third-party) related vulnerabilities, while SAST and DAST scans are periodically re-run for supported products. 

## Vulnerability Management Process

Any reported vulnerabilities related to WSO2 products will be managed in accordance with  our [Vulnerability Management Process](https://security.docs.wso2.com/en/latest/security-processes/vulnerability-management-process/), and confirmed vulnerabilities will be addressed based on their severity and impact.


### Coordinated Vulnerability Disclosure Notifications

  - For [EULA](https://wso2.com/licenses/eula/) subscribers and coordinated vulnerability disclosure (CVD) partners:
    - "Security Announcements" will be communicated in advance through official support channels before the public listing of [Security Advisories](https://security.docs.wso2.com/en/latest/security-announcements/security-advisories/). Subscribers should actively monitor these announcements and quickly apply the recommended fixes using the [WSO2 Updates tool](https://wso2.com/updates/). 

  - For community (open-source) users: 
    - A public announcement will be posted on our [Security Advisories](https://security.docs.wso2.com/en/latest/security-announcements/security-advisories/) page, and community users can follow the recommended remedial actions listed in the “Solutions” section of each advisory.

  - In the event of a zero-day vulnerability, WSO2 will first evaluate its relevance and potential impact on WSO2 products. We will then send a "Special Customer Security Announcement" to EULA subscribers, as well as coordinated vulnerability disclosure (CVD) partners, and publish a public disclosure on the [Incident Clarification](https://security.docs.wso2.com/en/latest/security-announcements/incident-clarifications/) section of our [Security Announcements](https://security.docs.wso2.com/en/latest/security-announcements/) page. We will continue providing updates until the vulnerability is resolved.
# WSO2's Security Commitment for Self-Hosted Products

WSO2 is committed to ensuring that industry best practices regarding security standards and mechanisms are rigorously applied to our processes. Below are WSO2's security commitments to its self-hosted products, covering the type of data we collate and how such data is used, such as the security of product development, design, coding testing, etc.

## Data processed by WSO2

* WSO2 only collects limited personally identifiable information (PII), such as full name, email address, phone number(s), and billing information, to provide support services and for billing purposes, per the [WSO2 Privacy Policy](https://wso2.com/privacy-policy).
* During the engagement with the customer, the WSO2 team would encounter limited information regarding the customer's requirements and environments to assist in the implementation and support-related matters through the official WSO2 support system and the official SFTP server. This information would be kept confidential.
* While providing enterprise support services, WSO2 may request logs, dumps, and configurations related to WSO2 products. However, WSO2 recommends sanitizing these artifacts before sharing.
* WSO2 does not require access to the customer's environment to provide support services.
* WSO2 updates service collects information regarding the product, product version, last applied update level, applied date, and customer email to validate subscriptions and send customer updates and notifications.

## Secure Software Development Process

WSO2 has a well-defined [Secure Software Development Process](https://security.docs.wso2.com/en/latest/security-processes/secure-software-development-process/), which details how we incorporate security aspects into our product development process.

## Security of Product Design

Security by design approach is followed within WSO2 for each new development initiative. It is conducted to identify the relevant security endpoints and trust boundaries to minimize the product vulnerabilities and reduce the attack surface through the product designing phase.

## Secure coding and reviews

* WSO2 engineers adhere to the [WSO2 Secure Engineering Guideline](https://security.docs.wso2.com/en/latest/security-guidelines/secure-engineering-guidelines/) when doing engineering tasks. This guideline provides technical guidance on addressing OWASP's Top 10 application security risks and additional security guidelines related to [WSO2 Secure Development processes](https://security.docs.wso2.com/en/latest/security-processes/secure-software-development-process/).
* WSO2 uses GitHub as our source code repository system. Source codes of products are available to the public in our [GitHub organization](https://github.com/wso2) for anyone to review and report security issues.
* Mandatory [peer code reviews](https://security.docs.wso2.com/en/latest/security-processes/secure-software-development-process/#code-reviews) are performed before any change is added to the code base to identify security deficiencies.
* When a 3rd party dependency is introduced to the WSO2 product, WSO2 engineers and the Security and Compliance team will assess the security of such dependencies. Approved dependencies are added and reviewed as part of [Third Party Dependency Analysis](https://security.docs.wso2.com/en/latest/security-processes/secure-software-development-process/#third-party-dependency-analysis).

## Security testing

* WSO2 conduct [mandatory product security assessments](https://security.docs.wso2.com/en/latest/security-processes/secure-software-development-process/#mandatory-checks-during-releases) during product release cycles under three categories. [Static Code Analysis](https://security.docs.wso2.com/en/latest/security-processes/secure-software-development-process/#static-code-analysis), [Software Composition Analysis](https://security.docs.wso2.com/en/latest/security-processes/secure-software-development-process/#third-party-dependency-analysis), and [Dynamic Analysis](https://security.docs.wso2.com/en/latest/security-processes/secure-software-development-process/#dynamic-analysis).
  * For Static Application Security Testing (SAST), we utilize the Find Security Bugs plugin, the Spotbugs plugin, Super-Linter, GoSec, and Veracode Static Analysis which provide OWASP Top 10 and SANS CWE Top 25 coverage.
  * For Dynamic Application Security Testing (DAST), we utilize Invicti (formerly Netsparker), BurpSuite Pro, and Qualys Web Application Scanner (WAS).
  * For Software Composition Analysis (SCA) or third-party dependency analysis, we utilize OWASP Dependency Check, OWASP Dependency Track, FOSSA, JFrog Xray, and Trivy (specifically for container images). Tools such as FOSSA are directly integrated with our source code repositories to provide near real-time visibility into third-party dependency vulnerabilities.
  * Product teams ensure products are released without any true positive vulnerabilities.
* To ensure that our supported products are secure, we continuously scan third-party dependencies and periodically conduct static and dynamic scans on updated product packs of our supported products.
* Vulnerabilities that are discovered will be assessed for their impact. If any true-positive vulnerabilities are identified, immediate actions will be taken, such as implementing fixes and patches according to their severity, in line with our [Vulnerability Management Process](https://security.docs.wso2.com/en/latest/security-processes/vulnerability-management-process/).

## Product vulnerability and patch management

* WSO2 products are supported for three years upon a major release. WSO2 provides updates and patches for bugs and security issues during this period. Please refer to the [support matrix](https://wso2.com/products/support-matrix/) for detailed information on supported products.
* Any vulnerability reported against WSO2 products would undergo the [ Vulnerability Management Process](https://security.docs.wso2.com/en/latest/security-processes/vulnerability-management-process/). Reported vulnerabilities will be assessed according to the CVSS scheme and fixed according to the given resolution timeframes.
* WSO2 has established a [Security Reward and Acknowledgement Program](https://security.docs.wso2.com/en/latest/security-reporting/reward-and-acknowledgement-program/) where security researchers can analyze the security state of WSO2 products and report any identified security issues or vulnerabilities in alignment with [Vulnerability Reporting Guidelines](https://security.docs.wso2.com/en/latest/security-reporting/vulnerability-reporting-guidelines/).
* WSO2 will first release patches to its customers via the U2 ([Update tool](https://wso2.com/updates/)). After one month, once customers have received these patches and updates, WSO2 will publish a security advisory on the [Security Advisory](https://security.docs.wso2.com/en/latest/security-announcements/security-advisories/) page.  This allows community users to patch their products by following the guidance provided in the Solution section of the Security Advisory.
* In some cases, certain reported vulnerabilities may not apply to WSO2 products, and WSO2 might choose not to patch them. Those vulnerabilities will be detailed on the [CVE Justifications](https://security.docs.wso2.com/en/latest/security-announcements/cve-justifications/) page.

## WSO2 infrastructure security

* WSO2's internal infrastructure and endpoints are managed in alignment with ISO/IEC 27001.
* All user endpoints and production servers are secured with an EPP/EDR solution to provide real-time protection against malware and exploitation and are monitored regularly.
* All user endpoints and production servers are utilizing data-at-rest encryption with AES-256 or higher, and data-in-transit encryption with TLS 1.2 or higher.
* All user endpoints and production servers are to install software that is approved and authorized.
* A central MDM solution manages all user endpoints and servers. A regular patch management process is in place.
* Conduct independent third-party audits annually, which are separated from annual ISO audits.
* Regular Internal and External VAPTs are conducted on WSO2 systems and network devices.
* All infrastructure-related incident responses are handled in alignment with ISO standards.

## Security guidelines for production deployment of WSO2 products

* WSO2 has published [secure guidelines for production deployment](https://security.docs.wso2.com/en/latest/security-guidelines/security-guidelines-for-production-deployment/). 
* This guideline recommends configurations to secure all layers of the production environment (OS, Network, and Application)
* Customers should follow these guidelines to ensure security when setting up products for production use. 
* Any product-related queries can be raised at the WSO2 support channels.

## Security commitment of WSO2

* Adhere to the [WSO2 Secure Engineering Guideline](https://security.docs.wso2.com/en/latest/security-guidelines/secure-engineering-guidelines/) and [WSO2 Secure Development processes](https://security.docs.wso2.com/en/latest/security-processes/secure-software-development-process/) when engineering WSO2 products.
* Ensure [mandatory product security assessments](https://security.docs.wso2.com/en/latest/security-processes/secure-software-development-process/#mandatory-checks-during-releases) are conducted and that periodic security scans are performed on supported products to maintain security throughout the product lifecycle.
* Ensure that product vulnerabilities are patched in compliance with the [Vulnerability Management Process](https://security.docs.wso2.com/en/latest/security-processes/vulnerability-management-process/).
* Upon request, provide customers with scan reports of static scanning, dynamic scanning, and software composition analysis reports to assist with customer compliance programs.
* In the event of a security incident, privacy incident, or data breach involving a customer(s), notify the customer(s) immediately within 48 hours of declaring the incident.
* WSO2 would work proactively with customers to remediate security incidents and provide detailed information/reporting regarding security incidents impacting customers.

## WSO2's responsibilities

* WSO2 shall make "Customer Security Announcements" regarding product vulnerabilities and remediations via its support system with clear instructions on how to apply the same.
* WSO2 will share the following reports subject to appropriate confidentiality undertakings with customers upon request.
  * Annual Independent party (External) VAPT and/or audit reports of WSO2 Infrastructure.
  * ISO/IEC 27001 Certificate and audit Reports
  * Security scan reports for WSO2 product(s).
  * Provide customers with detailed root cause analysis and incident reports.

## Customer's Responsibilities

* The customer must adhere to the [security guidelines for production deployment](https://security.docs.wso2.com/en/latest/security-guidelines/security-guidelines-for-production-deployment/) when setting up the environment to ensure that products are set up securely.
* The customer must proactively monitor Customer Security Announcements made by WSO2 and apply relevant remediation after conducting testing on lower environments within 30 calendar days after the Customer Security Announcements.
  * It is recommended to prevent the exploitation of unpatched deployments after public disclosure. Public Announcements will be made after a minimum buffer of 30 calendar days from the Security Announcement, enabling customers to protect their deployments before public disclosure of the issue.
* The customer must adhere to the [WSO2 Support Matrix](https://wso2.com/products/support-matrix/) and work toward upgrading/migrating to supported versions.
* If a customer is using WSO2 docker images, the customer must ensure that the customer is using the latest docker image from [WSO2 Private Docker Registry](https://docker.wso2.com/).
* The customer should inform WSO2 about any vulnerabilities or security issues identified within WSO2 products.
* The customer must ensure that sensitive data has been appropriately sanitized before sharing data, logs, configurations, and dumps with WSO2 support teams.
* If a user with access to the WSO2 support portal no longer requires such access, inform WSO2 regarding the same immediately and get access revoked.
* The customer must proactively nominate users who should have access to the WSO2 support portal and Customer Security Announcements.
* The customer must denote the security point of contact(s) so that "Customer Security Announcements" would reach them promptly. WSO2 recommends having these notifications sent out to the customer's security team or security leadership, who would proactively work towards mitigating the risks.

## Exclusions

WSO2 shall not be responsible for any security/breaches in respect of the following:
* If the customer gets compromised due to not monitoring the [Customer Security Announcements](https://security.docs.wso2.com/en/latest/security-processes/vulnerability-management-process/#announcing-to-the-customers) proactively, remediation actions must be taken to safeguard deployment following such announcements.
* If the customer gets compromised due to not adhering to the [security guidelines for production deployment](https://security.docs.wso2.com/en/latest/security-guidelines/security-guidelines-for-production-deployment/).
* The customer gets compromised due to not migrating to supported product versions listed under the [WSO2 Support Matrix](https://wso2.com/products/support-matrix/).
* Customizations or extensions developed or integrated into WSO2 products by the customer.

## Revision History

| Release Date | Version | Summary of the Changes |
|-------------|---------|------------------------|
| 2022-04-29 | 1.0.0 | Initial version |
| 2023-03-21 | 2.0.0 | Fixed broken links and amended process updates |
| 2024-12-26 | 3.0.0 | Fixed broken links and amended process updates |
| 2025-07-30 | 4.0.0 | Convert to markdown format and published |

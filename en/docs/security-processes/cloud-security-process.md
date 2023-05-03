---
title: Cloud Security Process
category: security-processes
published: 5th May 2023
version: 1.0
---

# Cloud Security Process

## Overview
We have incorporated DevSecOps methodologies into our Secure Software Development Lifecycle, employing cloud-native security best practices. This approach has fostered a collective responsibility for security throughout our teams.

This document is organized into sections that outline the secure design patterns and security measures we have put in place to safeguard against major threats. These threats include internal attacks, software supply chain attacks, employee account takeovers, service attacks, platform attacks, and more.

We have closely aligned our process with "*The Six Pillars of DevSecOps: Pragmatic Implementation*" by Cloud Security Alliance[^1].


## Secure Software Development Lifecycle  
The Secure Software Development Lifecycle (SSDLC) is an approach that embeds security within every stage of the software development process, from inception to deployment and maintenance. In this methodology, security is not treated as an afterthought but as a fundamental aspect throughout the entire SDLC.

We recognize the importance of adopting secure development practices to reduce the risk of vulnerabilities and cyberattacks. To accomplish this, we integrate security as a crucial component in each phase of our SDLC. This ensures that security considerations are incorporated into the design, development, testing, deployment, and maintenance stages of their software development process.

By integrating security into each stage of our SDLC, we strive to guarantee that software products and solutions are designed with security as a priority from the beginning. This approach helps minimize the chances of vulnerabilities and other security issues that may be identified later in the development process or after deployment. The ultimate outcome is a more secure software product capable of mitigating potential security risks and defending against cyber threats.


## Design and Architecture
The Secure Design and Architecture phase is the most crucial step in implementing security, as it takes place before any code is written. Detecting design flaws and potential risks at this stage can minimize vulnerabilities and save a considerable amount of effort. The risks identified during this phase encompass insecure data flows, susceptibilities in the selected framework and programming language, prevalent risks, unsound design choices, and defective business logic.


### Threat Modeling 
Threat modeling is used to identify threats and mitigation strategies that should be associated with cloud deployments, components, or features and shared with our customers. By adopting continuous threat modeling, engineers can design securely, become security aware, and address security concerns early in development, thus minimizing the need for security patches. When engineers seek to implement changes that may impact our security posture or products, the Security Team utilizes threat modeling as a valuable resource to validate security. The team encourages change and enhancement, while ensuring that these are carried out securely.


## Coding

### Secure Code Engineering Guidelines
Neglecting security during the coding process may lead to undetected vulnerabilities being deployed in production environments, potentially resulting in costly remediation efforts further along the SDLC. WSO2 engineers adhere to [Secure Coding Guidelines](../security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/introduction.md) to ensure that security best practices are implemented throughout the Software Development Life Cycle. This involves implementing security controls in the code, utilizing automation tools to reliably detect code weaknesses and vulnerabilities. 


### Container Hardening
Containerization enables rapid and consistent development, streamlining dependency management, which is vital for supporting DevSecOps workflows. Nevertheless, container security necessitates a distinct approach compared to virtual machines, and container orchestration adds another layer of complexity that demands proper management and security measures. WSO2 follows container hardening best practices and uses enforcements at the build pipelines to ensure only hardened containers are provisioned. Essential security principles enforced by WSO2 includes, least privilege principle, defense in depth, minimizing the attack surface, restricting the blast radius, and segregating duties.


### Software Composition Analysis 
Incorporating third-party components in application development can expedite the process; however, it also introduces risks such as security vulnerabilities, licensing requirements, and code quality concerns. Software Composition Analysis (SCA) tools assist in detecting and addressing these risks by offering visibility and implementing policies. WSO2 uses FOSSA, a commercial third-party dependency scanning tool, to actively scan cloud components and products to identify known vulnerabilities in third-party dependencies.


### Static Application Security Testing
Static Application Security Testing (SAST) is a software-driven method employed to identify security vulnerabilities within the source code during the coding stage of the software development lifecycle (SDLC). SAST, also referred to as open box security testing, delivers real-time feedback to developers, enabling them to detect and rectify potential security issues before progressing to the subsequent phase of the SDLC. Techniques such as Taint Analysis and Data Flow Analysis are utilized in Static Code Analysis to uncover potential vulnerabilities in the source code. WSO2, for example, employs the Veracode commercial static analyzer, along with multiple other recognized open source static scanners during the development phase.


## Integration and Test 

### Dynamic Application Security Test
Dynamic Application Security Testing (DAST) is a closed box testing methodology employed to detect security vulnerabilities by emulating external attacks on an application's external interfaces. DAST tools can examine an application without access to its source code, internal structure, or design. This method is commonly used for testing web applications and services, as well as API scanning, penetration testing, and fuzz testing. Dynamic Analysis is conducted while the application is running, facilitating the discovery of software vulnerabilities. WSO2 utilizes various DAST tools, including Netsparker, and Burp Suite, for dynamic security scanning.


### Container Testing
Testing the security of containers and container orchestrators within an environment that closely resembles production settings is extremely important. Configuration aspects related to container orchestrators and containers can be easily overlooked. Therefore, it is crucial to devise a series of tests to help validate the specific configurations of containers and container orchestrators. Particularly, for container testing, we develop test cases that enable the examination of container hosts and container orchestrator configurations for possible security misconfigurations. This is performed based on pipeline security measures and measures taken under [Runtime Defense and Monitoring](#runtime-defense-and-monitoring).


### Penetration Testing
WSO2 maintains an internal security team dedicated to ensuring the security of cloud components and products. This team carries out penetration tests and vulnerability assessments, and the resulting findings are promptly addressed by the respective product teams for implementing preventive measures. 

WSO2 Private Cloud customers may conduct their own penetration tests and get WSO2 team's assistance in addressing any identifications or concerns. WSO2 allows penetration testing on its cloud services under specific conditions, and interested parties must submit a request for approval outlining the testing scope, tools, source IP addresses, and other pertinent information. If granted approval, the testing must be performed in compliance with WSO2's provided terms, and any discovered issues must be reported to WSO2 within 24 hours. Testers are required to adhere to the terms and conditions of their agreement with WSO2 and must not inflict any damage or introduce risks during testing.


## Delivery and Deployment

### GitOps
GitOps is a modern approach to infrastructure automation that incorporates version control, collaboration, compliance, and CI/CD tooling principles into infrastructure management. By utilizing configuration files stored as code, infrastructure teams can automatically and consistently provision infrastructure with each deployment. GitOps is employed for managing both infrastructure and application code deployments, with the git repository serving as the source of truth for the deployment state. WSO2 leverages GitOps to manage its infrastructure and application deployments, allowing the company to manage cloud resources in a more effective and efficient manner.


### Guardrails
Guardrails are a collection of rules that provide continuous governance when constructing cloud environments. These integrated tools assist in resource governance, compliance monitoring, and ensure alignment with organizational goals. Guardrails can be implemented as preventive or detective controls, with high-level policies and rules in place. WSO2 utilizes Azure Policies, which can be automated within the software development process and utilized for compliance reporting or enforced/auto-remediation controls. Guardrails establish a consistent baseline for monitoring deployments.


### Environment Separation
Within the scope of this document, an environment refers to a collection of diverse technological components designed to serve a specific function. WSO2 has established environments that may encompass various network segments, as well as existing development environments employed throughout the development process, including development, staging, and production environments.


### Secrets & Key Management
In cloud environments, secrets and keys are typically stored within a secret manager. WSO2 makes use of a secret manager to safely store generic secrets such as passwords, keys, certificates, and databases. This entails managing digital authentication credentials and cryptographic key materials, including passwords, encryption keys, APIs, tokens, and other sensitive credentials necessary for authentication and cryptographic functions.


### Securing the CI/ CD Pipeline
WSO2 incorporates security scans at various stages of its CI/CD pipeline to protect its cloud solutions from security threats and vulnerabilities. This is achieved by employing [Static Application Security Testing (SAST)](#static-application-security-testing), adhering to coding best practices, and conducting [Software Composition Analysis (SCA)](#software-composition-analysis). Depending on the shared responsibility model, WSO2 consistently upgrades Kubernetes clusters with the most recent patches and updates. Furthermore, [WSO2 scans all images for vulnerabilities](#vulnerability-management) at the OS, application, and third-party dependency levels prior to deployment.


### System Hardening
WSO2 employs system hardening to improve security by minimizing a system's attack surface. This is accomplished by safeguarding data, ports, components, functions, and permissions to decrease potential vulnerabilities. System hardening lowers the risk of known vulnerabilities; however, it is crucial to maintain the system's functionality after the hardening process.


## Runtime Defense and Monitoring

### Cloud Security Posture Management
WSO2 uses Azure Defender for Cloud to manage the security posture of its cloud environments. Azure Defender for Cloud is a cloud security posture management tool that continuously monitors cloud resources for potential threats and vulnerabilities. By leveraging this tool, WSO2 is able to track security and identity scores, identify and address risks, and maintain a strong security posture to protect cloud resources from cyber attacks.


### Monitoring and Observability
WSO2 carries out monitoring, a process that involves gathering and analyzing data to track applications and infrastructure, as well as detecting and responding to suspicious activities and cyber incidents. Monitoring offers feedback to efficiently identify and resolve issues. Observability, conversely, enables the determination of system health through the analysis of its inputs and outputs. In its monitoring process, WSO2 Security Operations Center (SOC) examines not only applications, microservices, containers, and security event log analysis but also hardware resources and network transport.


## Incident Management
Organizations need dependable strategies for handling security breaches or cyberattacks, as preventive measures are not infallible. Incident response refers to a systematic method of minimizing harm and decreasing both recovery time and expenses. WSO2 utilizes a cloud-based incident management process that adheres to established protocols, maintains communication with stakeholders, and designates specific teams for managing incidents and establishing communication procedures.


## Risk Management 
At WSO2, risk management is meticulously executed throughout the entire SDLC, encompassing risks identified during threat modeling and other various stages of the development process. Beginning with the design phase, potential risks are systematically evaluated and addressed to ensure the security and integrity of the application, component, platform, and dependent resources. As the development progresses, risks are continually assessed and updated, with a strong emphasis on maintaining a security-aware mindset among engineers. By integrating risk management within each stage of the SDLC, WSO2 demonstrates its commitment to delivering secure software products and solutions, while actively mitigating potential vulnerabilities and cyber threats.


## Vulnerability Management 
To tackle the difficulties arising from the swift evolution of DevSecOps and the increasing risk of cyberattacks, it is crucial for organizations to implement a process for addressing vulnerabilities. This process involves detecting vulnerabilities, assessing their severity, resolving them using patches or other methods, and evaluating the efficacy of these actions. WSO2 has established a methodology, and automations for conducting periodic technical vulnerability assessments of its cloud infrastructure, as well as maintaining baseline security standards for various platforms to guarantee the preservation of adequate security levels.


## References
[^1]: [https://cloudsecurityalliance.org/artifacts/six-pillars-devsecops-pragmatic-implementation/](https://cloudsecurityalliance.org/artifacts/six-pillars-devsecops-pragmatic-implementation/)

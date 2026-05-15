---
title: Cloud Security Process
category: security-processes
version: 2.0
---

# Cloud Security Process

<p class="doc-info">Version: 2.0</p>
___

WSO2 cloud services follow a DevSecOps process aligned with [The Six Pillars of DevSecOps: Pragmatic Implementation](https://cloudsecurityalliance.org/artifacts/six-pillars-devsecops-pragmatic-implementation/) from the Cloud Security Alliance. This page is the WSO2-specific operational detail: the tools we use, the practices we enforce, and the points where engineers and the security team interact at each lifecycle stage. For the general framing of DevSecOps and each stage's intent, follow the CSA link.

## Design and Architecture

* **Threat modeling** is continuous. Engineers update the model when they make changes that may affect security posture; the Security Team uses the model to validate the change.
* Findings from threat modeling that are relevant to customers — risks in cloud deployments, components, or features — are shared with customers.

## Coding

* **Secure coding guidelines.** Engineers follow the [WSO2 Secure Coding Guidelines]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/introduction/). Security controls are implemented in code; automation detects weaknesses and vulnerabilities.
* **Container hardening.** Build pipelines enforce hardened containers — only hardened images are provisioned. Principles enforced: least privilege, defence in depth, minimised attack surface, restricted blast radius, separation of duties.
* **Software Composition Analysis (SCA).** WSO2 uses **FOSSA** to scan cloud components and products for known vulnerabilities in third-party dependencies.
* **Static Application Security Testing (SAST).** WSO2 uses **Veracode** plus several open-source static analysers during development.

## Integration and Test

* **Dynamic Application Security Testing (DAST).** WSO2 uses **Netsparker** (now Invicti) and **Burp Suite** for dynamic scanning of web applications, services, and APIs.
* **Container testing.** A dedicated test suite exercises container host and orchestrator configuration for misconfigurations. Coupled with the pipeline security measures and the [Runtime Defence and Monitoring](#runtime-defence-and-monitoring) controls below.
* **Penetration testing.**
    * WSO2's internal security team runs penetration tests and vulnerability assessments; findings are addressed by the relevant product teams.
    * **WSO2 Private Cloud customers** may conduct their own penetration tests. Submit a request to WSO2 covering scope, tools, source IP addresses, and other relevant details for approval. Approved tests must run under WSO2's terms; **any finding must be reported to WSO2 within 24 hours**; testers must comply with their agreement with WSO2 and must not cause damage or introduce risk during the test.

## Delivery and Deployment

* **GitOps** for infrastructure and application deployments. The git repository is the source of truth for the deployment state.
* **Guardrails** via **Azure Policies**, automated in the SDLC for compliance reporting and enforced / auto-remediation controls.
* **Environment separation.** Development, staging, and production environments are isolated; each may include further network segments per its function.
* **Secrets and key management.** A secret manager stores credentials, encryption keys, API keys, tokens, and other sensitive material used for authentication and cryptography.
* **Securing the CI/CD pipeline.** SAST + SCA + image vulnerability scanning (OS, application, third-party dependencies) run before deployment. Per the shared-responsibility model, WSO2 keeps Kubernetes clusters patched and up to date.
* **System hardening** is applied to reduce attack surface across data, ports, components, functions, and permissions.

## Runtime Defence and Monitoring

* **Cloud Security Posture Management.** WSO2 uses **Microsoft Defender for Cloud** (formerly Azure Defender for Cloud) to continuously monitor cloud resources, track security and identity scores, and address risks.
* **Monitoring and observability.** The WSO2 **Security Operations Center (SOC)** monitors applications, microservices, containers, security-event log analysis, hardware resources, and network transport.

## Incident Management

WSO2 runs a documented cloud incident-management process — defined protocols, designated incident-response teams, and stakeholder communication procedures. For SaaS-specific customer notifications, see [Security Incident Notification Process for SaaS](./saas-incident-notification-process.md).

## Risk Management

Risks identified during threat modeling and at each SDLC stage are tracked and re-evaluated as development progresses. The intent is to integrate risk awareness into engineering decisions rather than treat risk as a separate review.

## Vulnerability Management

WSO2 runs periodic technical vulnerability assessments of cloud infrastructure with a documented methodology and supporting automation; baseline security standards are maintained per platform. For the cross-product vulnerability management process, see [Vulnerability Management Process](./vulnerability-management-process.md).

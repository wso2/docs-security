---
title: Cloud Security Process
category: security-processes
version: 2.1
---

# Cloud Security Process

<p class="doc-info">Version: 2.1</p>
___

WSO2 cloud services operate under a DevSecOps process aligned with [The Six Pillars of DevSecOps: Pragmatic Implementation](https://cloudsecurityalliance.org/artifacts/six-pillars-devsecops-pragmatic-implementation/) from the Cloud Security Alliance: secure design, hardened build pipelines, continuous testing, governed delivery, runtime defense, and structured incident response. This page documents the tooling, controls, and engineering practices applied at each lifecycle stage; the CSA reference covers the conceptual framing.

## Design and Architecture

Continuous threat modeling drives the secure design phase.

- **Threat models are maintained alongside the system.** Engineers update the model when introducing changes that may affect security posture; the Security Team uses the model to validate each change before it lands.
- **Customer-relevant findings are disclosed.** Risks identified in cloud deployments, components, or features that are material to affected customers are communicated to those customers.

## Coding

Security controls and automated analysis are embedded in the coding stage.

- **Secure coding standards.** Engineers follow the [WSO2 Secure Coding Guidelines]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/introduction/), which codify defensive coding practices, secure use of platform APIs, and consistent input handling across the codebase.
- **Container hardening.** Build pipelines enforce hardened container images, and only hardened images are promoted to production. Enforced principles: least privilege, defense in depth, minimized attack surface, restricted blast radius, and separation of duties.
- **Software Composition Analysis (SCA).** [FOSSA](https://fossa.com/) scans cloud components and products for known vulnerabilities in third-party dependencies and surfaces license obligations alongside.
- **Static Application Security Testing (SAST).** [Veracode](https://www.veracode.com/) is the primary commercial scanner, complemented by open-source static analyzers tailored to each language and framework in the cloud portfolio.

## Integration and Test

Pre-production validation combines automated scanning, configuration testing, and human-led penetration testing.

- **Dynamic Application Security Testing (DAST).** [Invicti](https://www.invicti.com/) (formerly Netsparker) and [Burp Suite](https://portswigger.net/burp) probe deployed applications, services, and APIs for vulnerabilities observable from the outside.
- **Container and orchestrator testing.** A dedicated test suite exercises container host and orchestrator configurations against the hardening baseline; this complements the build-pipeline controls and the runtime controls described below.
- **Internal penetration testing.** WSO2's Security Team performs penetration tests and vulnerability assessments on a recurring cadence. Findings are routed to the responsible product teams for remediation, with severity-based service-level expectations.
- **Customer penetration testing.** WSO2 Private Cloud customers may conduct penetration tests against their own environments under a formal authorization process. A request must be submitted covering testing scope, tools, source IP addresses, and other relevant details for approval. Approved tests proceed under WSO2's published terms; findings must be reported to WSO2 within 24 hours; testers operate under the terms of their agreement with WSO2 and must not introduce risk or impact to the service during the test window.

## Delivery and Deployment

Infrastructure and application deployments are governed as code, with continuous compliance enforcement.

- **GitOps.** Infrastructure and application deployments are managed through Git; the repository is the source of truth for the deployment state and the audit trail for every change.
- **Policy guardrails.** [Azure Policies](https://learn.microsoft.com/en-us/azure/governance/policy/) are integrated into the SDLC for compliance reporting and enforced auto-remediation.
- **Environment separation.** Development, staging, and production environments are isolated and further segmented by function and trust boundary.
- **Secrets and key management.** A centralized secret manager holds credentials, encryption keys, API keys, tokens, and cryptographic material; programmatic access is mediated by the platform.
- **Pipeline security.** SAST, SCA, and container-image vulnerability scanning (operating system, application, and third-party dependency layers) gate every release. Kubernetes clusters are kept current with security patches per the shared-responsibility model.
- **System hardening.** Hardening is applied across data, ports, components, functions, and permissions to reduce the attack surface of each deployment.

## Runtime Defense and Monitoring

Continuous posture management and security telemetry support detection and response.

- **Cloud Security Posture Management (CSPM).** [Microsoft Defender for Cloud](https://learn.microsoft.com/en-us/azure/defender-for-cloud/) (formerly Azure Defender for Cloud) continuously evaluates cloud resources against secure-configuration baselines, tracks WSO2's security and identity posture scores, and surfaces actionable risks.
- **Security operations.** The WSO2 Security Operations Centre monitors applications, microservices, containers, security-event log analysis, hardware resources, and network transport, with detection and response playbooks for each signal class.

## Incident Management

WSO2 operates a documented cloud incident-management process: defined protocols, designated incident-response teams, severity-driven escalation, and stakeholder communication procedures. SaaS-specific customer notification commitments are documented separately. See [Security Incident Notification Process for SaaS](./saas-incident-notification-process.md).

## Risk Management

Risks identified during threat modeling and at each SDLC stage are tracked and re-evaluated as development progresses. Risk management is integrated into engineering decision-making rather than executed as a separate review, ensuring that residual risk is visible to the teams making the decisions that produce it.

## Vulnerability Management

Periodic technical vulnerability assessments of cloud infrastructure run on a documented schedule with supporting automation, and platform-specific baseline security standards are maintained over time. The cross-product process (disclosure intake, triage, advisory publication, and customer communication) is documented in the [Vulnerability Management Process](./vulnerability-management-process.md).

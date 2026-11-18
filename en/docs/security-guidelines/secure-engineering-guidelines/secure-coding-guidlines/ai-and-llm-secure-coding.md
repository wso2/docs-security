---
title: AI and LLM Secure Coding Guide
category: security-guidelines
version: 1.0
---

# AI and LLM Secure Coding Guide

<p class="doc-info">Version: 1.0</p>
___

When you build a Choreo Labs feature that calls a large language model (LLM), retrieves content for a model (RAG), exposes tools to a model, or runs an AI agent, follow this guide. The attack classes and general defenses are covered by the OWASP cheat sheets below, linked rather than restated. Cross-cutting rules (injection sinks, access control, logging, supply chain) are in the [Secure Coding Guide]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/) and not restated here.

## External references

* **Prompt injection.** [OWASP LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html): direct and indirect injection, encoding and obfuscation, RAG poisoning, system prompt extraction, and layered defenses.
* **AI agents.** [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html): tool permissions, memory and context security, human-in-the-loop controls, multi-agent trust, monitoring, and adversarial testing.

## Rules for AI and LLM features in Choreo Labs products

These are the points that are not obvious from the external references, or that have a reason specific to Choreo Labs.

### Treat the model as an untrusted caller

No prompt design reliably separates instructions from data, and any content the model reads (a user message, a retrieved document, a web page, a tool result) can carry instructions. Design as if an attacker controls the model's output. Pass model output to each sink under the same rules as user input: see [Injection]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#injection), [Cross-Site Scripting]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#cross-site-scripting-xss), and [Server Side Request Forgery]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#server-side-request-forgery-ssrf).

### Tools run with the caller's identity

Run every tool or retrieval call with the caller's tenant/organization identity from the request context and the caller's own permissions, never a service-wide credential. The model must not be able to choose the tenant: as with caller input, tenant identity rides in context, never in model output (see [Principles specific to Choreo Labs product code]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#principles-specific-to-choreo-labs-product-code)). Expose only the tools the feature needs, and re-check authorization at the data layer on every call.

### Scope memory and retrieval by tenant

Conversation memory, vector stores, and retrieval indexes hold tenant data. Partition them by tenant/organization and filter every lookup by the caller's identity from the request context; a retrieval query without a tenant filter is the same class of defect as a SQL query without one. Treat retrieved content as untrusted input to the model, per the first rule.

### Confirm actions that change state or send data out

Require explicit user confirmation before an action that changes state or sends data outside the tenant (an outbound request, an email, a message). Show the user the concrete action and its parameters, not the model's summary of it.

### Keep secrets and other tenants' data out of prompts

Assume the system prompt and anything else in the context window can be extracted. Do not put credentials, API keys, or other tenants' data in prompts. Prompts and model responses that reach logs follow [Mask or hash sensitive values]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#mask-or-hash-sensitive-values).

### Bound cost per request

Cap tokens, tool calls, and agent loop iterations per request and per tenant, so a crafted input cannot run up model cost or exhaust shared capacity. This is the model-call form of [Pagination, list limits, and resource ceilings]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#pagination-list-limits-and-resource-ceilings).

### Models, agent frameworks, and tool servers are dependencies

Pin and review third-party models, agent frameworks, and tool servers (for example, MCP servers) the same way as any other dependency: see [Software Supply Chain Failures]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#software-supply-chain-failures).

### Release review

Treat any feature that lets a model call tools or act on a user's behalf as a risky exception: route it through the Security and Compliance Team before release. Test it with the smoke tests in the prompt injection cheat sheet, including indirect injection through every content source the model reads.

## Review checklist

When adding a feature that calls an LLM or runs an AI agent in a Choreo Labs product:

- [ ] Model output reaches SQL, OS commands, HTML, redirects, and outbound requests only through the same validation and encoding as user input.
- [ ] Every tool and retrieval call runs with the caller's identity and tenant from the request context, with no service-wide credential.
- [ ] The tool set is the minimum the feature needs; authorization is re-checked at the data layer.
- [ ] Memory, vector stores, and retrieval indexes are partitioned and filtered by tenant.
- [ ] Actions that change state or send data outside the tenant need explicit user confirmation.
- [ ] No credentials or other tenants' data in prompts; logged prompts and responses are masked.
- [ ] Token, tool-call, and iteration limits are set per request and per tenant.
- [ ] Third-party models, agent frameworks, and tool servers are pinned and reviewed.
- [ ] The Security and Compliance Team reviewed the feature before release.

---
title: Secure Coding Guide — Java Stack
category: security-guidelines
version: 3.0
---

# Secure Coding Guide — Java Stack

<p class="doc-info">Version: 3.0</p>
___

This document is the WSO2-specific secure coding guide for the **established Java-based products** — the long-running, Carbon-framework-based codebase. The framing assumes you are working inside a 10+ year codebase: there are existing helpers, existing conventions, and cross-bundle constraints that limit how much can change in any single pull request. The rules below codify what is already enforced where possible, what is incrementally improved where not, and what is uniquely WSO2 (the helpers, the defaults, and the anti-patterns reviewers should reject).

Read [Secure Coding Principles]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/principles/) first — it lays out the language-agnostic rules every WSO2 engineer applies and the public references (OWASP, NIST, RFCs, SLSA) every engineer is expected to know. This document does not repeat that material; it documents only the choices that are specific to the WSO2 Java stack.

For the Go-based products, see [Secure Coding Guide — Go Stack]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/go-stack/). The cross-stack mapping is in [OWASP Top 10 - 2025 Prevention]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/owasp-t10-2025-prevention/).

Each section below maps to an OWASP Top 10 - 2025 category. H3 sub-sections preserve the historical topic anchors so inbound links from older mapping pages and external references continue to work.

---

## Broken Access Control

**External references**

* [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
* [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
* [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
* [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

**Specifics for the WSO2 Java stack**

Authorisation decisions go through the realm-aware `AuthorizationManager` or the REST API's classification helpers, not raw role string comparisons in handler code. The canonical pattern is to initialise the decision to deny, call the check, and let any exception leave the variable at deny:

```java
boolean isAuthorized = false;
try {
    isAuthorized = authorizationManager.isUserAuthorized(user, resource, action);
} catch (UserStoreException e) {
    log.error("Authorisation check failed for user " + maskedUser(user)
              + " on resource " + resource, e);
}
if (!isAuthorized) {
    throw RestApiUtil.buildForbiddenException(resource, id);
}
```

At REST entry points the existing `RestApiUtil` helpers classify the cause chain (`isDueToAuthorizationFailure`, `isDueToResourceNotFound`) and route to 403/404 responses respectively. New REST modules should reuse these helpers rather than parse exception messages.

Tenant identity rides in `PrivilegedCarbonContext`. Reading tenant id from a header, query parameter, or path segment is wrong by construction — those are user input. The companion lifecycle rule (`startTenantFlow` / `endTenantFlow` in `try`/`finally`) appears in [Mishandling of Exceptional Conditions](#mishandling-of-exceptional-conditions) and is security-critical: a missing `endTenantFlow` causes cross-tenant context leakage on the next thread reuse.

### Object-level access control (IDOR)

External reference: [OWASP API1:2023 — Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/).

Path- and function-level access controls are necessary but not sufficient. Every operation that returns or modifies an object identified by an opaque or guessable id (`/orders/12345`, `/users/u-abc`, `/tenants/foo/secrets/s-xyz`) must additionally check that the authenticated principal owns or has permission on that specific object. Authorisation is **never** derived from the URL path or request body alone — those are user input.

The enforcement point must be the data layer: every repository query carries the principal's tenant id and user id (or owner id) as predicates, and the repository refuses to return rows that don't match. Carbon's pattern is to read tenant id from `PrivilegedCarbonContext` and add it as a query parameter; user-owned data adds the user id from the authenticated principal in the same way. Anti-pattern: handler-level "is this id in the user's list of allowed ids?" — that's a TOCTOU bug waiting to happen and it doubles the query cost.

### Object property-level access control (mass assignment)

External reference: [OWASP API3:2023 — Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/).

Even after the principal is allowed to operate on an object, not every property on that object is theirs to read or write. The two-sided failure mode:

* **On read** — serialising a domain entity directly to the response can leak fields the principal must not see (`internal_status`, `risk_score`, `password_hash`). Never serialise the persistence entity directly. Construct a typed response DTO and project the fields explicitly.
* **On write** — accepting an open property bag on update lets an attacker slip extra fields (`{"role": "admin"}` into a profile update; `{"tenant_id": "victim"}` into a comment). The defence has two layers: (1) refuse unknown JSON properties (see [Input validation](#input-validation)); (2) the controller maps DTO fields onto the entity field-by-field rather than calling a generic `applyAll(dto, entity)` reflection helper.

Carbon's REST endpoints follow this pattern — domain objects are mapped to dedicated DTO classes under `org.wso2.carbon.apimgt.rest.api.*.dto` packages and the controller constructs each response DTO explicitly. New endpoints follow the same shape; do not add a generic Jackson reflection pass over a domain object.

### Path Traversal

External reference: [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal).

For path-based input crossing into the file system, canonicalise (`new File(base, untrusted).getCanonicalFile()`) and require that the canonical path starts with the trusted base directory; reject otherwise. Never concatenate untrusted segments into a file path with `+`. For archive extraction, validate each entry's resolved path before writing — the classic "Zip Slip" bug pattern.

### Missing Function Level Access Control

External reference: [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html).

Every administrative or tenant-scoped operation has its permission requirement declared in the OSGi service descriptor or the REST API definition — not derived from role-name string matching inside business logic. New endpoints get an authorisation check at the handler entry, before any data access.

### Cross-Site Request Forgery (CSRF)

External reference: [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

WSO2 Java products use both OWASP CSRFGuard token validation and `SameSite=Lax`/`Strict` on session cookies; configuration lives in `repository/conf/security/Owasp.CsrfGuard.Carbon.properties`. In JSPs use the `<csrf:tokenname/>`/`<csrf:tokenvalue/>` taglib for forms, AJAX headers, and multipart upload action URLs. State-changing endpoints reachable from a browser must validate the CSRF token; APIs reachable only by service-to-service calls (with bearer tokens) typically do not need CSRF tokens, but must document why.

### Server Side Request Forgery (SSRF)

External reference: [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

Outbound calls from server-side code that take a URL from user input (webhook destinations, OIDC discovery, federated-IdP metadata) must validate the resolved host against an allow-list and refuse private/link-local/loopback ranges. Use `HttpClient` with a custom `DnsResolver` that performs the validation on the *resolved* address, not the host string — DNS rebinding will otherwise bypass the check.

### Unvalidated Redirects and Forwards

External reference: [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html).

For login-callback and post-action redirects, match the target against a registered allow-list of relative paths (or fully-qualified URLs for OAuth `redirect_uri`). The same exact-match rule that applies to OAuth `redirect_uri` (see [Authentication Failures](#authentication-failures)) applies here.

---

## Security Misconfiguration

**External references**

* [OWASP Security Misconfiguration page](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
* [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
* [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
* [OWASP HTTP Security Response Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
* [Mozilla TLS configuration generator](https://ssl-config.mozilla.org/)

**Specifics for the WSO2 Java stack**

Carbon configuration lives under `repository/conf/`. Risky features ship disabled and require an explicit opt-in. Examples from `api-manager.xml`:

```xml
<EnableSecureVault>false</EnableSecureVault>
<EnableMTLSForAPIs>false</EnableMTLSForAPIs>
<Analytics>
    <Enabled>false</Enabled>
</Analytics>
```

Anti-patterns the code review must reject:

* `NoopHostnameVerifier.INSTANCE` or any `HostnameVerifier` that returns `true` unconditionally. APIM's `APIManagerComponent` and Identity Server's `MutualSSLManager` both expose an `ALLOW_ALL` option for backwards compatibility, gated by a system property; the corresponding code (`NoopHostnameVerifier.INSTANCE`, `AllowAllHostnameVerifier`) is present in the shipped source. Production deployments must run with the strict (or `DEFAULT_AND_LOCALHOST`) verifier, and new components must not add similar opt-outs.
* `SSLContext` without an explicit `TLSv1.2`+ protocol baseline. The Carbon precedent (`MutualSSLManager`) hard-codes the minimum; new code follows the same convention and sets `SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")` for hostname verification in the SSL engine itself.
* Self-registered users granted the Carbon Management Console "login" permission — particularly relevant for API Manager Store users, who must not be able to reach the admin console.

### XML External Entity (XXE)

External reference: [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html).

Every XML parser instance — `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, `SchemaFactory`, `Validator` — must have external-entity and DTD processing disabled before use. The minimum settings:

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

Apply the equivalent feature flags to every parser family. Where a service receives untrusted XML and must process DTDs, use a DTD-validating but external-entity-disabled configuration, and consider migrating to a non-XML interchange format.

### ClickJacking and Cross Frame Scripting

External reference: [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html).

Set `Content-Security-Policy: frame-ancestors 'none'` (or an explicit allow-list) on every HTML response, and `X-Frame-Options: DENY` for legacy compatibility. Both Carbon's admin console and the per-product portals must ship with frame-ancestors set in production.

### Cross-Origin Resource Sharing

External reference: [OWASP CORS section in HTTP Headers cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#access-control-allow-origin).

`Access-Control-Allow-Origin: *` is never combined with `Access-Control-Allow-Credentials: true`. Configure CORS allow-lists explicitly in the gateway or service config; reject the wildcard plus credentials combination at code review.

### Security Related HTTP Headers

External reference: [OWASP HTTP Security Response Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html).

Production deployments must set:

* `Strict-Transport-Security: max-age=15768000; includeSubDomains` at every TLS-terminating endpoint. Add `preload` only after confirming the hostname tree is fully HTTPS.
* `Content-Security-Policy` — tight directive set. Aim for nonce-based or hash-based `script-src` with no `'unsafe-inline'` and no `'unsafe-eval'`; `frame-ancestors 'none'` (or an explicit allow-list) for management UIs; `object-src 'none'`. Retrofitting old JSPs takes effort — track it as a hardening item rather than relaxing the policy.
* `X-Content-Type-Options: nosniff` everywhere.
* `Referrer-Policy: strict-origin-when-cross-origin` or stricter (`no-referrer` for admin UIs).
* `Permissions-Policy` — explicit deny for features the app doesn't use (`geolocation=(), microphone=(), camera=(), payment=()`).
* `Cache-Control: no-store` on responses that carry tokens, session identifiers, or PII.
* `Clear-Site-Data: "cache", "cookies", "storage"` on the logout response.

These belong in the Tomcat `catalina-server.xml`/`server.xml` of each Carbon product (or in the gateway in front of Carbon). A deployment without HSTS on every TLS-terminating endpoint is a hardening defect.

### API inventory, versioning, deprecation

External reference: [OWASP API9:2023 — Improper Inventory Management](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/).

An API endpoint that exists but is not in the published inventory ("shadow API") is the most common attack surface — same code, less monitoring, often older auth checks. The defence:

* Every endpoint has a registered owner, a stable version, and an explicit lifecycle (active / deprecated / retired). The published OpenAPI / Swagger spec is the source of truth; endpoints not in the spec must not be reachable on the production gateway.
* Deprecation has a documented sunset date, emits a `Sunset:` response header (RFC 8594) and an audit event on every call after the sunset date.
* Non-production environments (dev, staging) live on different hostnames and are not reachable from the public internet. Internal-only endpoints (admin services, IdP management APIs, scheduled-job triggers) bind to internal networks.
* The gateway's API inventory and the Identity Server's federated trust list are reviewed quarterly; entries with zero recent calls are scheduled for retirement.
* When publishing a new version of an API, the old version's retirement is part of the same plan — versions don't accumulate forever, and there is a documented policy on how long N−1 stays available.

### Default credentials, sample applications, management console exposure

External reference: [OWASP ASVS V14 — Configuration](https://owasp.org/www-project-application-security-verification-standard/).

* Every default credential is rotated before the service is exposed. The Carbon admin user (`admin`/`admin` by default) gets a fresh, randomised password on first deployment; the keystore passwords (`wso2carbon`) are replaced and stored in SecureVault or an external secret manager.
* Sample applications, demo content, the Carbon Management Console, JMX endpoints, gRPC reflection, and any debug/profiling endpoints bind to localhost or an internal network — never to the public ingress. The same goes for the Identity Server admin console, the APIM admin/devops portals, and any debug endpoints exposed by deployed mediators.
* Strip server banners: `Server: WSO2/X.Y.Z` and version-disclosing headers (`X-Powered-By`, version metadata in error pages) are removed in production. Tomcat's `<Connector>` `server="…"` attribute is set to a non-identifying value.
* Self-registered users must not be granted the Management Console "login" permission. This is particularly important for API Manager Store users, who must not be able to reach the admin console regardless of role chain.

---

## Software Supply Chain Failures

**External references**

* [SLSA framework](https://slsa.dev/)
* [OWASP Software Component Verification Standard](https://owasp.org/www-project-software-component-verification-standard/)
* WSO2 [incident clarifications]({{#base_path#}}/security-announcements/incident-clarifications/) — the npm and axios incidents show what happens to deployments that diverge from the official baseline.

**Specifics for the WSO2 Java stack**

Maven product POMs restrict resolution to WSO2-controlled repositories. Adding a new repository, or relaxing checksum policy from `fail`, is a reviewable change to one parent POM, not a silent override. (A current audit found `<checksumPolicy>ignore</checksumPolicy>` set in two `msf4j` POMs — those are open items to tighten, not approved patterns.)

```xml
<repositories>
    <repository>
        <id>wso2-nexus</id>
        <url>https://maven.wso2.org/nexus/content/groups/wso2-public/</url>
        <releases>
            <enabled>true</enabled>
            <updatePolicy>daily</updatePolicy>
            <checksumPolicy>fail</checksumPolicy>
        </releases>
    </repository>
</repositories>
```

Two rules apply to every new POM: pin every `<version>` exactly (via a properties block) — never via Maven version ranges or `LATEST`/`RELEASE`; and inherit repository configuration from the parent POM so trust additions go through one diff.

CI manifest guard: any pull request that modifies `pom.xml`, `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `go.mod`, `go.sum`, or `.npmrc` requires an explicit dependency-approval label before it can merge. The workflow blocks unlabelled changes regardless of whether the test suite passes.

For new dependencies, follow the existing WSO2 onboarding process before adoption. Known-vulnerable dependencies (the next sub-section) require **WSO2 Security and Compliance Team** review before they are added or kept.

### Unsafe consumption of upstream APIs

External reference: [OWASP API10:2023 — Unsafe Consumption of APIs](https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/).

The supply-chain risk is not only in the dependency tree — every upstream service the code calls (federated IdPs, payment processors, partner APIs, internal microservices) is an integration the attacker can target either by compromising the upstream or by abusing the integration's trust. Treat every upstream response as untrusted input:

* **Validate the response before parsing it.** Check the HTTP status, `Content-Type`, content length, and schema against what the integration declared it expects. Reject anything that doesn't match. An upstream that suddenly returns HTML when JSON is expected is a signal, not a value to pass through.
* **Apply the same TLS rules outbound as inbound** — strict hostname verification (no `NoopHostnameVerifier`), TLS 1.2+, certificate pinning for high-trust upstreams (see [Cryptographic Failures](#cryptographic-failures)).
* **Bound every upstream call** with a connection timeout, a read timeout, and a request-level timeout. Use a circuit breaker on consecutive failures so a misbehaving upstream cannot consume threads, sockets, or memory indefinitely.
* **Never trust an upstream-issued JWT's `alg`, `kid`, or claims without verification.** Verify the signature against the upstream's published JWKS, restrict `alg` to a known-good allow-list, validate `iss` / `aud` / `exp` / `nbf`. Treat the JWKS URL as a configured trust anchor — never as something the upstream tells you to fetch at runtime.
* **Where an upstream's behaviour change could weaken your security posture** (e.g., a federated IdP changes its supported MFA factors, a key-management service drops an algorithm), build an explicit assumption-check that fails loudly rather than silently accepting the new behaviour.

### Using Known Vulnerable Components

External references: [OWASP Top 10 - 2025 A06](https://owasp.org/Top10/) and [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/).

OWASP Dependency Check runs on every PR. Findings above the agreed severity threshold fail the build unless explicitly suppressed in an audited allow-list with a documented rationale. For JS surfaces, `npm audit --audit-level=high` runs in CI with a granular `.audit-ignore.json` allow-list maintained by scope (frontend, common, samples).

When a new external dependency is proposed, run a deep check against vulnerability databases (NVD, GitHub Advisory Database, Snyk DB) **before** adding it. If a CVE is present, the WSO2 Security and Compliance Team must accept the risk in writing — keeping the dependency is a deliberate choice, not a default.

---

## Cryptographic Failures

**External references**

* [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
* [NIST SP 800-131A — algorithm transitions](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final)
* [NIST SP 800-57 — key management](https://csrc.nist.gov/projects/key-management)
* [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
* [RFC 8725 — JWT Best Current Practice](https://datatracker.ietf.org/doc/html/rfc8725)

**Specifics for the WSO2 Java stack**

Carbon's central facade for encryption is `org.wso2.carbon.core.util.CryptoUtil` (with `encryptAndBase64Encode()` and `base64DecodeAndDecrypt()` as the typical entry points), backed by a pluggable `InternalCryptoProvider`. The class lives in `carbon-kernel`-adjacent modules; check the version of `CryptoUtil` shipped with the product to confirm the current method signatures. Identity and APIM components select the provider via configuration:

```java
private static final String CRYPTO_PROVIDER =
        "CryptoService.InternalCryptoProviderClassName";
private static final String SYMMETRIC_KEY_CRYPTO_PROVIDER =
        "org.wso2.carbon.crypto.provider.SymmetricKeyInternalCryptoProvider";
```

New code that handles a secret — refresh tokens, identity provider credentials, vault-managed configuration — goes through `CryptoUtil` or an injected `CryptoService`. Never call `Cipher.getInstance` directly from product code; the central helper is what allows an algorithm or padding upgrade to be a one-place change rather than a campaign.

When a code path does instantiate a `Cipher` directly (legacy or framework-boundary), use modern transformations explicitly. The pattern for new symmetric encryption:

```java
byte[] iv = new byte[12];
SecureRandom.getInstanceStrong().nextBytes(iv);
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
byte[] ciphertext = cipher.doFinal(plaintext);
// Persist iv || ciphertext together; never reuse iv with the same key.
```

For asymmetric, use `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`. Audit older code that falls back to `Cipher.getInstance("RSA", …)` without an explicit padding string — this resolves to provider-dependent defaults and is a known weak pattern. A current audit of the Java repos shows the pattern still present in at least `carbon-registry/CipherInitializer.java`, `carbon-identity-framework/SecondaryUserStoreConfigurator.java`, and the user-store deployer utility; these are open hardening items, not approved patterns.

JWT signing/verification uses the Nimbus JOSE library through the gateway's JWT validator. Restrict accepted algorithms to an explicit allow-list (typically RS256/RS384/RS512 or ES256), reject `alg: none` by construction, and reject HMAC algorithms wherever the verifier holds an asymmetric public key (alg-confusion). Validate `iss`, `aud`, `exp`, `nbf`, `iat` on every verification, and look the signing key up by `kid` from a JWKS endpoint — never honour an inline `jwk` header.

Keys are managed through `KeyStoreManager` (primary, internal, per-tenant). Source private-key passphrases from SecureVault, document a rotation cadence for each key class (signing keys ≤ 2 years, data-encryption keys ≤ 1 year), and audit every keystore replacement.

**Runtime secrets handling.** Secrets read from SecureVault, environment variables, or an external secret manager into the JVM must not leak via:

* Process environment dumps (`env`, `printenv`, container introspection)
* Crash dumps, heap dumps, or core files that ship to crash-reporting services
* Logs, error responses, or audit messages
* Debugger / JMX attach interfaces in production

Hold passwords and key material as `char[]` rather than `String` and `Arrays.fill(arr, '\0')` after use. For sensitive byte arrays, zero them before returning (`Arrays.fill(bytes, (byte) 0)`). Use `MessageDigest.isEqual` for constant-time comparison of MACs, signatures, and password hashes — never `Arrays.equals` which short-circuits.

**Certificate pinning for outbound critical connections.** For high-criticality outbound calls (upstream auth servers, key vaults, payment processors, federated IdP token endpoints), pin the expected certificate or public key in addition to standard CA validation. Carbon's HTTP client wiring should accept a trust-store of pinned certificates per upstream. Rotate pinned values on a documented schedule and overlap old/new for the rotation window.

Java deserialisation security is covered in [Software and Data Integrity Failures → Insecure Deserialization](#insecure-deserialization).

### Heap Inspection Attacks

External reference: [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html).

Hold credentials and key material as `char[]` rather than `String` so they can be zeroed after use. Carbon's user-store and authentication APIs use `char[]` for the same reason. After authentication, overwrite the array (`Arrays.fill(pw, '\0')`) before returning. Avoid logging or persisting credentials at any boundary.

### Privacy Violation - Password AutoComplete

External reference: [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#password-managers).

Sensitive form fields (password, OTP, recovery answers) set `autocomplete="off"` (or the appropriate per-field token such as `new-password`) on the HTML input. Carbon's authentication endpoint JSPs already follow this; new login or recovery flows must do the same.

### Random Number Generation

External reference: [OWASP Cryptographic Storage Cheat Sheet — Secure Random](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#secure-random-number-generation).

Use `SecureRandom.getInstanceStrong()` for security-relevant randomness (tokens, nonces, salts, IVs). Never `java.util.Random` for anything reaching a security decision. Seed once at startup; do not re-seed per call.

### Securing Cookies

External reference: [OWASP Session Management Cheat Sheet — Cookies](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies).

Session and authentication cookies are marked `HttpOnly`, `Secure`, and `SameSite=Lax` (or `Strict` for high-sensitivity flows). Set the cookie `Path` to the narrowest scope that works; never set `Domain` more widely than required. Carbon's authentication endpoint configuration ships these defaults — new servlets and JAX-RS endpoints must follow the same convention.

---

## Injection

**External references**

* [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
* [OWASP LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)
* [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
* [OWASP Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

**Specifics for the WSO2 Java stack**

#### Input validation

External reference: [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html).

Validation is the first defence in front of every injection sink. Rules:

* **Allow-list, not deny-list.** Define what the value can be (length, character class, format, range, enum) and reject anything that doesn't match. Trying to enumerate bad inputs is a losing game.
* **Length limit on every string field.** Even when there is no other constraint, set a maximum length appropriate to the field (usernames ≤ 64, free-text descriptions ≤ 4 KB, etc.). Set `maxRequestSize` at the servlet container so requests that exceed the limit are rejected before reaching application code.
* **Format validation for known shapes** — `UUID.fromString` for UUIDs, `URI`/`URL` parsing for URLs (and accept only after the parsed value is itself validated), Jakarta Bean Validation (`@Email`, `@Pattern`, `@Size`, `@Min`/`@Max`, custom validators) on DTOs.
* **Canonicalise before validating.** Unicode-normalise (NFKC), percent-decode, strip null bytes (`\0`), reject embedded CR/LF before any allow-list check — otherwise the same logical value can pass validation in one form and reach the sink in another.
* **Refuse unknown JSON fields.** Jackson: `mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)` and/or `@JsonIgnoreProperties(ignoreUnknown = false)`. Refusing unknown fields stops most "mass assignment" bugs.
* **JSON parsing limits.** Configure Jackson's `StreamReadConstraints` (max depth, max numeric length, max string length, max number of object properties) to bound parser cost on adversarial input.

#### Database access

Every database access goes through `PreparedStatement` with bind parameters — `?` placeholders, never string concatenation. The pattern:

```java
try (PreparedStatement ps = conn.prepareStatement(
        "SELECT id, name FROM users WHERE tenant_id = ? AND user_id = ?")) {
    ps.setInt(1, tenantId);
    ps.setString(2, userId);
    try (ResultSet rs = ps.executeQuery()) {
        // ...
    }
}
```

Dynamic identifiers (column names in `ORDER BY`, table names) cannot be bound as parameters. Validate them against a server-side allow-list before composing the statement; never accept the raw identifier from the request.

For OS command execution, use `ProcessBuilder` or `Runtime.exec(String[])` with each argument as a separate list element. Never the single-string overload, and never invoke a shell with interpolated input. If a shell is genuinely required, escape with a reviewed helper, not by hand.

```java
// Anti-patterns — reject in code review
Runtime.getRuntime().exec("convert " + userFilename + " out.png");                       // single-string overload + concatenation
new ProcessBuilder("/bin/sh", "-c", "convert " + userFilename + " out.png").start();     // shell with interpolated input
Runtime.getRuntime().exec(new String[]{"sh", "-c", "convert " + userFilename});          // same, via the array overload

// Safe — argument array, no shell
new ProcessBuilder("convert", userFilename, "out.png")
        .redirectErrorStream(true)
        .start();
Runtime.getRuntime().exec(new String[]{"convert", userFilename, "out.png"});
```

For HTML output use the [OWASP Java Encoder](https://owasp.org/www-project-java-encoder/) (`Encode.forHtml`, `Encode.forHtmlAttribute`, `Encode.forJavaScript`, `Encode.forUriComponent`) per output context. Never write user-supplied data into a JSP with `<%= %>` raw.

For LDAP filter values, use the Carbon LDAP escape helper (or a reviewed local copy of the RFC 4515 escape table). Concatenating user input into an LDAP filter is the standard injection bug.

Logs that include user-controlled values must strip CR/LF before logging (see [Log Injection / Log Forging (CRLF Injection)](#log-injection-log-forging-crlf-injection)).

### SQL Injection

External reference: [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html).

`PreparedStatement` with bind variables for every value, server-side allow-list validation for dynamic identifiers. Same pattern as the parent section.

### LDAP Injection

External reference: [OWASP LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html).

Use the project's LDAP filter-escape helper. Treat any code that builds a filter via `String.format` or `+` with user input as a security defect.

### OS Command Injection

External reference: [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html).

`ProcessBuilder` with separate argument slots, or `Runtime.exec(String[])` with an explicit argument array — never the single-string `Runtime.exec(String)` overload, and never `/bin/sh -c "…"` with interpolated user input.

A current audit found `Runtime.getRuntime().exec(command.toString())` style invocations in carbon-kernel's tooling code (`tools/SPIProviderTool.java`, `tools/ICFProviderTool.java`, `tools/NativeLibraryProvider.java`). These are tools, not runtime code paths, but they are open hardening items: migrate to `ProcessBuilder` with separate argument slots so they stop appearing in security scans.

### Cross-Site Scripting (XSS)

External reference: [OWASP Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).

OWASP Java Encoder per output context. Combine with a strict `Content-Security-Policy` for defence in depth — `script-src 'self'` with no inline scripts in new code. JSP pages: the encoder taglib (`<e:forHtml/>`) is preferred over JSTL `<c:out/>` because it offers per-context escaping.

### HTTP Response Splitting (CRLF Injection)

External reference: [OWASP HTTP Response Splitting](https://owasp.org/www-community/attacks/HTTP_Response_Splitting).

Any value placed into a response header must have CR/LF stripped first. Servlet API rejects raw CR/LF in headers in current containers; new code that builds headers manually (downstream HTTP clients, proxy filters) must also strip.

### Log Injection / Log Forging (CRLF Injection)

External reference: [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).

Carbon 4.4.3+ supports the `%K` token in the log4j pattern, which appends a per-entry UUID. Forged log entries from an attacker's CR/LF payload lack a valid UUID, distinguishing them from genuine entries. A current audit of shipped product log layouts shows `%K` is supported but not consistently enabled by default; production deployments should ensure the layout includes `%K` and that operations is aware of the convention. In addition, strip CR/LF from any user-controlled string before logging.

### Server-Side Template Injection (SSTI)

External reference: [OWASP Server-Side Template Injection](https://owasp.org/www-community/attacks/Server-Side_Template_Injection).

Template engines (Velocity, FreeMarker, Thymeleaf, JSP-EL) execute expressions in their input. User input must never be substituted into template *source* — only into pre-defined parameters of an already-compiled template. Carbon's mediation engine and various mediators support templated content; any mediator that accepts user-supplied template strings is a code-execution sink.

Anti-pattern: `engine.evaluate(userSuppliedTemplate, context)`. Correct pattern: a fixed, version-controlled template plus a bound parameter map.

### NoSQL and XPath injection

External references: [OWASP NoSQL Injection](https://owasp.org/www-community/attacks/SQL_Injection) and [OWASP XPath Injection](https://owasp.org/www-community/attacks/XPATH_Injection).

The same allow-list discipline applies: construct queries with the driver's structured query API (MongoDB Java driver `Filters`, BSON document builders), never by concatenating user input into a query string. For XPath, use parameterised expressions via `XPathExpression` and a bound `XPathVariableResolver`; never `String.format` into the XPath source.

### Regex denial of service (ReDoS)

External reference: [OWASP Regular Expression Denial of Service](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS).

Regular expressions evaluated against user input must be bounded. Java's `java.util.regex.Pattern` uses a backtracking engine — catastrophic backtracking on patterns like `(a+)+` or `(a|aa)+` against adversarial input consumes CPU exponentially. Rules:

* Never compile a user-supplied regex pattern.
* For application-defined patterns evaluated against user input, prefer possessive quantifiers (`a++`) or atomic groups (`(?>…)`) where applicable.
* Cap input length before matching (typically a few KB at most).
* For high-risk surfaces, consider a separate evaluation thread with a timeout (interrupt via `Thread.interrupt()` and an interruptible matcher).

### Email header injection

External reference: [OWASP Email Injection](https://owasp.org/www-community/attacks/Email_Injection).

Any code that sends email and substitutes user input into `To`, `From`, `Subject`, `Reply-To`, or any other RFC 5322 header must strip CR/LF and validate per-header. `JavaMail` `InternetAddress` performs address-level validation; subject and free-text headers still need CRLF stripping before being passed to the mail session.

---

## Insecure Design

**External references**

* [OWASP Threat Modeling Process](https://owasp.org/www-community/Threat_Modeling_Process)
* [OWASP Proactive Controls](https://owasp.org/www-project-proactive-controls/)
* [WSO2 Secure Software Development Process]({{#base_path#}}/security-processes/secure-software-development-process/) — for when STRIDE-LM design review is required.

**Specifics for the WSO2 Java stack**

The WSO2 SSDLC requires a STRIDE-LM design review before code review for any change that introduces a new external surface, a new authentication or authorisation surface, a new credential/secret/key store, or a new privilege grant. The design-review artefacts (data flow diagram, trust boundaries, abuse cases) live in the product's architecture repository.

Workflow state machines are explicit. The API publishing lifecycle is modelled with the `APIStatus` enum (CREATED, PUBLISHED, DEPRECATED, RETIRED) and the transitions are enforced by `APIStatusObserver`/`APIStatusHandler` at the service layer before persistence. Workflow approvals use `WorkflowStatusEnum`. New domains follow the same shape — a typed enum, a transition table, service-layer enforcement.

For one-time initialisation of shared state, use class- or interned-string-level locks. Carbon's identity caches use the pattern `synchronized (cacheName.intern()) { … }`. For higher-throughput state, prefer `java.util.concurrent` primitives. For idempotency keys, check and insert atomically against the database (`INSERT ... ON CONFLICT` / unique index) — never `SELECT` then `INSERT`.

Rate limiting goes through the API Manager gateway's `ThrottleHandler` with application/subscription/API/resource/hard-limit tiers. Endpoints that sit outside the gateway (Identity Server admin services, custom inbound endpoints, OAuth token endpoints) need explicit throttling — either an APIM tier policy or a custom `IdentityEventListener` enforcing per-user and per-IP counters.

**Pagination, list limits, and resource ceilings.** Every list endpoint paginates with a server-enforced maximum page size (typically 100–1000). Total counts on every page are returned only where the table is small enough to scan cheaply — otherwise return `hasMore` and let callers page until empty. Operations that could touch unbounded data (full-table scans, deep relationship traversal, regex against large text columns) require an authenticated administrative role or live behind a deliberate batch-job path. Per-tenant ceilings (queries-per-minute, max stored objects, max attachment size) prevent one tenant from exhausting shared resources. Reject `limit=` parameters above the configured maximum at the handler — don't trust caller-supplied page sizes.

#### Sensitive business flows and anti-automation

External reference: [OWASP API6:2023 — Unrestricted Access to Sensitive Business Flows](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/).

Some flows are technically a legal sequence of API calls but the business model breaks if they are automated: signup, password reset, OTP resend, MFA enrolment, gift-code redemption, refund initiation, free-tier resource creation, comment posting. The defence is per-flow, not per-request:

* Identify sensitive flows at design time as part of the STRIDE-LM review. The output is a labelled list — design review owns it.
* For each, apply a layered budget: per-user, per-device, per-IP, per-tenant, plus a global ceiling that protects shared infrastructure. APIM tier policies, Identity Server's reCAPTCHA components, and the account-lockout handler are the existing primitives.
* Combine velocity-based limits with behavioural signals (CAPTCHA challenge after the first few failures, device fingerprinting where it applies). Account lockout (see [Authentication Failures](#authentication-failures)) is the auth-specific instance of the same pattern.
* Every sensitive-flow invocation emits an audit event ([Logging and Alerting Failures](#logging-and-alerting-failures)). The SOC has alerts on velocity anomalies for the highest-value flows (signup spikes, password-reset volume, MFA-disable attempts).

### Unrestricted File Upload

External reference: [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).

Every upload endpoint enforces, in order: maximum file size at the servlet container, maximum file size at the handler, content-type allow-list (validated against the file's magic bytes, not just the `Content-Type` header), filename sanitisation (no path separators, no traversal sequences), and storage outside any web-served directory. Uploaded files that will be served back are served from a separate hostname (or at minimum a separate path) without execute permissions and with `Content-Type` set explicitly.

---

## Authentication Failures

**External references**

* [NIST SP 800-63B — Authentication and Lifecycle Management](https://pages.nist.gov/800-63-3/sp800-63b.html)
* [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/rfc9700)
* [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
* [RFC 8725 — JWT BCP](https://datatracker.ietf.org/doc/html/rfc8725)
* [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
* [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

**Specifics for the WSO2 Java stack**

Password policies are enforced through `PolicyEnforcer` registered against `IdentityMgtEventListener.doPreUpdateCredential()`. The shipped defaults (`DefaultPasswordLengthPolicy` with MIN_LENGTH=6, MAX_LENGTH=10) are demo defaults — production deployments override the registry with: minimum length 12, all four character classes required, no whitespace, no upper bound below 64. Products handling personal data add a custom `PolicyEnforcer` that consults the HaveIBeenPwned k-Anonymity API (or a local mirror) at password-set time.

Argon2id and PBKDF2 are both supported by the user-store. For new deployments choose Argon2id (memory ≥ 19 MiB, iterations ≥ 2, parallelism ≥ 1) or PBKDF2-HMAC-SHA256 with ≥ 600 000 iterations and a 32-byte salt. Store the algorithm name and parameters alongside the hash so tightening the parameters is transparent on the next successful authentication.

Multi-factor authentication is wired through `carbon-identity-framework/components/authenticator/` (TOTP, FIDO2, SMS-OTP, Email-OTP). Adaptive authentication scripts select the second factor based on requested ACR, enrolled factors, and risk signals. Administrative accounts are enrolled in TOTP or FIDO2 before being granted the role. SMS/email OTP is acceptable as a step-up or fallback factor, not as the sole factor for any account that can administer tenants, manage keys, or read other users' data.

Account lockout is wired through `IdentityMgtEventListener` and `AccountLockHandler`. Failed attempts are tracked in the `UserIdentityClaimsDO`; the `http://wso2.org/claims/identity/accountLocked` claim is set when the threshold is reached and consulted in `doPreAuthenticate()` before any credential check. Successful authentication resets the counter. **The single design rule reviewed in every product: the lockout claim is honoured by every authentication path** — interactive login, OAuth `password` grant, token endpoint, SCIM provisioning. Lockout enforced on one path but not another is the bug pattern that lets attackers move sideways.

OAuth 2.0 / OIDC implementation:

* PKCE accepts only `S256`; reject `plain`. Enforced for every public client at the authorisation request.
* `redirect_uri` matches the registered values **exactly**. No prefix match, no substring match, no fragment.
* On every refresh, issue a new refresh token and invalidate the old one. If a request later presents the invalidated token, revoke the entire token family and emit a security event. Without reuse detection, refresh-token rotation adds latency and no security.
* JWT verification uses the explicit `JWSAlgorithm` allow-list (RS256/RS384/RS512, ES256/ES384) and rejects `alg: none` by construction. The verifier holding an asymmetric key rejects HMAC algorithms (alg confusion).

**Token storage on clients.** Identity Server's authentication endpoints serve tokens to browser apps, mobile apps, and machine clients — what each client does with the token is part of the security model:

* **Browser apps**: never store refresh tokens or long-lived access tokens in `localStorage` / `sessionStorage` — they are accessible to any script and leak via XSS. Use `HttpOnly`, `Secure`, `SameSite=Strict` cookies, or the BFF (backend-for-frontend) pattern where the SPA never holds the long-lived credential.
* **Mobile apps**: use the platform secret store (Keychain on iOS, Android Keystore). Refresh tokens are device-bound where the platform supports it.

**Logout, session termination, propagation.** Logout invalidates the session server-side and revokes the associated refresh token. The OAuth provider implements `revocation_endpoint` (RFC 7009) and supports back-channel logout (OpenID Connect Back-Channel Logout) so relying parties are notified to end their sessions. For multi-device scenarios, "log out everywhere" is a first-class operation that revokes every active token family for the principal.

**Account recovery.** Security questions are weak passwords — don't use them. Recovery requires either an MFA factor or a magic link sent to a verified email/SMS, and the flow is rate-limited per principal and per IP. After successful recovery, force MFA re-enrollment.

**Sensitive operations require fresh authentication (step-up).** Password change, MFA configuration changes, email change, key issuance, role grant, and equivalent admin actions require fresh credentials regardless of session age. Email change in particular notifies the **old** email and requires verification of the **new** email before the change takes effect.

### Session Hijacking

External reference: [OWASP Session Management Cheat Sheet — Session Hijacking](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-hijacking-attacks).

Sessions are bound to a TLS-only `HttpOnly`, `Secure`, `SameSite=Lax` cookie; session identifiers are generated by the container's secure RNG, never derived from user input. Logout invalidates the session server-side via `HttpSession.invalidate()`, not just by deleting the client cookie.

### Session Fixation

External reference: [OWASP Session Management Cheat Sheet — Session Fixation](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#renew-the-session-id-after-any-privilege-level-change).

On Carbon 4 the pattern is: `session.invalidate()`, then `request.getSession()` to get a fresh session, then set the authenticated attribute on the new session. This sequence prevents an attacker from binding a victim to a known session identifier before login.

### Session Prediction

External reference: [OWASP Session Management Cheat Sheet — Session ID Generation](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-content-or-value).

Rely on the servlet container's session-id generator (it uses `SecureRandom`). Do not roll a custom session-id generator. For application-level tokens (CSRF, password-reset, email-verification), use `SecureRandom.getInstanceStrong()` with at least 128 bits of entropy.

---

## Software and Data Integrity Failures

**External references**

* [SLSA framework](https://slsa.dev/)
* [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
* [sigstore / cosign](https://docs.sigstore.dev/)

**Specifics for the WSO2 Java stack**

Release artefacts (JARs, container images, Helm charts) are signed on protected infrastructure with a short-lived signing identity. Maven release pipelines run `maven-gpg-plugin` (or a sigstore equivalent) to produce `.asc` signatures next to each artefact; release notes publish SHA-256 checksums. Container images are signed with cosign before being pushed; deployment manifests reference images by digest, not tag.

CI workflow integrity: every workflow declares an explicit `permissions:` block scoped to what it needs. Avoid `pull_request_target` for workflows that handle secrets unless the workflow gates execution behind a label.

For inbound webhooks and auto-update channels: verify HMAC **before** parsing the payload. Use `MessageDigest.isEqual(byte[], byte[])` for the comparison — never `Arrays.equals`, which is not constant-time in older JDKs.

**Subresource Integrity (SRI).** Any third-party JavaScript or CSS loaded by URL from a CDN in a Carbon-served page or product UI carries an `integrity="sha384-…"` attribute and `crossorigin="anonymous"`. If a script's content cannot be pinned (because the CDN URL serves a moving target), host the script from a domain the team controls instead.

**API replay protection.** Sensitive write endpoints (key issuance, role grant, permission change, financial transfer if applicable) require a request-level `jti` or `nonce` and reject duplicates within a short window. Combine with a request expiry (`exp` on the request envelope, typically 5 minutes) to bound replay attempts. JWT-based requests already carry `jti`; non-JWT request signing should include a nonce-and-timestamp envelope.

### Insecure Deserialization

External reference: [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html).

For Java serialisation across the trust boundary, use `ObjectInputFilter` (JEP 290, Java 9+) — for example `-Djdk.serialFilter=com.wso2.expected.**;!*` — to restrict the classes the JVM will deserialise. On older Java, subclass `ObjectInputStream` and override `resolveClass()` to allow-list expected classes, throwing `InvalidClassException` for unauthorised classes. Mark sensitive fields `transient`. Prefer JSON/XML over Java serialisation for any cross-trust-boundary payload, and audit dependencies for known gadget libraries (Commons Collections, Spring Beans, Groovy).

A current audit of the Java repos shows multiple sites in identity-framework and registry components that construct `ObjectInputStream` without an `ObjectInputFilter` or `resolveClass()` override (workflow-mgt DAO, application-mgt DAO, the framework's `JavaSessionSerializer`, registry common utilities). These are open hardening items; any new code that follows this pattern must add a filter on the same change.

For inbound payloads that must remain dynamic (webhooks, plug-in configuration), require the producer to sign the payload, verify the signature first, then construct the typed object.

---

## Logging and Alerting Failures

**External references**

* [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
* [OWASP Logging Vocabulary Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html)

**Specifics for the WSO2 Java stack**

Use `log.error(message, throwable)` — the two-arg form that captures the full stack and cause chain. `log.error("..." + e.getMessage())` is lossy. The Carbon log layout supports the `%K` UUID token (Carbon 4.4.3+) so that forged log entries from log-injection attempts lack a valid UUID and are distinguishable from genuine entries.

Log at the failure boundary — the handler or the repository where the error stops — not at every layer the error passes through. The "log every layer" pattern produces unreadable traces and frequently leaks the same secret repeatedly.

#### Operational logs vs audit logs

These are two different concerns and should be treated as such:

* **Operational logs** record what the code did, for debugging and incident triage. Typical fields: timestamp, log level, component, message, exception. Retention is short (days to weeks) and the sink is the standard log aggregator.
* **Audit logs** record what users and admins did, for security investigation and compliance. Retention is long (months to years), the sink is append-only and tamper-evident, and the schema is stable. Audit logs are not a place for stack traces or framework chatter.

In Carbon products, the audit log goes through a dedicated logger (`AUDIT_LOG`) wired to a separate appender so the operational and audit streams can be retained and forwarded independently.

#### What must be in every audit event

| Field | Notes |
|---|---|
| `timestamp` | RFC 3339 with timezone; server clocks NTP-synchronised |
| `correlation_id` | Request id propagated across services |
| `tenant_id` | From `PrivilegedCarbonContext`, not from request input |
| `principal_id` | Authenticated user id; `null`/`anonymous` is itself a valuable signal |
| `principal_type` | `user` / `service_account` / `system` |
| `source_ip` | After resolving `X-Forwarded-For` against trusted proxies, not the raw header |
| `user_agent` | Truncated if needed |
| `action` | Stable enum, e.g. `auth.login`, `iam.role.grant`, `key.rotate` |
| `target` | Object class and id (`api:foo`, `user:u-abc`); never the full object |
| `decision` | `allow` / `deny` / `error` |
| `reason` | Short code if `deny` or `error` (e.g. `mfa_required`, `account_locked`) |

#### What never to log

Treat the following as **never log**, regardless of log level, regardless of intent:

* Passwords, password hints, recovery answers
* Access tokens, refresh tokens, ID tokens, OAuth `code`, OAuth `state`, OAuth client secrets
* Session identifiers, CSRF tokens, signed-URL signatures
* API keys, bearer tokens, webhook secrets
* Encryption keys, private keys, symmetric key material, key passphrases, keystore passwords
* MFA secrets (TOTP seeds), backup codes, recovery codes
* Plaintext PII beyond the principal id required for audit — full address, phone, date of birth, identity numbers, financial account numbers, health information, biometric data
* Full request bodies, full response bodies, full HTTP headers for endpoints that handle credentials
* Stack traces in user-facing responses (server-side only)
* Internal hostnames, internal IPs, file paths, environment variables

Where a value needs to appear in logs for correlation (e.g., a token id), log the **hash** or a **truncated prefix** with explicit ellipsis (`abcd1234…`) — never the full value. Carbon products use local masking helpers; extend those rather than building ad-hoc redactors.

#### Required security events

Every one of these emits an audit event; an alert fires on the patterns marked **alert**:

* Authentication: success, failure, account lockout (**alert** on N failures from one source in a window), MFA challenge issued, MFA failure, MFA success
* Authorisation: deny (**alert** on cross-tenant deny attempts), grant of a privileged role (**alert**)
* Password change, MFA enrolment / removal, email change, account recovery
* Token: issue, refresh, revoke (manual and automatic), reuse-detection trigger (**alert**)
* Key: read of a privileged key, rotate, revoke (**alert**)
* Configuration: change to a security setting (CORS allow-list, lockout thresholds, JWT issuers, federated IdPs) (**alert**)
* Administrative actions: tenant create/delete, user create/delete, role grant/revoke

#### Retention and integrity

Audit logs are append-only at the sink (no in-place edits, no deletions during the retention window). Forward to a dedicated audit sink — separate from operational logs — and consider signing or hash-chaining log batches for tamper evidence. Retention is set per the operating-team policy and is at least the SOC investigation window plus the compliance horizon (commonly 1 year for security events, longer for regulated data).

### Insufficient Logging and Monitoring

External reference: [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).

Refer to **Operational logs vs audit logs** above for the structure. The most common failure modes that cause "insufficient logging" findings in audits:

* Decisions logged at `DEBUG` rather than `INFO`/`AUDIT`, so they disappear from production
* Source IP read straight from `X-Forwarded-For` without proxy-trust evaluation, so the logged IP is whatever the attacker put in the header
* Failure events logged but not aggregated into an alert, so the SOC never sees them
* PII masked in some paths and not others, so the audit stream sometimes leaks personal data
* Audit logs and operational logs sharing a sink, so retention policy can't distinguish them

---

## Mishandling of Exceptional Conditions

**External references**

* [OWASP Improper Error Handling](https://owasp.org/www-community/Improper_Error_Handling)
* [CWE-703 — Improper Check or Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/703.html)

**Specifics for the WSO2 Java stack**

Catch the specific exception type you can handle. `catch (Exception e)` and `catch (Throwable t)` hide bugs and disable compile-time discipline. The OSGi `BundleActivator.start(BundleContext)` / `stop(BundleContext)` pair is allowed to declare `throws Exception` — the framework expects bootstrap failures to surface.

On any exception during a security-relevant decision (authentication, authorisation, signature verification, integrity check), the request must default to deny. Initialise the decision variable to the safe value before the `try`; never set it to the permissive value inside `catch`.

At REST/SOAP entry points, install a centralised exception mapper. The canonical pattern in `carbon-apimgt` is `org.wso2.carbon.apimgt.rest.api.util.exception.GlobalThrowableMapper`, which builds an `ErrorDTO` (`code`, `message`, `description`, `moreInfo`) and decides server-side whether to log the full stack via the per-error `ErrorHandler.printStackTrace()` flag. Stack traces, internal class names, SQL fragments, and file paths must never appear in `ErrorDTO.description` or `ErrorDTO.moreInfo`. New REST modules follow this pattern; do not write `e.getMessage()` or `e.toString()` directly into the response.

Resource cleanup uses `try`-with-resources for any `AutoCloseable` (`Connection`, `PreparedStatement`, `ResultSet`, `InputStream`, `OutputStream`):

```java
try (Connection conn = APIMgtDBUtil.getConnection();
     PreparedStatement ps = conn.prepareStatement(SQL_ORGANIZATION_EXISTS)) {
    ps.setString(1, orgId);
    try (ResultSet rs = ps.executeQuery()) {
        return rs.next();
    }
} catch (SQLException e) {
    APIMgtDBUtil.rollbackConnection(conn, "Failed to look up organisation " + orgId, e);
    throw new APIManagementException("Failed to look up organisation", e);
}
```

The multi-tenancy variant is **security-critical**. Carbon's tenant scoping is held in a `ThreadLocal`; if `PrivilegedCarbonContext.endTenantFlow()` is not called the next request reused on the same thread runs with the previous tenant's identity, including its permissions and userstore. Always call `endTenantFlow()` from a `finally` block:

```java
PrivilegedCarbonContext.startTenantFlow();
try {
    PrivilegedCarbonContext.getThreadLocalCarbonContext()
            .setTenantDomain(tenantDomain, true);
    // tenant-scoped work
} finally {
    PrivilegedCarbonContext.endTenantFlow();
}
```

Each `startTenantFlow` must be paired with exactly one `endTenantFlow` on every path, including exception paths.

Anti-patterns reviewers must reject:

```java
// Swallow and continue
try { riskyCall(); } catch (Exception ignored) {}

// Lossy log, swallow cause
try { riskyCall(); }
catch (Exception e) { log.error("Something failed: " + e.getMessage()); }

// Fail open
boolean allowed = true;
try { allowed = check(); }
catch (Exception e) { log.warn("permission check failed", e); }
```

Empty `catch` blocks are only acceptable for best-effort cleanup helpers (`closeQuietly`), and those helpers themselves log at `WARN` so the failure is still observable.

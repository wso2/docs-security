---
title: Secure Coding Guide
category: security-guidelines
version: 4.0
---

# Secure Coding Guide

<p class="doc-info">Version: 4.0</p>
___

This is the canonical WSO2 secure coding guide. It applies to every WSO2 product, in every language, but the implementation specifics differ between the established Java/Carbon-based products and the new Go-based products. Each section has a shared block of principles, references, and rules, followed by stack-specific implementation in tabs.

**How to read this guide.** Click the tab for the stack you work in (**Java stack** for the Carbon-based products, **Go stack** for the new Go-based products). Material remembers your choice across the site — once you pick a tab here, every other tab on every other page switches with it.

**Companion pages.**

* [OWASP Top 10 - 2025 Prevention]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/owasp-t10-2025-prevention/) maps the OWASP Top 10 - 2025 categories to the sections below.
* [OWASP API Security Top 10 - 2023 Prevention]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/owasp-api-top10-2023-prevention/) maps the OWASP API Security Top 10 to the same sections.
* [General Recommendations for React Secure Coding]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-react-secure-coding/) — frontend specifics.
* [Tooling Recommendations for Secure Coding]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/tooling-recommendations-for-secure-coding/) — security-related tooling.

## Principles WSO2 commits to

These apply regardless of language, framework, or product:

1. **Defence in depth.** Never rely on a single layer. Auth at the gateway *and* at the service. Encryption in transit *and* at rest. Input validation *and* output encoding.
2. **Fail secure.** On any exception during a security decision (authn, authz, signature verify, integrity check), default to deny. Initialise the decision variable to the safe value before `try`; never set it to the permissive value inside `catch`.
3. **Least privilege.** Components, service accounts, tokens, and roles hold the minimum permissions they need.
4. **Deny by default.** New code paths default to deny — for authz, network rules, CORS, container capabilities, CI workflow permissions, feature flags.
5. **Secure by default.** Risky features ship disabled. Production hardening is opt-in.
6. **Validate at trust boundaries, re-check at the data layer.** Tenant identity is carried in context and re-checked at the data layer, never inferred from caller input.
7. **Separate authentication from authorisation.** Both must run on every protected request; authorisation must default to deny.
8. **Audit and observability.** Every security-relevant decision emits a structured log event with a correlation id. Never log secrets, full tokens, or personal data.
9. **No security through obscurity.** Design assuming the code, configuration, and topology are public.
10. **Treat configuration as code.** Security-relevant settings are version-controlled, reviewed, validated in CI. Changes go through code review.

## External references every engineer should know

Cited inline throughout this guide where they apply; read them once and refer back.

### General application security
* [OWASP Top 10 (latest)](https://owasp.org/Top10/), [OWASP API Security Top 10](https://owasp.org/API-Security/), [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/), [OWASP Proactive Controls](https://owasp.org/www-project-proactive-controls/), [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/), [CWE Top 25](https://cwe.mitre.org/top25/).

### Identity and OAuth
* [NIST SP 800-63 — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/), [RFC 6749 — OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749), [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636), [RFC 9700 — OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/rfc9700), [RFC 7519 — JWT](https://datatracker.ietf.org/doc/html/rfc7519), [RFC 8725 — JWT BCP](https://datatracker.ietf.org/doc/html/rfc8725), [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html).

### Cryptography and transport
* [NIST SP 800-52 — TLS](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final), [SP 800-131A — algorithm transitions](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final), [SP 800-57 — key management](https://csrc.nist.gov/projects/key-management), [Mozilla TLS config generator](https://ssl-config.mozilla.org/), [RFC 8446 — TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446).

### Supply chain and build integrity
* [SLSA](https://slsa.dev/), [OWASP SCVS](https://owasp.org/www-project-software-component-verification-standard/), [OpenSSF Best Practices](https://www.bestpractices.dev/), [CycloneDX](https://cyclonedx.org/), [SPDX](https://spdx.dev/).

### WSO2 internal references
* [Secure Software Development Process]({{#base_path#}}/security-processes/secure-software-development-process/) — STRIDE-LM design review expectations.
* [Vulnerability Management Process]({{#base_path#}}/security-processes/vulnerability-management-process/).
* [Cloud Security Process]({{#base_path#}}/security-processes/cloud-security-process/).
* [Security Reporting]({{#base_path#}}/security-reporting/report-security-issues/).
* [WSO2 incident clarifications]({{#base_path#}}/security-announcements/incident-clarifications/).

---

## Broken Access Control

**External references**

* [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html), [Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html), [CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html), [SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

**Rules**

* Authorisation is checked on every protected request. Initialise the decision variable to deny; let exceptions leave it at deny.
* Tenant identity rides in a typed context (Carbon's `PrivilegedCarbonContext` in Java; a typed `context.Context` key in Go). Reading tenant id from a header, query parameter, or request body is wrong by construction.
* The store/repository layer carries the tenant predicate (and user/owner predicate where applicable) on every query, and refuses to return rows that don't match. Authorisation is not derived from the URL path alone.

### Object-level access control (IDOR)

External reference: [OWASP API1:2023 — Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/).

Path- and function-level access controls are necessary but not sufficient. Every operation that returns or modifies an object identified by an opaque or guessable id (`/orders/12345`, `/users/u-abc`, `/tenants/foo/secrets/s-xyz`) must additionally check that the authenticated principal owns or has permission on that specific object. The enforcement point is the data layer.

=== "Java stack"

    Read tenant id from `PrivilegedCarbonContext` and add it as a query parameter to every repository query; the repository refuses to return rows whose tenant does not match. Carbon's pattern of reading the principal from the authenticated context (not from request input) and threading it through the query is canonical. Anti-pattern: a handler-level "is this id in the user's list of allowed ids?" check — that doubles the query cost and creates a TOCTOU window.

=== "Go stack"

    Repository functions take `context.Context` as their first parameter and read the tenant id from a typed context key (never a `string` key). The store refuses to execute if the tenant is missing; defaulting to a "super tenant" or the empty string is a cross-tenant data exposure, not a convenience.

    ```go
    type tenantCtxKey struct{}

    func WithTenant(ctx context.Context, tenantID string) context.Context {
        return context.WithValue(ctx, tenantCtxKey{}, tenantID)
    }

    func GetTenant(ctx context.Context) (string, bool) {
        tenantID, ok := ctx.Value(tenantCtxKey{}).(string)
        return tenantID, ok && tenantID != ""
    }
    ```

    A current audit shows this pattern is not yet uniformly adopted across the WSO2 Go services — each new service should add the helpers when it introduces tenant scope.

### Object property-level access control (mass assignment)

External reference: [OWASP API3:2023 — Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/).

Even after the principal is allowed to operate on an object, not every property on that object is theirs to read or write.

* **On read** — serialising a domain entity directly to the response can leak fields the principal must not see (`internal_status`, `risk_score`, `password_hash`). Never serialise the persistence entity directly. Project explicitly to a typed response DTO.
* **On write** — accepting an open property bag on update lets an attacker slip extra fields (`{"role": "admin"}` into a profile update). The defence is two layers: refuse unknown JSON fields ([Input validation](#input-validation)) and map DTO fields onto the entity field-by-field rather than via reflection.

=== "Java stack"

    Carbon's REST endpoints use explicit DTOs in `org.wso2.carbon.apimgt.rest.api.*.dto` packages and construct each response DTO field-by-field from the domain object. Jackson is configured to fail on unknown properties. New endpoints follow the same shape — do not add a reflective pass over a domain object.

=== "Go stack"

    Define separate `Request` and `Response` DTO structs per endpoint, map field-by-field at the service layer, and use `json.Decoder.DisallowUnknownFields()` on every inbound decoder.

    ```go
    type UpdateUserRequest struct {
        DisplayName string `json:"display_name" validate:"required,min=1,max=128"`
        Locale      string `json:"locale"       validate:"required,bcp47_language_tag"`
    }

    type UpdateUserResponse struct {
        ID          string    `json:"id"`
        DisplayName string    `json:"display_name"`
        Locale      string    `json:"locale"`
        UpdatedAt   time.Time `json:"updated_at"`
        // role, password_hash, internal_status: deliberately not exposed
    }
    ```

### Path Traversal

External reference: [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal).

For path input crossing into the file system, canonicalise the resolved path and require that the canonical form starts with the trusted base directory; reject otherwise. Never concatenate untrusted segments with `+`. For archive extraction, validate each entry's resolved path before writing ("Zip Slip").

=== "Java stack"

    `new File(base, untrusted).getCanonicalFile()` and compare to `baseCanonical.toPath()`. Use `java.nio.file.Path.resolve` + `normalize` + prefix check; or `Path.toRealPath` with `LinkOption.NOFOLLOW_LINKS` where symlinks must not be followed.

=== "Go stack"

    `filepath.Clean(filepath.Join(base, untrusted))` and `strings.HasPrefix(clean, baseClean+string(filepath.Separator))`; reject otherwise. For archive extraction, `filepath.Rel(baseClean, target)` and require the relative path does not start with `..`.

### Missing Function Level Access Control

External reference: [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html).

Every administrative or tenant-scoped operation declares its permission requirement at the endpoint definition, not derived from role-name string matching inside business logic. Every endpoint gets an authorisation check at the handler entry, before any data access.

=== "Java stack"

    Permission requirement declared in the OSGi service descriptor or the JAX-RS resource annotation. New endpoints follow the same convention.

=== "Go stack"

    Authentication and authorisation middleware sits in front of every protected handler. On any failure the middleware writes the error response and stops the chain (`c.Abort()` in Gin, early `return` after writing in `net/http`).

    ```go
    authHeader := c.GetHeader("Authorization")
    if authHeader == "" {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
        c.Abort()
        return
    }
    tokenString := strings.TrimPrefix(authHeader, "Bearer ")
    if tokenString == authHeader {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format. Expected: Bearer <token>"})
        c.Abort()
        return
    }
    ```

    The public-vs-protected list is data, not code — keep a `permissions.go` (or equivalent) that enumerates every public path; anything not on the list is protected by default.

### Cross-Site Request Forgery (CSRF)

External reference: [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

State-changing endpoints reachable from a browser must validate a CSRF token. APIs reachable only by service-to-service calls (with bearer tokens) typically do not need CSRF tokens but must document why.

=== "Java stack"

    OWASP CSRFGuard tokens *and* `SameSite=Lax`/`Strict` on session cookies. Config in `repository/conf/security/Owasp.CsrfGuard.Carbon.properties`. In JSPs, use the `<csrf:tokenname/>`/`<csrf:tokenvalue/>` taglib for forms, AJAX headers, and multipart upload action URLs.

=== "Go stack"

    Issue an unguessable token on session creation, embed it in a cookie *and* require it as a header (the "double-submit cookie" pattern) or use a dedicated middleware. Combine with `SameSite=Strict` cookies.

### Server Side Request Forgery (SSRF)

External reference: [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

Outbound calls that take a URL from user input (webhook destinations, OIDC discovery, federated-IdP metadata) must validate the *resolved* host against an allow-list and refuse private / link-local / loopback ranges. DNS rebinding bypasses host-string checks.

=== "Java stack"

    `HttpClient` with a custom `DnsResolver` that performs the validation on the resolved address, not the host string.

=== "Go stack"

    Customise the `http.Transport`'s `DialContext` to call `net.DefaultResolver.LookupIPAddr`, validate each resolved IP, and refuse if any falls in a private / link-local / loopback range.

### Unvalidated Redirects and Forwards

External reference: [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html).

For login-callback and post-action redirects, match the target against a registered allow-list of relative paths (or fully-qualified URLs for OAuth `redirect_uri`). The same exact-match rule that applies to OAuth `redirect_uri` (see [Authentication Failures](#authentication-failures)) applies here.

---

## Security Misconfiguration

**External references**

* [OWASP Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/), [XXE Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html), [Clickjacking Defense](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html), [HTTP Security Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html), [Mozilla TLS config](https://ssl-config.mozilla.org/).

**Rules**

* Default configurations are safe to deploy unchanged. Dangerous features (debug endpoints, sample apps, analytics with PII, weak ciphers, broad CORS, mutual TLS off) ship disabled.
* Default credentials are rotated before the service is exposed. Sample apps, demo data, debug/profiling/management endpoints bind to localhost or an internal network — never the public ingress.
* Strip server banners. Don't return `Server: <product>/<version>` headers or version-disclosing metadata in error pages.
* Use the modern HTTP security header set on every protected response.

### HTTP security headers

Production deployments must set:

| Header | Value (default) |
|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` (add `preload` only after the hostname tree is fully HTTPS) |
| `Content-Security-Policy` | Nonce-based `script-src 'self' 'nonce-{n}'`; no `'unsafe-inline'`, no `'unsafe-eval'`; `frame-ancestors 'none'` (or explicit allow-list); `object-src 'none'`; `base-uri 'none'` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` (or stricter for admin / token-bearing surfaces) |
| `Permissions-Policy` | Deny features not used: `geolocation=(), microphone=(), camera=(), payment=(), interest-cohort=()` |
| `Cross-Origin-Opener-Policy` | `same-origin` — required for cross-origin isolation; mandatory on auth UIs |
| `Cross-Origin-Embedder-Policy` | `require-corp` |
| `Cross-Origin-Resource-Policy` | `same-site` |
| `Cache-Control` | `no-store` on token/PII responses |
| `Clear-Site-Data` | `"cache", "cookies", "storage"` on logout |

Cookies that carry authentication or session state are `HttpOnly; Secure; SameSite=Strict; Path=<narrow>`. Do not set `Domain` unless cross-subdomain sharing is required.

`Access-Control-Allow-Origin: *` is never combined with `Access-Control-Allow-Credentials: true`.

=== "Java stack"

    Headers belong in Carbon's Tomcat config (`catalina-server.xml`/`server.xml`) or in the terminating proxy. Retrofitting old JSPs to a nonce-based CSP takes effort — track it as a hardening item rather than relaxing the policy.

=== "Go stack"

    Apply the header set in middleware, not per-handler. Reject any header missing from the middleware chain at code review.

### Container security defaults

External reference: [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/).

* Image: distroless or minimal base — no shell, no package manager, no unnecessary binaries.
* Pod-level: `runAsNonRoot: true`, non-zero `runAsUser`/`runAsGroup`/`fsGroup`, `seccompProfile.type: RuntimeDefault`, `automountServiceAccountToken: false` unless the pod talks to the K8s API.
* Container-level: `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: ["ALL"]`; `emptyDir` for temp/log paths.
* Image pull by digest, not by tag.
* CPU and memory requests + limits on every container.
* `NetworkPolicy` default-deny in every namespace; explicit allow policies per service.
* `PodDisruptionBudget` for critical workloads.

Never `privileged: true`, `hostNetwork: true`, `hostPID: true`, `hostIPC: true`, or `hostPath` volumes.

### XML External Entity (XXE)

External reference: [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html).

=== "Java stack"

    Every XML parser instance — `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, `SchemaFactory`, `Validator` — has external-entity and DTD processing disabled before use:

    ```java
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    dbf.setXIncludeAware(false);
    dbf.setExpandEntityReferences(false);
    ```

    Apply equivalent feature flags to every parser family.

=== "Go stack"

    `encoding/xml` does not expand external entities by default — standard parsing is safe. Where a third-party library wraps another XML parser (e.g., libxml2 bindings), check its default settings explicitly.

### ClickJacking and Cross Frame Scripting

External reference: [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html).

`Content-Security-Policy: frame-ancestors 'none'` (or an explicit allow-list) on every HTML response, and `X-Frame-Options: DENY` for legacy compatibility. Admin consoles must ship with `frame-ancestors` set in production.

### Cross-Origin Resource Sharing

External reference: [OWASP CORS section](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#access-control-allow-origin).

Configure CORS allow-lists explicitly. Reject `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true` at code review.

### Security Related HTTP Headers

See [HTTP security headers](#http-security-headers) above.

### API inventory, versioning, deprecation

External reference: [OWASP API9:2023 — Improper Inventory Management](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/).

An API endpoint that exists but is not in the published inventory ("shadow API") is the most common attack surface — same code, less monitoring, often older auth checks.

* Every endpoint has a registered owner, a stable version, an explicit lifecycle (active / deprecated / retired). The published OpenAPI/Swagger spec is the source of truth; endpoints not in the spec must not be reachable on the production gateway.
* Deprecation has a documented sunset date and emits a `Sunset:` response header (RFC 8594) plus an audit event on every call after the sunset date.
* Non-production environments (dev, staging) live on different hostnames; internal-only endpoints bind to internal networks.
* Quarterly review of the gateway's API inventory and the IdP's federated trust list; entries with zero recent calls are scheduled for retirement.
* When publishing a new API version, the old version's retirement is part of the same plan.

=== "Java stack"

    Gateway inventory in the APIM publisher portal. Identity Server federated trust list reviewed quarterly. `Sunset:` header set at the JAX-RS layer for deprecated resources.

=== "Go stack"

    Generate the router from the OpenAPI spec, or fail the CI build if a handler exists that is not in the spec. Internal endpoints use Kubernetes `ClusterIP` services + `NetworkPolicy`, not `LoadBalancer`.

### Default credentials, sample applications, management console exposure

* Every default credential is rotated before exposure (the Carbon admin user gets a fresh randomised password on first deployment; keystore passwords are replaced and stored in SecureVault or an external secret manager).
* Sample applications, demo content, Carbon Management Console, JMX, gRPC reflection, debug/profiling endpoints — all bind to localhost or an internal network, never public ingress.
* Strip server banners (`Server: WSO2/X.Y.Z` and version-disclosing headers).
* Self-registered users must not be granted the Management Console "login" permission. Particularly important for API Manager Store users.

---

## Software Supply Chain Failures

**External references**

* [SLSA](https://slsa.dev/), [OWASP SCVS](https://owasp.org/www-project-software-component-verification-standard/).
* WSO2 [incident clarifications]({{#base_path#}}/security-announcements/incident-clarifications/) — the npm and axios incidents show what happens to deployments that diverge from the official baseline.

**Rules**

* Pin every dependency to an exact version. Never floating ranges (`^1.2`, `~1.2`, `LATEST`, `RELEASE`, `latest`).
* Commit the lock file on every change. Verify in CI (`npm ci` / `pnpm install --frozen-lockfile` / `go mod download` with `GOFLAGS=-mod=readonly`).
* Validate dependency manifests on every PR. The build fails if a manifest changes without an explicit approval label.
* A single trusted source per ecosystem (WSO2 Nexus for Maven, the documented Go module proxy, scoped mirror for npm). Resolution from any other source is a reviewable change.
* Generate an SBOM (CycloneDX or SPDX) as part of the release pipeline; attach to released artefacts.
* Sign every released artefact on protected infrastructure with a short-lived signing identity.
* Treat the CI runner and its secrets as a primary attack surface. Least-privileged `permissions:` on every workflow.

=== "Java stack"

    Product POMs restrict resolution to WSO2-controlled repositories:

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

    Pin every `<version>` exactly (via a properties block) — never via Maven version ranges or `LATEST`/`RELEASE`. Inherit repository configuration from the parent POM so trust additions go through one diff. **Current audit:** `<checksumPolicy>ignore</checksumPolicy>` is set in two `msf4j` POMs — open items to tighten.

=== "Go stack"

    `go.sum` is committed alongside every `go.mod` change. CI runs with `GOFLAGS=-mod=readonly`:

    ```yaml
    env:
      GOFLAGS: "-mod=readonly"
    on:
      pull_request_target:
        paths:
          - '**/go.mod'
          - '**/go.sum'
    ```

    `replace` directives in `go.mod` are review-required. For frontend modules pin the entire dependency graph via the workspace catalog + lock file (`pnpm install --frozen-lockfile`); never `^` or `~` ranges in `package.json` for production builds. For air-gapped builds, document the required `GOPROXY` (an internal mirror, never `direct`).

### Using Known Vulnerable Components

External reference: [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/).

OWASP Dependency Check runs on every PR; findings above the agreed threshold fail the build unless explicitly suppressed in an audited allow-list with documented rationale. For JS surfaces, `npm audit --audit-level=high` with a granular `.audit-ignore.json`. New dependencies require WSO2 Security and Compliance Team review if a CVE is present.

### Unsafe consumption of upstream APIs

External reference: [OWASP API10:2023 — Unsafe Consumption of APIs](https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/).

Treat every upstream API response as untrusted input.

* Validate response status, content-type, schema, size before parsing. Reject anything that doesn't match.
* Apply outbound TLS rules: strict hostname verification, TLS 1.2+, certificate pinning for high-trust upstreams (see [Cryptographic Failures](#cryptographic-failures)).
* Bound every upstream call (connection / read / request-level timeouts; circuit breaker on consecutive failures).
* Never trust an upstream-issued JWT's `alg`, `kid`, or claims without verification. Verify against the upstream's published JWKS. Treat the JWKS URL as a configured trust anchor — never something the upstream tells you to fetch at runtime.
* Where an upstream's behaviour change could weaken your security posture (federated IdP drops MFA, KMS drops an algorithm), build an explicit assumption-check that fails loudly.

=== "Java stack"

    Carbon's HTTP client wiring should accept a per-upstream trust-store; rotate pinned values with overlap windows.

=== "Go stack"

    Per-request timeout via `context.WithTimeout`; circuit breaker (e.g. `sony/gobreaker` or equivalent); `http.MaxBytesReader` on the response body before decoding.

---

## Cryptographic Failures

**External references**

* [OWASP Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html), [Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), [NIST SP 800-131A](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final), [NIST SP 800-57](https://csrc.nist.gov/projects/key-management), [RFC 8725 — JWT BCP](https://datatracker.ietf.org/doc/html/rfc8725).

**Rules**

* **Symmetric**: AES-128 or AES-256 in GCM mode with a fresh random 96-bit nonce per encryption.
* **Asymmetric**: RSA 2048+ with OAEP-SHA-256, or ECDSA P-256+, or Ed25519.
* **Hashing for integrity**: SHA-256 or SHA-3.
* **Password hashing**: Argon2id (memory ≥ 19 MiB, iterations ≥ 2, parallelism ≥ 1, key size 32 bytes) or PBKDF2-HMAC-SHA256 with ≥ 600 000 iterations and a 32-byte salt. Store algorithm name and parameters alongside the hash.
* **Banned**: MD5, SHA-1, 3DES, RC4, AES in ECB mode, `RSA/ECB/PKCS1Padding`, `Cipher.getInstance("AES")` without a mode, `Cipher.getInstance("RSA")` without padding.
* **TLS**: minimum TLS 1.2 (TLS 1.3 preferred), strict hostname verification, HSTS at the terminating proxy. Never `AllowAllHostnameVerifier`, `NoopHostnameVerifier.INSTANCE`, or `tls.Config{InsecureSkipVerify: true}` in production paths.
* **JWT**: per-verifier algorithm allow-list (typically RS256/RS384/ES256). Reject `alg: none`. Reject HMAC algorithms where the verifier holds an asymmetric key (alg-confusion). Validate `iss`, `aud`, `exp`, `nbf`, `iat` on every verification. Look up the signing key by `kid` from a JWKS cache; never honour an inline `jwk` header.
* **Keys**: documented rotation cadence (signing keys ≤ 2 years, data-encryption keys ≤ 1 year). Per-tenant data-encryption keys. Source private-key passphrases from a secret manager. Log every key lifecycle event.
* **Runtime secrets**: never leak via process env dumps, crash dumps, debugger/JMX interfaces, error responses, or logs. Hold password and key material in `char[]`/`[]byte` and zero after use where the language allows.
* Centralise crypto access behind audited helpers; never call primitives directly from product code.

=== "Java stack"

    Carbon's central facade for encryption is `org.wso2.carbon.core.util.CryptoUtil` (`encryptAndBase64Encode`, `base64DecodeAndDecrypt`), backed by a pluggable `InternalCryptoProvider`. Identity and APIM components select the provider via configuration:

    ```java
    private static final String CRYPTO_PROVIDER =
            "CryptoService.InternalCryptoProviderClassName";
    private static final String SYMMETRIC_KEY_CRYPTO_PROVIDER =
            "org.wso2.carbon.crypto.provider.SymmetricKeyInternalCryptoProvider";
    ```

    New code that handles a secret — refresh tokens, identity provider credentials, vault-managed configuration — goes through `CryptoUtil` or an injected `CryptoService`. Never call `Cipher.getInstance` directly from product code.

    When a code path does instantiate a `Cipher` directly (legacy or framework boundary), use modern transformations explicitly:

    ```java
    byte[] iv = new byte[12];
    SecureRandom.getInstanceStrong().nextBytes(iv);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
    byte[] ciphertext = cipher.doFinal(plaintext);
    // Persist iv || ciphertext together; never reuse iv with the same key.
    ```

    For asymmetric, use `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`. **Current audit:** `Cipher.getInstance("RSA")` without padding remains in `carbon-registry/CipherInitializer`, `carbon-identity-framework/SecondaryUserStoreConfigurator`, and the user-store deployer utility — open hardening items.

    JWT signing/verification uses Nimbus JOSE through the gateway's `JWTValidator`:

    ```java
    JWSAlgorithm algorithm = jwt.getHeader().getAlgorithm();
    if (algorithm != null && (JWSAlgorithm.RS256.equals(algorithm)
            || JWSAlgorithm.RS384.equals(algorithm)
            || JWSAlgorithm.RS512.equals(algorithm))) {
        JWSVerifier jwsVerifier = new RSASSAVerifier(publicKey);
        return jwt.verify(jwsVerifier);
    } else {
        throw new APISecurityException(...);
    }
    ```

    Keys are managed through `KeyStoreManager` (primary, internal, per-tenant). Source private-key passphrases from SecureVault.

    Carbon's `MutualSSLManager` hard-codes the TLS minimum:

    ```java
    private static final String protocol = "TLSv1.2";
    ```

    New code that builds an `SSLContext` sets TLS 1.2+, `SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")`, and never installs `NoopHostnameVerifier.INSTANCE`. APIM's `APIManagerComponent` and IS's `MutualSSLManager` expose an `ALLOW_ALL` option for backwards compatibility, gated by a system property — not enabled in production deployments; new components must not add similar opt-outs.

    Hold credentials and key material as `char[]` rather than `String`. After authentication, `Arrays.fill(pw, '\0')`. Compare MACs with `MessageDigest.isEqual`, never `Arrays.equals` (not constant-time in older JDKs).

=== "Go stack"

    Go through the project's central crypto helper package — never call `crypto/aes`, `crypto/rsa`, or `crypto/sha256` directly from product code. For the API platform, `pkg/encryption/manager.go` (dispatcher) plus `pkg/encryption/<alg>/` providers is the established shape. New services should follow the same pattern.

    AES-GCM with a fresh random nonce per call:

    ```go
    func encryptAESGCM(key, plaintext []byte) ([]byte, error) {
        block, err := aes.NewCipher(key)
        if err != nil {
            return nil, fmt.Errorf("failed to create AES cipher: %w", err)
        }
        aesgcm, err := cipher.NewGCM(block)
        if err != nil {
            return nil, fmt.Errorf("failed to create GCM mode: %w", err)
        }
        nonce := make([]byte, aesgcm.NonceSize())
        if _, err := rand.Read(nonce); err != nil {
            return nil, fmt.Errorf("failed to generate nonce: %w", err)
        }
        return aesgcm.Seal(nonce, nonce, plaintext, nil), nil
    }
    ```

    Never reuse `key+nonce`; never derive the nonce from a counter.

    Password hashing parameters from configuration:

    ```go
    h := argon2.IDKey(credentialValue, credSalt,
        uint32(a.Iterations), uint32(a.Memory),
        uint8(a.Parallelism), uint32(a.KeySize))
    ```

    JWT verification — restrict the accepted algorithm at parse time inside the keyfunc:

    ```go
    token, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
        switch t.Method.Alg() {
        case "RS256", "RS384", "ES256":
            // continue
        default:
            return nil, fmt.Errorf("unsupported alg %q", t.Method.Alg())
        }
        kid, _ := t.Header["kid"].(string)
        return jwks.GetKey(kid)
    })
    ```

    `tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}` on every outbound HTTP client and every server config. `InsecureSkipVerify: true` is acceptable only when operator-configured with a secure default of `false`; hardcoded `true` is a defect. **Current audit:** ~48 production occurrences across multiple Go services; each must be reviewed.

### Heap Inspection Attacks

External reference: [OWASP Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html).

=== "Java stack"

    Hold credentials and key material as `char[]` rather than `String` so they can be zeroed after use. Carbon's user-store and authentication APIs use `char[]` for the same reason. After authentication, overwrite the array (`Arrays.fill(pw, '\0')`) before returning. Avoid logging or persisting credentials at any boundary.

=== "Go stack"

    Use `[]byte` for secret material; `crypto/subtle.ConstantTimeCompare` for sensitive comparisons. Note that Go strings are immutable and cannot be zeroed — keep secrets in `[]byte` from the point of read.

### Privacy Violation - Password AutoComplete

External reference: [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#password-managers).

Sensitive form fields (password, OTP, recovery answers) set `autocomplete="off"` or the appropriate per-field token (`new-password`, `one-time-code`) on the HTML input.

### Random Number Generation

External reference: [OWASP Cryptographic Storage — Secure Random](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#secure-random-number-generation).

=== "Java stack"

    `SecureRandom.getInstanceStrong()` for security-relevant randomness (tokens, nonces, salts, IVs). Never `java.util.Random` for anything reaching a security decision. Seed once at startup; do not re-seed per call.

=== "Go stack"

    `crypto/rand.Read` for security-relevant randomness; never `math/rand` for anything reaching a security decision.

### Securing Cookies

External reference: [OWASP Session Management — Cookies](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies).

Session and authentication cookies are `HttpOnly`, `Secure`, `SameSite=Lax` (or `Strict` for high-sensitivity flows). Set `Path` to the narrowest scope that works. Never set `Domain` more widely than required.

---

## Injection

**External references**

* [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html), [LDAP Injection](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html), [OS Command Injection](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html), [Cross-Site Scripting](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html), [Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html).

### Input validation

Validation is the first defence in front of every injection sink. Rules apply across both stacks:

* **Allow-list, not deny-list.** Define what the value can be (length, character class, format, range, enum) and reject anything that doesn't match.
* **Length limit on every string field.** Even when there is no other constraint, set a maximum length appropriate to the field.
* **Format validation for known shapes** — UUID, email, URL (parse, then validate the parsed value).
* **Canonicalise before validating** — Unicode NFKC, percent-decode, strip null bytes, reject embedded CR/LF before any allow-list check.
* **Refuse unknown JSON fields.**
* **JSON parsing limits** — bound parser cost (depth, numeric length, string length, number of properties) on adversarial input.

=== "Java stack"

    Use Jakarta Bean Validation (`@Email`, `@Pattern`, `@Size`, `@Min`/`@Max`, custom validators) on DTOs. Jackson: `mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)` or `@JsonIgnoreProperties(ignoreUnknown = false)`. Configure Jackson's `StreamReadConstraints` to bound parser cost on adversarial input. Set `maxRequestSize` at the servlet container.

=== "Go stack"

    Decode request bodies into typed structs (never `map[string]any` for production handlers) with `go-playground/validator` tags. `dec := json.NewDecoder(r.Body); dec.DisallowUnknownFields()`. `http.MaxBytesReader(w, r.Body, maxBodySize)` on every body-reading handler.

    ```go
    type CreateAppRequest struct {
        Name        string   `json:"name"        validate:"required,min=1,max=128,alphanumunicode"`
        Description string   `json:"description" validate:"omitempty,max=4096"`
        Scopes      []string `json:"scopes"      validate:"max=32,dive,oneof=read write admin"`
    }
    ```

### SQL Injection

Use parameterised queries with bind variables; never string concatenation. For dynamic identifiers (column names in `ORDER BY`, table names) validate against a server-side allow-list before composing the statement.

=== "Java stack"

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

=== "Go stack"

    ```go
    row := db.QueryRowContext(ctx,
        "SELECT id, name FROM users WHERE tenant = $1 AND id = $2",
        tenantID, userID)
    ```

### LDAP Injection

Use the project's LDAP filter-escape helper. Building a filter via `String.format` / `fmt.Sprintf` / `+` with user input is a security defect.

### OS Command Injection

`ProcessBuilder` / `exec.CommandContext` with separate argument slots — never the single-string form, and never `sh -c "…"` with interpolated input.

=== "Java stack"

    ```java
    // Anti-patterns — reject in code review
    Runtime.getRuntime().exec("convert " + userFilename + " out.png");
    new ProcessBuilder("/bin/sh", "-c", "convert " + userFilename + " out.png").start();
    Runtime.getRuntime().exec(new String[]{"sh", "-c", "convert " + userFilename});

    // Safe — argument array, no shell
    new ProcessBuilder("convert", userFilename, "out.png")
            .redirectErrorStream(true).start();
    Runtime.getRuntime().exec(new String[]{"convert", userFilename, "out.png"});
    ```

    **Current audit:** `Runtime.getRuntime().exec(command.toString())` style invocations remain in carbon-kernel's tooling code (`tools/SPIProviderTool.java`, `tools/ICFProviderTool.java`, `tools/NativeLibraryProvider.java`) — open hardening items.

=== "Go stack"

    ```go
    // Anti-patterns — reject in code review
    exec.CommandContext(ctx, "sh", "-c", "convert "+userFilename+" out.png")
    exec.CommandContext(ctx, "/bin/sh", "-c", fmt.Sprintf("convert %s out.png", userFilename))

    // Safe — argument slots, no shell
    cmd := exec.CommandContext(ctx, "convert", userFilename, "out.png")
    cmd.Stdin = nil
    out, err := cmd.CombinedOutput()
    ```

### Cross-Site Scripting (XSS)

Per-context encoding at the output point. Pair with a strict `Content-Security-Policy`.

=== "Java stack"

    [OWASP Java Encoder](https://owasp.org/www-project-java-encoder/) per output context: `Encode.forHtml`, `Encode.forHtmlAttribute`, `Encode.forJavaScript`, `Encode.forUriComponent`. JSP: encoder taglib (`<e:forHtml/>`) preferred over JSTL `<c:out/>`. Never write user-supplied data into a JSP with `<%= %>` raw.

=== "Go stack"

    Render HTML with `html/template`, never `text/template`. The auto-escaping is per-context (HTML attribute vs. script vs. URL).

### HTTP Response Splitting (CRLF Injection)

External reference: [OWASP HTTP Response Splitting](https://owasp.org/www-community/attacks/HTTP_Response_Splitting).

Strip CR/LF from any value placed into a response header. Modern servlet containers and `net/http` reject raw CR/LF, but new code that builds headers manually (downstream HTTP clients, proxy filters) must also strip.

### Log Injection / Log Forging (CRLF Injection)

Strip CR/LF from any user-controlled value before logging. See [Logging and Alerting Failures](#logging-and-alerting-failures).

=== "Java stack"

    Carbon 4.4.3+ supports the `%K` token in the log4j pattern, appending a per-entry UUID. Forged log entries from an attacker's CR/LF payload lack a valid UUID. **Current audit:** `%K` is supported but not consistently enabled in product default log layouts — production deployments should ensure the layout includes `%K`.

### Server-Side Template Injection (SSTI)

External reference: [OWASP SSTI](https://owasp.org/www-community/attacks/Server-Side_Template_Injection).

Template engines (Velocity, FreeMarker, Thymeleaf, JSP-EL, Jinja, `html/template`, `text/template`) execute expressions in their input. User input must never be substituted into template *source* — only into pre-defined parameters of an already-compiled template. Anti-pattern: `engine.evaluate(userSuppliedTemplate, context)`.

### NoSQL and XPath injection

Construct queries with the driver's structured query API (MongoDB filters, BSON documents, XPath with bound variables) — never by concatenating user input into a query string.

### Regex denial of service (ReDoS)

External reference: [OWASP ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS).

* Never compile user-supplied regex patterns.
* Cap input length before matching.
* For application-defined patterns, use linear-time semantics where possible.

=== "Java stack"

    `java.util.regex.Pattern` uses a backtracking engine — catastrophic backtracking on patterns like `(a+)+` consumes CPU exponentially. Prefer possessive quantifiers (`a++`) or atomic groups (`(?>…)`) where applicable. For high-risk surfaces, use a separate evaluation thread with a timeout (interruptible matcher).

=== "Go stack"

    Go's `regexp` package uses RE2 (linear time, no backtracking) — safe by design. Bounding input length still applies, to cap memory.

### Email header injection

External reference: [OWASP Email Injection](https://owasp.org/www-community/attacks/Email_Injection).

Any code that sends email and substitutes user input into `To`, `From`, `Subject`, `Reply-To`, or any other RFC 5322 header must strip CR/LF and validate per-header. Prefer libraries that build headers programmatically over string formatting.

---

## Insecure Design

**External references**

* [OWASP Threat Modeling Process](https://owasp.org/www-community/Threat_Modeling_Process), [OWASP Proactive Controls](https://owasp.org/www-project-proactive-controls/), [WSO2 Secure Software Development Process]({{#base_path#}}/security-processes/secure-software-development-process/).

**Rules**

* Any feature that introduces a new external attack surface, a new authentication or authorisation surface, a new credential or secret store, or a new privilege grant goes through STRIDE-LM design review with the security lead before code review begins.
* Default configurations are safe to deploy unchanged ([Security Misconfiguration](#security-misconfiguration)).
* Workflow state transitions are enforced by an explicit state machine (an enum + transition table, checked at the service layer before persistence). Never derive the next state from caller input alone.
* All shared mutable state is guarded against race conditions. Critical sections that span "check then act" hold the lock for both steps, or use compare-and-set primitives.
* Every endpoint that performs work is rate-limited (per-user **and** per-IP **and** global, not just one).
* Trust boundaries are named and enforced; tenant identity is carried in context and re-checked at the data layer.

=== "Java stack"

    Workflow state machines are explicit: `APIStatus` (`CREATED`, `PUBLISHED`, `DEPRECATED`, `RETIRED`) with `APIStatusObserver`/`APIStatusHandler` enforcing transitions at the service layer; workflow approvals use `WorkflowStatusEnum`. New domains follow the same shape.

    For one-time initialisation of shared state, class- or interned-string-level locks: `synchronized (cacheName.intern()) { ... }`. For higher-throughput state, prefer `java.util.concurrent` primitives. For idempotency, atomic database operations (`INSERT ... ON CONFLICT` / unique index) — never `SELECT` then `INSERT`.

    Rate limiting via the APIM gateway's `ThrottleHandler` (application/subscription/API/resource/hard-limit). Endpoints outside the gateway (IS admin services, custom inbound, OAuth token endpoints) need explicit throttling — APIM tier policies or a custom `IdentityEventListener` with per-user and per-IP counters.

=== "Go stack"

    Document the trust model in `ARCHITECTURE.md`; list every public path explicitly; default-deny for anything else. Encode operation-level security as declarative data in the API spec, not as ad-hoc code in handlers. Model long-running workflows as typed state machines with optimistic locking on `(instance_id, current_state)`.

    Concurrency primitives: `sync.Once` for one-time init, `sync.RWMutex` for high-throughput maps, database uniqueness for idempotency. Rate limiting at middleware, not per handler.

### Pagination, list limits, and resource ceilings

External reference: [OWASP API4:2023 — Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/).

Every list endpoint paginates with a server-enforced maximum page size (typically 100–1000). Total counts on every page only where the table is small enough to scan cheaply — otherwise return `hasMore` and let callers page until empty. Operations that could touch unbounded data require an admin role or a deliberate batch-job path. Per-tenant ceilings (queries-per-minute, max stored objects, max attachment size) prevent one tenant exhausting shared resources. Reject `limit=` parameters above the configured maximum at the handler.

### Sensitive business flows and anti-automation

External reference: [OWASP API6:2023 — Unrestricted Access to Sensitive Business Flows](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/).

Some flows are technically a legal sequence of API calls but the business model breaks if they are automated: signup, password reset, OTP send, MFA enrolment, gift-code redemption, refund initiation, free-tier resource creation, comment posting.

* Identify sensitive flows at design time as part of the STRIDE-LM review.
* Apply a layered budget per flow: per-user, per-device, per-IP, per-tenant, plus a global ceiling.
* Combine velocity limits with behavioural signals (CAPTCHA after the first few failures, device fingerprinting).
* Every sensitive-flow invocation emits an audit event; the SOC alerts on velocity anomalies for the highest-value flows.

### Unrestricted File Upload

External reference: [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).

Every upload endpoint enforces, in order: maximum file size at the container, maximum file size at the handler, content-type allow-list (validated against the file's magic bytes, not just the `Content-Type` header), filename sanitisation, storage outside any web-served directory. Files served back are served from a separate hostname (or at minimum a separate path), without execute permissions, with `Content-Type` set explicitly.

---

## Authentication Failures

**External references**

* [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html), [RFC 9700 — OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/rfc9700), [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636), [RFC 8725 — JWT BCP](https://datatracker.ietf.org/doc/html/rfc8725), [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).

**Rules**

* Password policy on every credential write: minimum length 12, all four character classes required, no whitespace, no upper bound below 64. For products handling personal data, also reject passwords that appear on a breached-password list (HIBP k-Anonymity API or a local mirror).
* Password hashing with Argon2id or PBKDF2 per the parameters in [Cryptographic Failures](#cryptographic-failures). Store the algorithm name and parameters alongside the hash.
* MFA is the default for any account with administrative or sensitive-data access. Support TOTP and FIDO2 / WebAuthn primarily; SMS/email OTP as step-up or fallback, never as sole factor for privileged accounts.
* Lockout after a small number of failed attempts in a sliding window; unlock after a documented duration or by admin. Reset the counter on success. **The lockout claim must be honoured by every authentication path** — interactive login, OAuth `password` grant, token endpoint, SCIM provisioning. Enforced on one path but not another is the bug pattern that lets attackers move sideways.
* Defend against credential stuffing at the gateway: per-IP and per-user rate limits, CAPTCHA escalation, breached-password rejection at password-set time, anomaly logging (impossible travel, unfamiliar device).
* OAuth 2.0 / OIDC: PKCE with `S256` for every public client (reject `plain`). Validate `state` on every authz code flow and `nonce` on every OIDC flow (bind nonce to the issued ID token). Enforce **exact** `redirect_uri` matching with no fragment. Rotate refresh tokens on every refresh and detect reuse. JWT `alg` allow-list per verifier (see [Cryptographic Failures](#cryptographic-failures)).
* **Token storage on clients.** Browsers: never store refresh tokens in `localStorage` / `sessionStorage`; use `HttpOnly; Secure; SameSite=Strict` cookies or the BFF pattern. Mobile: platform secret store (Keychain / Android Keystore), device-bound where supported.
* **Logout** invalidates the session server-side and revokes the associated refresh token. Implement `revocation_endpoint` (RFC 7009) and OIDC back-channel logout. "Log out everywhere" revokes every active token family for the principal.
* **Account recovery** doesn't use security questions. Recovery requires either an MFA factor or a magic link to a verified address, rate-limited per principal and per IP. After successful recovery, force MFA re-enrollment.
* **Step-up authentication.** Password change, MFA configuration changes, email change, key issuance, role grant — fresh credentials required regardless of session age. Email change notifies the **old** email and requires verification of the **new** email.

=== "Java stack"

    Password policies are enforced through `PolicyEnforcer` registered against `IdentityMgtEventListener.doPreUpdateCredential()`. The shipped defaults (`DefaultPasswordLengthPolicy` with `MIN_LENGTH=6`, `MAX_LENGTH=10`) are demo defaults — **production deployments must override** the registry per the rules above. Products handling personal data add a custom `PolicyEnforcer` consulting the HaveIBeenPwned k-Anonymity API at password-set time.

    MFA: authenticators in `carbon-identity-framework/components/authenticator/` (TOTP, FIDO2, SMS-OTP, Email-OTP). Adaptive authentication scripts select the second factor based on ACR / enrolled factors / risk signals.

    Account lockout: `IdentityMgtEventListener` + `AccountLockHandler`. Failed attempts tracked in `UserIdentityClaimsDO`; the `http://wso2.org/claims/identity/accountLocked` claim is set when the threshold is reached and consulted in `doPreAuthenticate()` before any credential check.

    OAuth: PKCE enforced at the authz request; `redirect_uri` exact match; refresh-token rotation with reuse detection emits a security event and revokes the token family.

=== "Go stack"

    Password hashing parameters from configuration (Argon2id or PBKDF2), not hard-coded constants. Store the algorithm name and parameters alongside the hash.

    OTP delivery is built around a short-lived signed session token rather than a server-side OTP store:

    ```go
    sessionData := common.OTPSessionData{
        Recipient:  otpDTO.Recipient,
        Channel:    otpDTO.Channel,
        OTPValue:   hash.GenerateThumbprintFromString(otp.Value), // hash, never plaintext
        ExpiryTime: otp.ExpiryTimeInMillis,
    }
    sessionToken, _ := s.createSessionToken(ctx, sessionData)
    ```

    PKCE accepts only `S256`; reject `plain` by construction:

    ```go
    if codeChallengeMethod != CodeChallengeMethodS256 {
        return ErrInvalidChallengeMethod
    }
    ```

    `redirect_uri` matches the registered values exactly. Refresh-token rotation issues a new token and invalidates the old; an invalidated-token presentation revokes the entire token family and emits a security event.

### Session Hijacking

Sessions are bound to a TLS-only `HttpOnly; Secure; SameSite=Lax` (or `Strict`) cookie; session identifiers are generated by a secure RNG. Logout invalidates server-side, not just by deleting the client cookie.

### Session Fixation

=== "Java stack"

    Carbon 4 pattern: `session.invalidate()`, then `request.getSession()` for a fresh session, then set the authenticated attribute on the new session. This sequence prevents an attacker from binding a victim to a known session id before login.

=== "Go stack"

    Issue a fresh session token after authentication; invalidate any prior token associated with the principal.

### Session Prediction

Use the platform's secure RNG (`SecureRandom.getInstanceStrong()` in Java, `crypto/rand` in Go) for session identifiers and CSRF / recovery / verification tokens. At least 128 bits of entropy.

---

## Software and Data Integrity Failures

**External references**

* [SLSA](https://slsa.dev/), [OWASP Deserialization](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html), [sigstore / cosign](https://docs.sigstore.dev/).

**Rules**

* Sign every release artefact (JAR, container, Helm chart, OS package) on protected infrastructure with a short-lived signing identity. Publish the signature next to the artefact and document verification in the install guide. Produce SHA-256 checksums alongside every release.
* Reference container images by digest, not by tag, in deployment manifests.
* Every CI workflow declares an explicit `permissions:` block scoped to the minimum. Avoid `pull_request_target` with secrets unless gated behind an approval step.
* Subresource Integrity (SRI) on any third-party JS or CSS loaded by URL from a CDN.
* API replay protection: sensitive write endpoints require a request-level `jti` or `nonce` and reject duplicates within a short window. Combine with a request expiry to bound replay attempts.
* Reject deserialisation of untrusted data into arbitrary types (see [Insecure Deserialization](#insecure-deserialization)).

=== "Java stack"

    Maven release pipelines run `maven-gpg-plugin` (or sigstore equivalent) producing `.asc` signatures next to each artefact; release notes publish SHA-256 checksums. Container images signed with cosign before push; deployment manifests reference images by digest. HMAC verification uses `MessageDigest.isEqual(byte[], byte[])` — never `Arrays.equals`.

=== "Go stack"

    Release-pipeline target shape (cosign signing not yet wired in current workflows — open hardening item):

    ```yaml
    - name: Sign release artefacts
      run: |
        for f in dist/*.zip; do
          cosign sign-blob --yes --bundle "${f}.cosign.bundle" "${f}"
          sha256sum "${f}" > "${f}.sha256"
        done
        cosign sign --yes "ghcr.io/.../${IMAGE}:${VERSION}"
    ```

    Webhook HMAC verification uses `hmac.Equal` — never `==`:

    ```go
    mac := hmac.New(sha256.New, sharedSecret)
    mac.Write(rawBody)
    expected := mac.Sum(nil)
    got, err := hex.DecodeString(r.Header.Get("X-Hub-Signature-256"))
    if err != nil || !hmac.Equal(expected, got) {
        http.Error(w, "invalid signature", http.StatusUnauthorized)
        return
    }
    ```

### Insecure Deserialization

External reference: [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html).

=== "Java stack"

    Use `ObjectInputFilter` (JEP 290, Java 9+) — for example `-Djdk.serialFilter=com.wso2.expected.**;!*` — to restrict the classes the JVM will deserialise. On older Java, subclass `ObjectInputStream` and override `resolveClass()` to allow-list expected classes. Mark sensitive fields `transient`. Prefer JSON/XML over Java serialisation for any cross-trust-boundary payload. Audit dependencies for known gadget libraries (Commons Collections, Spring Beans, Groovy).

    **Current audit:** multiple sites in identity-framework and registry components construct `ObjectInputStream` without `ObjectInputFilter` or `resolveClass()` override (workflow-mgt DAO, application-mgt DAO, `JavaSessionSerializer`, registry common utilities) — open hardening items.

    For inbound payloads that must remain dynamic (webhooks, plug-in config), require the producer to sign the payload, verify the signature, then construct the typed object.

=== "Go stack"

    Go's standard `encoding/json`, `encoding/xml`, `encoding/gob` don't reconstruct arbitrary types by default — typed DTOs are the safe path. For binary protocols (Protobuf, MessagePack), use the generated typed code, not generic decoders.

---

## Logging and Alerting Failures

**External references**

* [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html), [Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html).

### Operational logs vs audit logs

These are two different concerns and must be treated as such:

* **Operational logs** record what the code did, for debugging and incident triage. Short retention, standard log aggregator.
* **Audit logs** record what users and admins did, for security investigation and compliance. Long retention, append-only sink, stable schema, no stack traces or framework chatter.

In Carbon products, the audit log goes through a dedicated logger (`AUDIT_LOG`) wired to a separate appender. In a new Go service, the audit log goes through a dedicated `*slog.Logger` (e.g., a separate `audit` package) wired to its own handler.

### What must be in every audit event

| Field | Notes |
|---|---|
| `timestamp` | RFC 3339 with timezone; server clocks NTP-synchronised |
| `correlation_id` | Request id propagated across services |
| `tenant_id` | From the authenticated context, not from request input |
| `principal_id` | Authenticated user id; `null`/`anonymous` is a valuable signal |
| `principal_type` | `user` / `service_account` / `system` |
| `source_ip` | Resolved against trusted proxies, not the raw `X-Forwarded-For` |
| `user_agent` | Truncated if needed |
| `action` | Stable enum: `auth.login`, `iam.role.grant`, `key.rotate`, … |
| `target` | Object class and id (`api:foo`, `user:u-abc`); never the full object |
| `decision` | `allow` / `deny` / `error` |
| `reason` | Short code for `deny`/`error` (`mfa_required`, `account_locked`) |

### What never to log

Regardless of log level, regardless of intent:

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

Where a value needs to appear for correlation (e.g., a token id), log the **hash** or a **truncated prefix** with explicit ellipsis (`abcd1234…`) — never the full value.

### Required security events

Every one of these emits an audit event; alerts fire on the patterns marked **alert**:

* Authentication: success, failure, lockout (**alert** on N failures from one source in a window), MFA challenge issued, MFA failure, MFA success
* Authorisation: deny (**alert** on cross-tenant deny attempts), grant of a privileged role (**alert**)
* Password change, MFA enrolment / removal, email change, account recovery
* Token: issue, refresh, revoke (manual and automatic), reuse-detection trigger (**alert**)
* Key: read of a privileged key, rotate, revoke (**alert**)
* Configuration: change to a security setting (CORS allow-list, lockout thresholds, JWT issuers, federated IdPs) (**alert**)
* Administrative actions: tenant create / delete, user create / delete, role grant / revoke

### Retention and integrity

Audit logs are append-only at the sink (no in-place edits, no deletions during the retention window). Forward to a dedicated audit sink — separate from operational logs — and consider signing or hash-chaining log batches for tamper evidence. Retention is at least the SOC investigation window plus the compliance horizon (commonly 1 year for security events, longer for regulated data).

### Stack-specific logger usage

=== "Java stack"

    `log.error(message, throwable)` — the two-arg form captures the full stack and cause chain. `log.error("..." + e.getMessage())` is lossy. Carbon log layout supports the `%K` UUID token (Carbon 4.4.3+) so that forged log entries from log-injection attempts lack a valid UUID. Sensitive values are masked with local helpers — extend those rather than building ad-hoc redactors.

=== "Go stack"

    Logging through the project's structured logger (built on `log/slog`):

    ```go
    logger.ErrorContext(ctx, "token validation failed",
        slog.String("tenant", tenantID),
        slog.String("request_id", traceID),
        slog.Any("cause", err),
    )
    ```

    A central set of masking helpers is on the roadmap; until they land, redact at the call site explicitly. Reviewers must reject any logger call that interpolates secrets or PII into a message string.

Log at the failure boundary only. Avoid the "log every layer" anti-pattern — it produces unreadable traces and frequently leaks the same secret repeatedly.

### Insufficient Logging and Monitoring

The most common failure modes:

* Decisions logged at `DEBUG` rather than `INFO`/`AUDIT`, so they disappear from production
* Source IP read straight from `X-Forwarded-For` without proxy-trust evaluation
* Failure events logged but not aggregated into an alert
* PII masked in some paths and not others
* Audit logs and operational logs sharing a sink, so retention policy can't distinguish them

---

## Mishandling of Exceptional Conditions

**External references**

* [OWASP Improper Error Handling](https://owasp.org/www-community/Improper_Error_Handling), [CWE-703](https://cwe.mitre.org/data/definitions/703.html).

**Rules**

* Catch the **specific** exception type you can handle. Catching `Exception`, `Throwable`, `RuntimeException`, or using bare `recover()` for ordinary control flow hides bugs and disables compile-time discipline.
* On any exception during a security decision, default to deny. Initialise the decision variable to the safe value before `try`; never set it to the permissive value inside `catch`.
* At every external boundary (REST / SOAP / gRPC / JMS / scheduled job), install a centralised exception mapper. Sanitised response only — no stack traces, file paths, SQL fragments, class names, framework identifiers.
* Always release every resource an exception path could leak (JDBC, file handles, sockets, OSGi service refs, mutex locks, `ThreadLocal` entries, `CarbonContext` tenant flows).
* Log the original exception with its stack trace **server-side** using the canonical logger. Never log secrets or PII as part of an exception message.
* If the failing operation participated in a transaction, the cleanup rolls it back; never let an aborted operation commit.
* Avoid TOCTOU around exception handlers — re-validate state inside the recovery block.

=== "Java stack"

    **Catch typed exceptions**:

    ```java
    try {
        URITemplate uriTemplate = new URITemplate(uri);
    } catch (URITemplateException e) {
        String msg = "Error parsing URI " + uri;
        log.error(msg, e);
        throw new APIManagementException(msg, e);
    }
    ```

    The OSGi `BundleActivator.start(BundleContext)` / `stop(BundleContext)` pair is allowed to declare `throws Exception` — the framework expects bootstrap failures to surface.

    **Fail-secure** for authorisation decisions:

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

    **Centralised exception mapper** at REST/SOAP boundaries — `org.wso2.carbon.apimgt.rest.api.util.exception.GlobalThrowableMapper` builds an `ErrorDTO` (`code`, `message`, `description`, `moreInfo`) and decides server-side whether to log the full stack via per-error `ErrorHandler.printStackTrace()`. New REST modules follow this pattern.

    **Resource cleanup** — `try`-with-resources for any `AutoCloseable`:

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

    **Tenant cleanup is security-critical.** Carbon's tenant scoping is held in a `ThreadLocal`; if `PrivilegedCarbonContext.endTenantFlow()` is not called, the next request reused on the same thread runs with the previous tenant's identity. Always call `endTenantFlow()` from a `finally` block:

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

    Each `startTenantFlow` is paired with exactly one `endTenantFlow` on every path, including exception paths.

    **Anti-patterns reviewers must reject:**

    ```java
    try { riskyCall(); } catch (Exception ignored) {}            // swallow and continue
    try { riskyCall(); }                                          // lossy log
    catch (Exception e) { log.error("Something failed: " + e.getMessage()); }
    boolean allowed = true;                                       // fail open
    try { allowed = check(); }
    catch (Exception e) { log.warn("permission check failed", e); }
    ```

    Empty `catch` blocks are only acceptable for best-effort cleanup helpers (`closeQuietly`), and those helpers themselves log at `WARN`.

=== "Go stack"

    `panic` is reserved for unrecoverable initialisation failures. Use `error` returns for ordinary control flow. Recover from `panic` only at safe boundaries — request handlers, goroutine entry points, transaction wrappers — and convert to `error`:

    ```go
    defer func() {
        if p := recover(); p != nil {
            stack := string(debug.Stack())
            log.GetLogger().Error("panic during transaction",
                log.String("dbName", t.dbName),
                log.Any("panic", p),
                log.String("stack", stack),
            )
            if rbErr := tx.Rollback(); rbErr != nil {
                switch v := p.(type) {
                case error:
                    err = errors.Join(fmt.Errorf("transaction aborted: %w", v), rbErr)
                default:
                    err = errors.Join(fmt.Errorf("transaction aborted: %v", v), rbErr)
                }
            }
        }
    }()
    ```

    Wrap errors with `fmt.Errorf("...: %w", err)` to preserve the chain. Define sentinel errors at package level; inspect with `errors.Is` and `errors.As`. Never serialise a raw Go `error` into a client-facing JSON response. Define a canonical `ErrorResponse` envelope per service and translate at the handler layer only.

    `defer` cleanup immediately after acquisition:

    ```go
    tx, err := r.db.Begin()
    if err != nil {
        return err
    }
    defer tx.Rollback() // safe: Rollback is a no-op after Commit

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("upstream request failed: %w", err)
    }
    defer func() { _ = resp.Body.Close() }()
    ```

    Do not `defer` inside a loop — each iteration accumulates a deferred call that doesn't run until the function returns. Wrap the loop body in a closure if a per-iteration defer is genuinely needed.

    `context.Context` is the first parameter on every function that does I/O. Propagates cancellation, timeouts, and trace identity downstream. Never replace the incoming context with `context.Background()` mid-flight.

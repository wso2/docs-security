---
title: Secure Coding Guide — Go Stack
category: security-guidelines
version: 1.0
---

# Secure Coding Guide — Go Stack

<p class="doc-info">Version: 1.0</p>
___

This document is the WSO2-specific secure coding guide for the **Go-based products**. It assumes you are working in a greenfield service: there is no 10-year legacy to retrofit, so the modern pattern is the default and any deviation needs a documented reason.

Read [Secure Coding Principles]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/principles/) first — it lays out the rules every WSO2 engineer applies regardless of stack, and the public references (OWASP, NIST, RFCs, SLSA) every engineer is expected to know. This document does not repeat that material; it documents only the choices that are specific to WSO2's Go services.

Each section below maps to an OWASP Top 10 - 2025 category. The cross-stack mapping page is [OWASP Top 10 - 2025 Prevention]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/owasp-t10-2025-prevention/).

## Broken Access Control

**External references**

* [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
* [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
* [OWASP ASVS — V4 Access Control](https://owasp.org/www-project-application-security-verification-standard/)

**Specifics for the WSO2 Go stack**

Every protected path goes through authentication and authorisation middleware *before* the domain handler. On any failure the middleware writes the error response and stops the chain (`c.Abort()` in Gin, `return` after writing in `net/http`, an early-return error in the framework in use); falling through to the handler with a missing identity is a bug. A representative pattern (Gin shown; adapt to the router/framework actually in the service):

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

The public-vs-protected list is data, not code. Maintain a `permissions.go` (or equivalent) that enumerates every public path, and let the router treat anything not on the list as protected by default.

**Object-level access control (IDOR).** Path- and function-level access controls are necessary but not sufficient. Every operation that returns or modifies an object identified by an opaque or guessable id (`/orders/{id}`, `/tenants/{t}/secrets/{s}`) must additionally check that the authenticated principal owns or has permission on that specific object. Authorisation is **never** derived from the URL path or request body alone — those are user input.

The enforcement point is the store/repository layer: every query carries the tenant id (and user/owner id where applicable) as a predicate, and the store refuses to return rows that don't match. The handler/service layers extract the principal from `context.Context`; they do not pass id values from the URL through to the store without a tenant-bound predicate. See [OWASP API1:2023 — Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/).

#### Object property-level access control (mass assignment)

External reference: [OWASP API3:2023 — Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/).

Even after the principal is allowed to operate on an object, not every property on that object is theirs to read or write. The two-sided failure mode:

* **On read** — serialising a domain struct directly to the response can leak fields the principal must not see. Define a typed `Response` DTO with explicit JSON tags and project from the domain struct field-by-field; do not write `json.Marshal(entity)`.
* **On write** — accepting an open property bag on update lets an attacker slip extra fields (`{"role": "admin"}` into a profile update). The defence is two-layered: (1) `json.Decoder.DisallowUnknownFields()` rejects unknown fields ([Input validation](#input-validation)); (2) the service layer maps `Request` DTO fields onto the entity field-by-field, never `reflect`-based whole-struct copying.

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

// Service layer maps explicitly, never reflectively
func (s *userService) Update(ctx context.Context, id string, req UpdateUserRequest) (*UpdateUserResponse, error) {
    u, err := s.store.Get(ctx, id)
    if err != nil { return nil, err }
    u.DisplayName = req.DisplayName
    u.Locale = req.Locale
    if err := s.store.Save(ctx, u); err != nil { return nil, err }
    return &UpdateUserResponse{ID: u.ID, DisplayName: u.DisplayName, Locale: u.Locale, UpdatedAt: u.UpdatedAt}, nil
}
```

Where the service is multi-tenant, tenant identity is carried in `context.Context` via a typed key — never a `string` key (which collides with any other package's `string`-keyed value), never a request header read inside the data layer. A reasonable shape:

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

A current code audit shows this pattern is not yet uniformly adopted across the WSO2 Go services — each new service should add the helpers as it introduces tenant scope. The data layer refuses to execute if the tenant is missing; defaulting to a "super tenant" or the empty string is a cross-tenant data exposure, not a convenience.

## Security Misconfiguration

**External references**

* [OWASP Configuration Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Web_Service_Security_Cheat_Sheet.html)
* [Mozilla TLS configuration generator](https://ssl-config.mozilla.org/)
* [RFC 8446 — TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)

**Specifics for the WSO2 Go stack**

Configuration loads from the project's central config package, which merges defaults with operator overrides and refuses to start if a required value is missing. Defaults must be safe to deploy unchanged. Specifically:

* `MinVersion: tls.VersionTLS12` (preferring TLS 1.3 where available) on every outbound HTTP client and every server `tls.Config`. The shape from production code:

  ```go
  tlsConfig := &tls.Config{
      MinVersion: tls.VersionTLS12,
      ServerName: host,
  }
  ```

  `InsecureSkipVerify` is acceptable **only** when it is read from operator-supplied configuration with a secure default of `false`, narrowly documented (e.g., a single integration-test flag, a dev-mode self-signed certificate path). Hardcoded `InsecureSkipVerify: true` in production code is a defect. A current audit of the WSO2 Go services found ~48 production occurrences across multiple repos; some are operator-config driven and acceptable, others should be removed or gated behind a documented flag — flag each at code review and require justification.

* Debug endpoints, profiling endpoints (`/debug/pprof`), and verbose error responses are off in production builds — typically gated behind a build tag or a config flag whose default is `false`.
* CORS origins are an explicit allow-list. Never `Access-Control-Allow-Origin: *` on an endpoint that accepts credentials.
* Container manifests set `runAsNonRoot: true`, drop all capabilities, and use a read-only root filesystem. Anything else needs justification.

Test code may use `InsecureSkipVerify: true` for self-signed certificates, but reviewers must reject any non-test occurrence.

#### HTTP security headers — modern baseline

A new Go service must ship every protected response with the following set, applied in middleware, not per-handler:

| Header | Value (default) | Notes |
|---|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | Add `preload` only after the full hostname tree is HTTPS-only |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self' 'nonce-{n}'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'` | Nonce-based; no `'unsafe-inline'`, no `'unsafe-eval'`; relax `frame-ancestors` only with an explicit allow-list |
| `X-Content-Type-Options` | `nosniff` | Everywhere |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Stricter (`no-referrer`) for admin and token-bearing surfaces |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=(), payment=(), interest-cohort=()` | Deny features the service doesn't use |
| `Cross-Origin-Opener-Policy` | `same-origin` | Required for cross-origin isolation; mandatory on auth UIs |
| `Cross-Origin-Embedder-Policy` | `require-corp` | Required alongside COOP for cross-origin isolation |
| `Cross-Origin-Resource-Policy` | `same-site` | For responses not intended for cross-origin embedding |
| `Cache-Control` | `no-store` on token/PII responses | Don't let CDNs or browsers cache personal or credential data |
| `Clear-Site-Data` | `"cache", "cookies", "storage"` on logout | Wipes client state on session end |

Cookies that carry authentication or session state are `HttpOnly; Secure; SameSite=Strict; Path=<narrow>`. Do not set `Domain` unless cross-subdomain sharing is required; if it is, document why.

Anti-patterns to reject in review: any of the headers above missing from the middleware chain, `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`, server banners disclosing the Go version or framework.

#### Container security defaults

External reference: [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/).

Every container image and pod manifest ships with:

* Image: distroless or minimal base — no shell, no package manager, no unnecessary binaries.
* Pod-level: `runAsNonRoot: true`, `runAsUser`/`runAsGroup`/`fsGroup` non-zero, `seccompProfile.type: RuntimeDefault`, `automountServiceAccountToken: false` unless the pod talks to the K8s API.
* Container-level: `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: ["ALL"]`. Use `emptyDir` for temp / log paths.
* Image pull by digest (`image: ghcr.io/...@sha256:...`), not by tag.
* CPU and memory requests and limits on every container.
* `NetworkPolicy` default-deny in every namespace; add explicit allow policies per service.
* `PodDisruptionBudget` for critical workloads.

Never `privileged: true`, `hostNetwork: true`, `hostPID: true`, `hostIPC: true`, or `hostPath` volumes.

#### API inventory, versioning, deprecation

External reference: [OWASP API9:2023 — Improper Inventory Management](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/).

An API endpoint that exists but is not in the published inventory ("shadow API") is the most common attack surface — same code, less monitoring, often older auth checks. For a greenfield Go service:

* Every endpoint has a registered owner, a stable version (in the URL path or via a header), and an explicit lifecycle (active / deprecated / retired). The published OpenAPI spec is the source of truth; the router is generated from the spec, or a CI check fails the build if a handler exists that isn't in the spec.
* Deprecation emits a `Sunset:` header (RFC 8594) and an audit event on every call after the sunset date.
* Non-production environments (dev, staging) live on different hostnames and are not reachable from the public internet. Internal-only endpoints bind to internal networks (Kubernetes `ClusterIP` services + NetworkPolicy, not `LoadBalancer`).
* The inventory is reviewed quarterly; entries with zero recent calls are scheduled for retirement.
* On a major version bump, the retirement of the previous version is planned at the same time — versions do not accumulate forever.

#### Default credentials, sample applications, management endpoints

Default credentials are rotated before the service is exposed. Sample applications, demo data, debug endpoints (`/debug/pprof`), profiling, and admin/management endpoints bind to localhost or to an internal network — never to the public ingress. Strip server banners; don't return version-disclosing headers (`X-Powered-By`, `Server: <framework>/<version>`).

## Software Supply Chain Failures

**External references**

* [SLSA framework](https://slsa.dev/)
* [OWASP Software Component Verification Standard](https://owasp.org/www-project-software-component-verification-standard/)
* WSO2 [incident clarifications]({{#base_path#}}/security-announcements/incident-clarifications/) — the npm and axios incidents demonstrate what happens to deployments that diverge from the official baseline.

**Specifics for the WSO2 Go stack**

`go.sum` is committed alongside every `go.mod` change. CI runs with `GOFLAGS=-mod=readonly`; a PR that modifies `go.mod` without updating `go.sum` fails the build, and one that modifies either without an explicit dependency-approval label is blocked by the manifest-guard workflow:

```yaml
on:
  pull_request_target:
    paths:
      - '**/go.mod'
      - '**/go.sum'
env:
  GOFLAGS: "-mod=readonly"
```

`replace` directives in `go.mod` are review-required changes. By default, do not use them.

Frontend modules shipped alongside Go services pin their entire dependency graph via the workspace catalog plus lock file (`pnpm install --frozen-lockfile` in CI). Never use `^` or `~` ranges in `package.json` for production builds.

For deployments inside customer networks, document the required `GOPROXY` value — an internal mirror, never `direct`. `direct` bypasses the integrity-friendly proxy and reaches upstream VCS endpoints that may not be reproducible.

#### Unsafe consumption of upstream APIs

External reference: [OWASP API10:2023 — Unsafe Consumption of APIs](https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/).

The supply-chain risk extends beyond the module tree. Every upstream service the code calls (federated IdPs, payment processors, partner APIs, internal microservices) is an integration the attacker can target either by compromising the upstream or by abusing the integration's trust. Treat every upstream response as untrusted input:

* **Validate the response before parsing it.** Check the HTTP status, `Content-Type`, content length, and schema against what the integration declared. Reject anything that doesn't match — an upstream that suddenly returns HTML when JSON is expected is a signal, not a value to pass through.
* **Apply the same TLS rules outbound as inbound** — `MinVersion: tls.VersionTLS12`, no `InsecureSkipVerify`, certificate pinning for high-trust upstreams.
* **Bound every upstream call.** Set a per-request timeout via `context.WithTimeout`; use a circuit breaker (e.g., `sony/gobreaker` or equivalent) on consecutive failures so a misbehaving upstream cannot consume goroutines or sockets indefinitely. Apply `http.MaxBytesReader` to the response body before decoding.
* **Never trust an upstream-issued JWT's `alg`, `kid`, or claims without verification.** Verify the signature against the upstream's published JWKS, restrict `alg` in the keyfunc to a known-good allow-list, validate `iss` / `aud` / `exp` / `nbf`. Treat the JWKS URL as a configured trust anchor — never something the upstream tells you to fetch at runtime.
* **Where an upstream's behaviour change could weaken your security posture** (a federated IdP drops MFA, a KMS drops an algorithm), build an explicit assumption-check that fails loudly rather than silently accepting the new behaviour.

## Cryptographic Failures

**External references**

* [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
* [NIST SP 800-131A — algorithm transitions](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final)
* [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
* [RFC 8725 — JWT Best Current Practice](https://datatracker.ietf.org/doc/html/rfc8725)

**Specifics for the WSO2 Go stack**

Go through the project's central crypto helper package — never call `crypto/aes`, `crypto/rsa`, or `crypto/sha256` directly from product code. Each WSO2 Go service should expose a single helper package that dispatches by algorithm and pins the safe primitives; for the API platform, `pkg/encryption/manager.go` plus algorithm-specific providers under `pkg/encryption/<alg>/` is the established shape. New services should follow the same pattern rather than scatter `crypto/aes` calls across handlers.

A representative implementation:

```go
switch params.Algorithm {
case AlgorithmAESGCM:
    return encryptAESGCM(key.([]byte), content)
case AlgorithmRSAOAEP256:
    return encryptRSAOAEP256(key.(*rsa.PublicKey), content)
}
```

The AES-GCM implementation generates a fresh random nonce per call and prepends it to the ciphertext:

```go
nonce := make([]byte, aesgcm.NonceSize())
if _, err := rand.Read(nonce); err != nil {
    return nil, fmt.Errorf("failed to generate nonce: %w", err)
}
return aesgcm.Seal(nonce, nonce, plaintext, nil), nil
```

Never reuse `key + nonce`. Do not "optimise" the nonce by deriving it from a counter.

Password hashing parameters are configuration, never hard-coded constants. Argon2id (memory ≥ 19 MiB, iterations ≥ 2, parallelism ≥ 1, key size 32 bytes) or PBKDF2-HMAC-SHA256 (≥ 600 000 iterations, 32-byte salt) are the accepted options. Store the algorithm name and parameters alongside the hash so that tightening the defaults causes a re-hash on the next successful authentication.

For JWT verification, restrict the accepted algorithm at parse time inside the keyfunc — never trust the algorithm declared in the token header:

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

Refuse `alg: none`, refuse HMAC algorithms wherever the verifier holds an asymmetric public key (alg-confusion), validate `iss`, `aud`, `exp`, `nbf`, `iat` on every verification, and look the key up by `kid` from a JWKS cache — never honour an inline `jwk` header.

## Injection

**External references**

* [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
* [OWASP LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)
* [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
* [OWASP Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

**Specifics for the WSO2 Go stack**

#### Input validation

External reference: [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html).

Validation is the first defence in front of every injection sink. For Go services, the baseline is:

* **Typed DTOs everywhere.** Decode request bodies into typed structs, never into `map[string]any` for production handlers. Pair structs with `go-playground/validator` tags (`validate:"required,min=1,max=64,alphanum"`) and run validation before passing the DTO to the service layer.
* **Refuse unknown fields.** `dec := json.NewDecoder(r.Body); dec.DisallowUnknownFields()`. Refusing unknown fields stops most "mass assignment" bugs and silently-ignored malformed input.
* **Bounded reading.** `http.MaxBytesReader(w, r.Body, maxBodySize)` on every handler that reads a body. Set per-endpoint maxima (a config endpoint has a much smaller limit than a file upload).
* **Length and range on every field.** Validator tags enforce `min` / `max` for strings, numbers, slices, and maps. Even free-text fields get a maximum length (e.g., 4 KB).
* **Allow-list, not deny-list.** Define what's allowed (`oneof=foo bar baz`, `alphanum`, custom regex with bounded complexity); reject anything that doesn't match.
* **Canonicalise before validating.** Unicode-normalise (`golang.org/x/text/unicode/norm` NFKC), percent-decode where the field is URL-encoded, strip null bytes (`\x00`), reject embedded CR/LF before any allow-list check.
* **JSON parsing limits.** `json.Decoder` does not enforce depth or numeric size limits; for adversarial input wrap with a length-limited reader, and reject documents above a configured depth via a manual decode if necessary.

```go
type CreateAppRequest struct {
    Name        string   `json:"name"        validate:"required,min=1,max=128,alphanumunicode"`
    Description string   `json:"description" validate:"omitempty,max=4096"`
    Scopes      []string `json:"scopes"      validate:"max=32,dive,oneof=read write admin"`
}

func handleCreateApp(w http.ResponseWriter, r *http.Request) {
    r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
    dec := json.NewDecoder(r.Body)
    dec.DisallowUnknownFields()
    var req CreateAppRequest
    if err := dec.Decode(&req); err != nil {
        writeBadRequest(w, "invalid request body")
        return
    }
    if err := validate.Struct(req); err != nil {
        writeBadRequest(w, formatValidationError(err))
        return
    }
    // ... rest of handler
}
```

#### Sink-specific rules

* **SQL**: only `database/sql` (or a typed wrapper around it) with placeholder-based queries. Never `fmt.Sprintf` user input into a query string. For dynamic column or order-by values, validate against a server-side allow-list before composing the statement.

  ```go
  // Good
  row := db.QueryRowContext(ctx, "SELECT id, name FROM users WHERE tenant = $1 AND id = $2", tenantID, userID)
  ```

* **OS commands**: use `exec.CommandContext(ctx, "binary", arg1, arg2)` with separate arguments. Never shell out via `sh -c` or `bash -c` with interpolated input. If a shell is genuinely required, treat the command string as untrusted by construction and escape with `shellescape` or equivalent.

  ```go
  // Anti-patterns — reject in code review
  exec.CommandContext(ctx, "sh", "-c", "convert "+userFilename+" out.png")   // shell with interpolation
  exec.CommandContext(ctx, "/bin/sh", "-c", fmt.Sprintf("convert %s out.png", userFilename))

  // Safe — argument slots, no shell
  cmd := exec.CommandContext(ctx, "convert", userFilename, "out.png")
  cmd.Stdin = nil
  out, err := cmd.CombinedOutput()
  ```
* **HTML output**: render with `html/template`, never `text/template`. The auto-escaping is per-context (HTML attribute vs. script vs. URL) and gets it right only when the template type matches the output type.
* **LDAP**: use the project's LDAP helper, which applies RFC 4515 escaping to filter values. Do not concatenate user-supplied strings into LDAP filters.
* **Logs**: strip CR/LF from any user-controlled value before logging (see Logging and Alerting Failures below).

#### Other injection classes

* **Server-Side Template Injection (SSTI)**: `text/template` does not HTML-escape; never use it to render HTML to a browser. Use `html/template` and pass user data as parameters, not as part of the template source. No code path compiles a template from user input.
* **NoSQL injection**: use the driver's structured query API (typed filters, BSON documents for MongoDB), never `fmt.Sprintf` user input into a JSON query.
* **GraphQL** (where present): disable schema introspection in production, set a query depth limit (e.g., 10), set a query complexity limit, treat every field resolver as an authorisation point.
* **Regex DoS**: Go's `regexp` package uses RE2 (linear time, no backtracking), which is safe by design — but pattern compilation from user input is still rejected, and input length is still bounded before matching to cap memory.
* **Email header injection**: when sending email, strip CR/LF from any field substituted into a header, validate `To`/`From` as RFC 5322 addresses, and prefer libraries that build headers programmatically over string formatting.

## Insecure Design

**External references**

* [OWASP Threat Modeling Process](https://owasp.org/www-community/Threat_Modeling_Process)
* [OWASP Proactive Controls C1 — Define Security Requirements](https://owasp.org/www-project-proactive-controls/)
* [WSO2 Secure Software Development Process]({{#base_path#}}/security-processes/secure-software-development-process/) — for when a STRIDE-LM design review is required.

**Specifics for the WSO2 Go stack**

* Document the trust model in the project's `ARCHITECTURE.md`. List every public path explicitly; anything not on the list is protected by default.
* Encode operation-level security as declarative data — JWT requirement, scopes, rate limits — in the API specification, not in handler code. Reviews and audits then diff the spec, not the implementation.
* Model long-running workflows as explicit state machines: a typed `State` enum, a transition table, persistence keyed on `(instance_id, current_state)` with optimistic locking to prevent concurrent advances.
* Protect shared mutable state with `sync.Once` for one-time initialisation, `sync.RWMutex` for high-throughput maps, and database-side uniqueness (`INSERT ... ON CONFLICT DO NOTHING`) for idempotency rather than in-memory check-then-write.
* Rate-limit at middleware, not per handler. The policy is per-user **and** per-IP **and** global — not just one of those. Account lockout, IP throttling, and CAPTCHA escalation are reviewed at design time, not retrofitted after an incident.
* Inputs are decoded into typed DTOs at the handler, the tenant identifier is read from the authenticated context at the service, and the store refuses queries that do not include the tenant predicate. The layered re-check is the defence against confused-deputy bugs.
* **Pagination, list limits, and resource ceilings.** Every list endpoint paginates with a server-enforced maximum page size (typically 100–1000). Total counts on every page are returned only where the table is small enough to scan cheaply — otherwise return `hasMore` and let callers page until empty. Operations that could touch unbounded data (full-table scans, deep graph traversal) require an admin role or a deliberate batch-job path. Per-tenant ceilings (queries-per-minute, max stored objects, max attachment size) prevent one tenant from exhausting shared resources. Reject `limit=` parameters above the configured maximum at the handler; do not trust caller-supplied page sizes.

#### Sensitive business flows and anti-automation

External reference: [OWASP API6:2023 — Unrestricted Access to Sensitive Business Flows](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/).

Some flows are technically a legal sequence of API calls but the business model breaks if they are automated: signup, password reset, OTP send/verify, MFA enrolment, refund initiation, gift-code redemption, free-tier resource creation, comment posting. The defence is per-flow, not per-request:

* Identify sensitive flows at design time. They get explicit names and the list is reviewed at design review.
* For each, apply a layered budget in middleware: per-user, per-device, per-IP, per-tenant, plus a global ceiling.
* Combine velocity-based limits with behavioural signals — CAPTCHA challenge after the first few failures, device fingerprinting, anomaly detection on velocity from one source. Account lockout (see [Authentication Failures](#authentication-failures)) is the auth-specific instance of the same pattern.
* Every sensitive-flow invocation emits an audit event ([Logging and Alerting Failures](#logging-and-alerting-failures)). The SOC has alerts on velocity anomalies for the highest-value flows (signup spikes, password-reset volume, MFA-disable attempts).

## Authentication Failures

**External references**

* [NIST SP 800-63B — Authentication and Lifecycle Management](https://pages.nist.gov/800-63-3/sp800-63b.html)
* [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/rfc9700)
* [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
* [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

**Specifics for the WSO2 Go stack**

OTP delivery is built around a short-lived signed session token rather than a server-side OTP store. The OTP is generated, hashed, and embedded in a session JWT issued to the client. On verification the server recomputes the hash from the supplied code and compares:

```go
sessionData := common.OTPSessionData{
    Recipient:  otpDTO.Recipient,
    Channel:    otpDTO.Channel,
    OTPValue:   hash.GenerateThumbprintFromString(otp.Value), // hash, never plaintext
    ExpiryTime: otp.ExpiryTimeInMillis,
}
sessionToken, _ := s.createSessionToken(ctx, sessionData)
```

The pattern carries two guarantees: the OTP is never stored or transmitted in clear after generation, and the session is bound to a single attempt window.

For OAuth 2.0:

* PKCE accepts **only** `S256`. Reject `plain` by construction.

  ```go
  if codeChallengeMethod != CodeChallengeMethodS256 {
      return ErrInvalidChallengeMethod
  }
  ```

* `redirect_uri` matches the registered values **exactly**. No prefix match, no substring match, no fragment, no trailing-slash inference.
* On every refresh, issue a new refresh token and invalidate the old one. If a request later presents an invalidated token, revoke the entire token family and emit a security event. Refresh token rotation without reuse detection adds latency and no security.
* Validate `state` on every authorisation code flow; validate `nonce` on every OIDC flow and bind it to the issued ID token.

**Token storage on clients.** When the Go service serves a browser app or a mobile app:

* **Browsers**: never store refresh tokens or long-lived access tokens in `localStorage` / `sessionStorage` — they are accessible to any script and leak via XSS. Use `HttpOnly`, `Secure`, `SameSite=Strict` cookies, or the BFF (backend-for-frontend) pattern where the SPA never holds the long-lived credential.
* **Mobile apps**: use the platform secret store (Keychain on iOS, Android Keystore). Refresh tokens are device-bound where the platform supports it.

**Logout and session termination.** Logout invalidates the session server-side and revokes the associated refresh token. Implement `revocation_endpoint` (RFC 7009) and OIDC back-channel logout so relying parties end their sessions too. "Log out everywhere" is a first-class operation that revokes every active token family for the principal.

**Account recovery.** Don't use security questions. Use a recovery flow that requires either an MFA factor or a magic link sent to a verified address, rate-limited per principal and per IP. After successful recovery, force MFA re-enrollment.

**Sensitive operations require fresh authentication (step-up).** Password change, MFA configuration changes, email change, key issuance, role grant: fresh credentials are required regardless of session age. Email change in particular notifies the **old** email and requires verification of the **new** email before the change takes effect.

## Software and Data Integrity Failures

**External references**

* [SLSA framework](https://slsa.dev/)
* [sigstore / cosign](https://docs.sigstore.dev/)
* [Securing GitHub Actions](https://docs.github.com/en/actions/security-guides)

**Specifics for the WSO2 Go stack**

* Reference container images by digest, not by tag, in deployment manifests. The release pipeline should record the digest in the release notes; deployment manifests pin that digest. The target shape:

  ```yaml
  image:
    registry: ghcr.io/.../<image>
    digest: sha256:0e1f3c…
    pullPolicy: IfNotPresent
  ```

  *Current state:* the WSO2 Go services do not yet consistently emit or consume image digests in deployment manifests. New deployments and Helm charts should adopt the digest form; existing tag-based references are a known gap to close.

* Sign every release artefact — ZIP/tarball, container image, Helm chart — with cosign in the release workflow, using a sigstore identity tied to the workflow's OIDC token (no long-lived signing keys). Attach the signature next to the artefact and document `cosign verify` in the install guide. The target workflow shape:

  ```yaml
  - name: Sign release artefacts
    run: |
      for f in dist/*.zip; do
        cosign sign-blob --yes --bundle "${f}.cosign.bundle" "${f}"
        sha256sum "${f}" > "${f}.sha256"
      done
      cosign sign --yes "ghcr.io/.../${IMAGE}:${VERSION}"
  ```

  *Current state:* cosign signing is not yet wired into WSO2 Go release workflows. Adopt it on the next workflow revision; in the interim, publish SHA-256 checksums alongside each release artefact so customers have at least integrity verification.

* Every CI workflow declares an explicit `permissions:` block scoped to what it needs. A linter workflow does not need `packages: write`. A release workflow does.
* Avoid `pull_request_target` for workflows that handle secrets unless the workflow gates execution behind an approval label. The standard `pull_request` trigger runs PR code without secrets and is the safe default.
* For frontends served by the Go service that load third-party JS or CSS by URL from a CDN, set [Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity): `<script src="…" integrity="sha384-…" crossorigin="anonymous">`. If the CDN URL is dynamic, host the resource from a domain the team controls instead.
* **API replay protection**: sensitive write endpoints (key issuance, role grant, financial operations) require a request `nonce` (or JWT `jti`) and reject duplicates within a short window (typically 5 minutes). Combine with a request expiry on the envelope to bound replay attempts.
* For inbound webhooks and auto-update channels, verify the HMAC **before** parsing the payload. Use `hmac.Equal` for the comparison — never `==`:

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

## Logging and Alerting Failures

**External references**

* [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
* [OWASP Logging Vocabulary Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html)

**Specifics for the WSO2 Go stack**

Logging goes through the project's structured logger, built on Go's `log/slog`. Emit structured fields, not concatenated strings, and include request/tenant/trace identifiers from `context.Context`:

```go
logger.ErrorContext(ctx, "token validation failed",
    slog.String("tenant", tenantID),
    slog.String("request_id", traceID),
    slog.Any("cause", err),
)
```

Log at the failure boundary — the handler or the repository where the error stops — not at every layer the error passes through. The "log every layer" pattern produces unreadable traces and frequently leaks the same secret repeatedly.

#### Operational logs vs audit logs

These are two different concerns and should be treated as such:

* **Operational logs** record what the code did, for debugging and incident triage. Short retention, standard log aggregator.
* **Audit logs** record what users and admins did, for security investigation and compliance. Long retention, append-only sink, stable schema, no stack traces, no framework chatter.

In a new Go service, the audit log goes through a dedicated `*slog.Logger` (e.g., a separate `audit` package) wired to its own handler so the operational and audit streams have independent retention and forwarding.

#### What must be in every audit event

| Field | Notes |
|---|---|
| `timestamp` | RFC 3339 with timezone; server clocks NTP-synchronised |
| `correlation_id` | Request id propagated through `context.Context` |
| `tenant_id` | From the typed context key, not from request input |
| `principal_id` | Authenticated user id; `anonymous` is itself a valuable signal |
| `principal_type` | `user` / `service_account` / `system` |
| `source_ip` | Resolved against trusted proxies, not the raw `X-Forwarded-For` |
| `user_agent` | Truncated if needed |
| `action` | Stable enum: `auth.login`, `iam.role.grant`, `key.rotate`, … |
| `target` | Object class and id (`api:foo`, `user:u-abc`); never the full object |
| `decision` | `allow` / `deny` / `error` |
| `reason` | Short code for `deny` / `error` (e.g. `mfa_required`, `account_locked`) |

#### What never to log

Treat the following as **never log**, regardless of log level, regardless of intent:

* Passwords, password hints, recovery answers
* Access tokens, refresh tokens, ID tokens, OAuth `code`, OAuth `state`, OAuth client secrets
* Session identifiers, CSRF tokens, signed-URL signatures
* API keys, bearer tokens, webhook secrets
* Encryption keys, private keys, symmetric key material, key passphrases
* MFA secrets (TOTP seeds), backup codes, recovery codes
* Plaintext PII beyond the principal id required for audit — full address, phone, date of birth, identity numbers, financial account numbers, health information, biometric data
* Full request bodies, full response bodies, full HTTP headers for endpoints that handle credentials
* Stack traces in user-facing responses (server-side only)
* Internal hostnames, internal IPs, file paths, environment variables

Where a value needs to appear in logs for correlation (e.g., a token id), log the **hash** or a **truncated prefix** with explicit ellipsis (`abcd1234…`) — never the full value. A central set of masking helpers is on the roadmap; until they land, redact at the call site explicitly.

#### Required security events

Every one of these emits an audit event; an alert fires on the patterns marked **alert**:

* Authentication: success, failure, lockout (**alert** on N failures from one source in a window), MFA challenge issued, MFA failure, MFA success
* Authorisation: deny (**alert** on cross-tenant deny attempts), grant of a privileged role (**alert**)
* Password change, MFA enrolment / removal, email change, account recovery
* Token: issue, refresh, revoke (manual and automatic), reuse-detection trigger (**alert**)
* Key: read of a privileged key, rotate, revoke (**alert**)
* Configuration: change to a security setting (CORS allow-list, lockout thresholds, JWT issuers, federated IdPs) (**alert**)
* Administrative actions: tenant create / delete, user create / delete, role grant / revoke

#### Retention and integrity

Audit logs are append-only at the sink (no in-place edits, no deletions during the retention window). Forward to a dedicated audit sink — separate from operational logs — and consider signing or hash-chaining log batches for tamper evidence. Retention is set per the operating-team policy and is at least the SOC investigation window plus the compliance horizon (commonly 1 year for security events, longer for regulated data).

## Mishandling of Exceptional Conditions

**External references**

* [OWASP Improper Error Handling](https://owasp.org/www-community/Improper_Error_Handling)
* [CWE-703 — Improper Check or Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/703.html)

**Specifics for the WSO2 Go stack**

`panic` is reserved for unrecoverable initialisation failures. Use `error` returns for ordinary control flow. Recover from `panic` only at safe boundaries — request handlers, goroutine entry points, and transaction wrappers — and convert the recovered value to an `error`:

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

Wrap errors with `fmt.Errorf("...: %w", err)` to preserve the chain. Define sentinel errors at package level and inspect with `errors.Is`; use `errors.As` for typed errors. Never serialise a raw Go `error` into a client-facing JSON response — `err.Error()` typically contains the wrapped chain, including file paths and driver-level messages. Define a canonical `ErrorResponse` envelope per service and translate at the handler layer only.

For resources, `defer` cleanup immediately after acquisition:

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

Do not put `defer` inside a loop — each iteration accumulates a deferred call that does not run until the function returns. Wrap the loop body in a closure if a per-iteration defer is genuinely needed.

`context.Context` is the first parameter on every function that does I/O. It propagates cancellation, timeouts, and trace identity downstream. Never replace the incoming context with `context.Background()` mid-flight.

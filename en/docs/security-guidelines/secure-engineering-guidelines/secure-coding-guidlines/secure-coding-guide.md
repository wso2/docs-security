---
title: Secure Coding Guide
category: security-guidelines
version: 4.1
---

# Secure Coding Guide

<p class="doc-info">Version: 4.1</p>
___

When you write code for a WSO2 product, follow this guide. Each section opens with the canonical external reading (OWASP, NIST, RFCs), then lists what's WSO2-specific: named helpers to use, default configurations to override, anti-patterns to avoid, and stack-specific call shapes. For the general "what and why" of a category, follow the external links.

**How to read this guide.** Click the tab for your stack (**Java stack** for Carbon-based products, **Go stack** for the new Go-based products). Material remembers your choice across the site.

**Companion pages.**

* [OWASP Top 10 - 2025 Prevention]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/owasp-t10-2025-prevention/) — mapping table to the sections below.
* [OWASP API Security Top 10 - 2023 Prevention]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/owasp-api-top10-2023-prevention/) — API-specific mapping.
* [General Recommendations for React Secure Coding]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-react-secure-coding/) — frontend specifics.
* [Tooling Recommendations for Secure Coding]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/tooling-recommendations-for-secure-coding/).

## Canonical external references

Read these once; we link back to specific entries throughout this guide instead of restating them.

* General: [OWASP Top 10](https://owasp.org/Top10/), [OWASP API Security Top 10](https://owasp.org/API-Security/), [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/), [OWASP Proactive Controls](https://owasp.org/www-project-proactive-controls/), [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/), [CWE Top 25](https://cwe.mitre.org/top25/).
* Identity and OAuth: [NIST SP 800-63](https://pages.nist.gov/800-63-3/), [RFC 9700 — OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/rfc9700), [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636), [RFC 8725 — JWT BCP](https://datatracker.ietf.org/doc/html/rfc8725), [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html).
* Cryptography and transport: [NIST SP 800-131A](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final), [NIST SP 800-52](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final), [NIST SP 800-57](https://csrc.nist.gov/projects/key-management), [Mozilla TLS config generator](https://ssl-config.mozilla.org/).
* Supply chain: [SLSA](https://slsa.dev/), [OWASP SCVS](https://owasp.org/www-project-software-component-verification-standard/), [OpenSSF Best Practices](https://www.bestpractices.dev/), [CycloneDX](https://cyclonedx.org/), [SPDX](https://spdx.dev/).
* WSO2 internal: [Secure Software Development Process]({{#base_path#}}/security-processes/secure-software-development-process/) · [Vulnerability Management]({{#base_path#}}/security-processes/vulnerability-management-process/) · [Cloud Security Process]({{#base_path#}}/security-processes/cloud-security-process/) · [Security Reporting]({{#base_path#}}/security-reporting/report-security-issues/) · [Incident clarifications]({{#base_path#}}/security-announcements/incident-clarifications/).

## Principles specific to WSO2 product code

The general principles (defence in depth, fail secure, least privilege, deny by default, secure defaults, no security through obscurity) are covered in [OWASP Proactive Controls](https://owasp.org/www-project-proactive-controls/). The principles that are *not* obvious from external references and must be applied when writing WSO2 product code:

1. **Tenant identity rides in context, never in caller input.** Carbon's `PrivilegedCarbonContext` in Java; a typed `context.Context` key in Go. Reading tenant id from a header, query parameter, or request body is wrong by construction.
2. **Re-check authorisation at the data layer.** The store layer carries tenant and owner predicates on every query and refuses to return non-matching rows; handler-level checks alone are insufficient.
3. **Centralise crypto behind audited helpers.** Carbon's `CryptoUtil`; the project's central `pkg/encryption/manager.go` shape in Go. Never call `Cipher.getInstance` / `crypto/aes` directly from product code.
4. **Configuration is code.** Security-relevant settings (CORS allow-lists, lockout thresholds, JWT issuers, federated IdPs, log layouts) are version-controlled and reviewed.

---

## Broken Access Control

External: [OWASP A01](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) · [Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) · [Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html).

### Object-level access control (IDOR)

External: [OWASP API1:2023](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/).

The enforcement point is the data layer, not the handler.

=== "Java stack"

    Read tenant id from `PrivilegedCarbonContext` and add it as a query parameter to every repository query; the repository refuses rows whose tenant does not match. Anti-pattern: a handler-level "is this id in the user's allowed list?" check — doubles query cost and creates a TOCTOU window.

=== "Go stack"

    Repository functions take `context.Context` first and read tenant from a typed context key (never a `string` key). Defaulting to a super tenant or empty string on missing context is cross-tenant data exposure.

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

    Every Go service that handles tenant-scoped data carries these helpers (or an equivalent typed context key) and uses them at every repository call.

### Object property-level access control (mass assignment)

External: [OWASP API3:2023](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/).

Never serialise a persistence entity directly. Never accept an open property bag on update.

=== "Java stack"

    Carbon's REST endpoints use explicit DTOs in `org.wso2.carbon.apimgt.rest.api.*.dto` packages and construct each response field-by-field from the domain object. Jackson is configured to fail on unknown properties (see [Injection — Input validation](#input-validation)). New endpoints follow the same shape — do not add a reflective pass over a domain object.

=== "Go stack"

    Separate `Request` and `Response` DTO structs per endpoint; map field-by-field at the service layer; `json.Decoder.DisallowUnknownFields()` on every inbound decoder.

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

External: [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal) · [Zip Slip](https://snyk.io/research/zip-slip-vulnerability).

=== "Java stack"

    `new File(base, untrusted).getCanonicalFile()` and compare to `baseCanonical.toPath()`. Or `Path.toRealPath` with `LinkOption.NOFOLLOW_LINKS` where symlinks must not be followed.

=== "Go stack"

    `filepath.Clean(filepath.Join(base, untrusted))` and `strings.HasPrefix(clean, baseClean+string(filepath.Separator))`. For archive extraction, `filepath.Rel(baseClean, target)` and reject if the relative path starts with `..`.

### Missing Function Level Access Control

External: [OWASP API5:2023](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/).

=== "Java stack"

    Permission requirement declared in the OSGi service descriptor or the JAX-RS resource annotation, not derived from role-name string matching inside business logic.

=== "Go stack"

    Authn/authz middleware sits in front of every protected handler; on failure it writes the response and calls `c.Abort()` (Gin) or `return`s after writing (`net/http`). Keep a `permissions.go` (or equivalent) that enumerates every public path; anything not on the list is protected by default.

### Cross-Site Request Forgery (CSRF)

External: [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

Bearer-token APIs without browser-session cookies typically do not need CSRF tokens but must document why.

=== "Java stack"

    OWASP CSRFGuard tokens *and* `SameSite=Lax`/`Strict` on session cookies. WSO2 configuration: [OWASP CSRFGuard]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/owasp-csrf-guard/) (Carbon properties, JSP taglib usage, multipart and AJAX integration).

=== "Go stack"

    Use [`gorilla/csrf`](https://github.com/gorilla/csrf) middleware (double-submit cookie pattern) plus `SameSite=Strict` cookies. Wire the middleware in front of every state-changing handler at the router root; mark bearer-token-only API routes as exempt (those carry the `Authorization` header explicitly, which the browser does not attach cross-site).

### Server Side Request Forgery (SSRF)

External: [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

WSO2 surfaces that take URLs from input: webhook destinations, OIDC discovery, federated-IdP metadata. Validate the *resolved* address, not the host string (DNS rebinding bypasses host-string checks).

=== "Java stack"

    `HttpClient` with a custom `DnsResolver` that validates resolved addresses.

=== "Go stack"

    Custom `http.Transport.DialContext` that calls `net.DefaultResolver.LookupIPAddr` and rejects private / link-local / loopback ranges.

### Unvalidated Redirects and Forwards

External: [OWASP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html).

Match against a registered allow-list of relative paths (or fully-qualified URLs for OAuth `redirect_uri`). The same exact-match rule that applies to OAuth `redirect_uri` (see [Authentication Failures](#authentication-failures)) applies here.

---

## Security Misconfiguration

External: [OWASP A05](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) · [HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html).

### HTTP security headers

The header set your code should emit, and how to wire it on Carbon/Tomcat, Go services, the WSO2 API Gateway, reverse proxies, and Kubernetes ingresses, is in [HTTP Security Headers — Configuration Reference]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/security-related-http-headers/).

### Container security defaults

External: [Kubernetes Pod Security Standards (Restricted)](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted) — adopt the Restricted profile as the WSO2 baseline.

WSO2-specific:

* Image: distroless or minimal base. No shell, no package manager.
* Image pull by digest, not tag.
* `NetworkPolicy` default-deny in every namespace; explicit allow per service.
* `PodDisruptionBudget` for critical workloads.

### XML External Entity (XXE)

External: [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html).

=== "Java stack"

    Every parser instance — `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, `SchemaFactory`, `Validator` — has DTD and external-entity processing disabled before use:

    ```java
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    dbf.setXIncludeAware(false);
    dbf.setExpandEntityReferences(false);
    ```

    Apply the equivalent flags to every parser family (`DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, `SchemaFactory`, `Validator`). Where the same parser is constructed in multiple places, centralise the configuration in a project-local helper so the flags can't drift between call sites.

=== "Go stack"

    `encoding/xml` does not expand external entities by default — standard parsing is safe. Where a third-party library wraps another parser (libxml2 bindings, for instance), check its default settings explicitly.

### ClickJacking and Cross Frame Scripting

External: [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html).

Admin consoles must ship with `frame-ancestors` set in production. Values in [HTTP Security Headers]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/security-related-http-headers/).

### Cross-Origin Resource Sharing

External: [MDN — CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS).

Reject `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true` at code review.

### API inventory, versioning, deprecation

External: [OWASP API9:2023](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/) · [RFC 8594 — Sunset header](https://datatracker.ietf.org/doc/html/rfc8594).

=== "Java stack"

    Gateway inventory in the APIM Publisher portal. Identity Server federated trust list reviewed quarterly. `Sunset:` header set at the JAX-RS layer for deprecated resources.

=== "Go stack"

    Generate the router from the OpenAPI spec, or fail the CI build if a handler exists that is not in the spec. Internal endpoints use Kubernetes `ClusterIP` services + `NetworkPolicy`, never `LoadBalancer`.

### Default credentials, sample apps, management console exposure

WSO2-specific operational rules:

* Rotate the Carbon admin password before exposure. Replace shipped keystore passwords and store in SecureVault or an external secret manager.
* Sample apps, demo content, Carbon Management Console, JMX, gRPC reflection, debug/profiling endpoints bind to localhost or an internal network — never public ingress.
* Strip server banners (`Server: WSO2/X.Y.Z` and version-disclosing headers).
* Self-registered users must not be granted the Management Console "login" permission. Particularly important for API Manager Store users.

---

## Software Supply Chain Failures

External: [SLSA](https://slsa.dev/) · [OWASP SCVS](https://owasp.org/www-project-software-component-verification-standard/).

WSO2 [incident clarifications]({{#base_path#}}/security-announcements/incident-clarifications/) document past npm and axios incidents; deployments that diverge from the official baseline are the recurring failure pattern.

WSO2-specific operational rules:

* Pin every dependency to an exact version. Lock files committed (`go.sum`, `package-lock.json`, `pnpm-lock.yaml`). CI installs from lock (`npm ci`, `pnpm install --frozen-lockfile`, `GOFLAGS=-mod=readonly`).
* Single trusted source per ecosystem: WSO2 Nexus for Maven, the documented Go module proxy, the scoped mirror for npm. Resolution from any other source is a reviewable change.
* SBOM (CycloneDX or SPDX) generated in the release pipeline and attached to artefacts.
* Sign every released artefact on protected infrastructure with a short-lived signing identity.
* Least-privilege `permissions:` on every CI workflow. Never `pull_request_target` with secrets without an explicit approval gate.

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

    Inherit from the parent POM so trust additions go through one diff. **Current audit:** `<checksumPolicy>ignore</checksumPolicy>` is set in two `msf4j` POMs — open hardening items.

=== "Go stack"

    `go.sum` committed alongside every `go.mod` change. CI runs with `GOFLAGS=-mod=readonly`:

    ```yaml
    env:
      GOFLAGS: "-mod=readonly"
    on:
      pull_request_target:
        paths:
          - '**/go.mod'
          - '**/go.sum'
    ```

    `replace` directives in `go.mod` are review-required. For air-gapped builds, document the required `GOPROXY` (an internal mirror, never `direct`).

### Using Known Vulnerable Components

Operational scanning (Dependency Check / govulncheck / npm audit), suppression policy, and the security-review workflow are in [Dependency Vulnerability Analysis]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/external-dependency-analysis-analysis-using-owasp-dependency-check/).

### Unsafe consumption of upstream APIs

External: [OWASP API10:2023](https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/).

Every upstream response is untrusted. Validate status, content-type, schema, and size; apply outbound TLS rules from [Cryptographic Failures](#cryptographic-failures); bound every call with timeouts and a circuit breaker. Treat the JWKS URL as configured trust, never something the upstream tells you to fetch at runtime.

=== "Java stack"

    Carbon's HTTP client wiring accepts per-upstream trust stores; rotate pinned values with overlap windows.

=== "Go stack"

    `context.WithTimeout` per request; circuit breaker (`sony/gobreaker` or equivalent); `http.MaxBytesReader` on the response body before decoding.

---

## Cryptographic Failures

WSO2 baselines to:

* **[NIST SP 800-131A](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final)** — approved algorithms and the transition schedule. Anything NIST currently marks as legacy / disallowed (MD5, SHA-1, 3DES, RC4, RSA without padding, AES without a mode, etc.) is banned in WSO2 product code.
* **[OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)** — symmetric / asymmetric primitives, nonce handling, key management.
* **[OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)** — current Argon2id / PBKDF2 / bcrypt parameters. These move over time; use the cheat-sheet values current at implementation time, store the algorithm name and parameters alongside the hash, and re-evaluate at every release.
* **[Mozilla TLS configuration generator](https://ssl-config.mozilla.org/)** — TLS versions, cipher suites, OCSP, HSTS at the terminator. Pick the "Intermediate" or "Modern" profile and pin to the generated config.
* **[RFC 8725 — JWT BCP](https://datatracker.ietf.org/doc/html/rfc8725)** — JWT algorithm allow-listing, alg-confusion defence, `kid`/`jwk` header handling, claim validation.

WSO2-specific additions:

* **Per-verifier JWT algorithm allow-list is data, not code.** Configured via deployment.toml in Carbon products; embedded in the keyfunc switch in Go services. Reject `alg: none` and reject HMAC where the verifier holds an asymmetric key.
* **Never honour an inline `jwk` header.** Always look up keys by `kid` from a JWKS cache pinned to the trusted issuer.
* **Hardcoded TLS verification bypasses are defects.** `AllowAllHostnameVerifier`, `NoopHostnameVerifier.INSTANCE`, `tls.Config{InsecureSkipVerify: true}` literal in production paths fail review. Operator-configurable bypasses are acceptable only with a secure default of `false` and a deployment-time warning.

=== "Java stack"

    **Use the central facade.** Carbon's `org.wso2.carbon.core.util.CryptoUtil` (`encryptAndBase64Encode`, `base64DecodeAndDecrypt`) is backed by a pluggable `InternalCryptoProvider`. Components select the provider via configuration:

    ```java
    private static final String CRYPTO_PROVIDER =
            "CryptoService.InternalCryptoProviderClassName";
    private static final String SYMMETRIC_KEY_CRYPTO_PROVIDER =
            "org.wso2.carbon.crypto.provider.SymmetricKeyInternalCryptoProvider";
    ```

    Any new code that handles a secret (refresh tokens, IdP credentials, vault-managed configuration) goes through `CryptoUtil` or an injected `CryptoService`. Do not call `Cipher.getInstance` directly from product code.

    Where a code path must instantiate a `Cipher` directly (legacy or framework boundary), use modern transformations explicitly: `AES/GCM/NoPadding` (96-bit IV, persist `iv || ciphertext`, never reuse `iv` with the same key); `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` for asymmetric. **Current audit:** `Cipher.getInstance("RSA")` without padding remains in `carbon-registry/CipherInitializer`, `carbon-identity-framework/SecondaryUserStoreConfigurator`, and the user-store deployer utility — open hardening items.

    **JWT verification** uses Nimbus JOSE through the gateway's `JWTValidator` with an explicit algorithm switch:

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

    Keys flow through `KeyStoreManager` (primary, internal, per-tenant). Private-key passphrases come from SecureVault.

    **TLS.** Carbon's `MutualSSLManager` hard-codes `private static final String protocol = "TLSv1.2";`. New `SSLContext` construction sets TLS 1.2+, `SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")`, and never installs `NoopHostnameVerifier.INSTANCE`. APIM's `APIManagerComponent` and IS's `MutualSSLManager` expose an `ALLOW_ALL` option for backwards compatibility behind a system property — not enabled in production. New components must not add similar opt-outs.

    Compare MACs with `MessageDigest.isEqual`, never `Arrays.equals` (not constant-time in older JDKs). Hold credentials and key material as `char[]`, not `String`; `Arrays.fill(pw, '\0')` after use.

=== "Go stack"

    **Use the central crypto package** — never call `crypto/aes`, `crypto/rsa`, or `crypto/sha256` directly from product code. For the API platform, `pkg/encryption/manager.go` (dispatcher) plus `pkg/encryption/<alg>/` providers is the established shape. New services should follow the same shape.

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

    **JWT** — restrict the accepted algorithm at parse time inside the keyfunc:

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

    **TLS** — `tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}` on every outbound client and every server config. `InsecureSkipVerify: true` is acceptable only when operator-configured with a secure default of `false`; hardcoded `true` is a defect. **Current audit:** ~48 production occurrences across multiple Go services; each must be reviewed.

    **Constant-time comparison** with `crypto/subtle.ConstantTimeCompare` (or `hmac.Equal` for MACs). `crypto/rand.Read` for nonces, salts, IVs, session ids — never `math/rand`. Keep secret material in `[]byte` from the point of read (Go strings are immutable and cannot be zeroed).

### Securing Cookies

External: [OWASP Session Management Cheat Sheet — Cookies](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies).

WSO2 baseline for session and authentication cookies: `HttpOnly; Secure; SameSite=Lax` (or `Strict` for high-sensitivity flows). `Path` set to the narrowest scope that works. `Domain` only when cross-subdomain sharing is required.

---

## Injection

External: [OWASP A03](https://owasp.org/Top10/A03_2021-Injection/) · [Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html) · [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html).

### Input validation

The general rules (allow-list not deny-list, length caps, format validation, canonicalisation before validation, refuse unknown JSON fields, bound parser cost) are in the OWASP Input Validation Cheat Sheet. WSO2-specific call shapes:

=== "Java stack"

    Jakarta Bean Validation (`@Email`, `@Pattern`, `@Size`, `@Min`/`@Max`, custom validators) on DTOs. `mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)` or `@JsonIgnoreProperties(ignoreUnknown = false)`. Configure `StreamReadConstraints` to bound Jackson parser cost on adversarial input. Set `maxRequestSize` at the servlet container.

=== "Go stack"

    Typed DTO + `go-playground/validator` tags; `dec.DisallowUnknownFields()` on every decoder; `http.MaxBytesReader` on every body-reading handler.

    ```go
    type CreateAppRequest struct {
        Name        string   `json:"name"        validate:"required,min=1,max=128,alphanumunicode"`
        Description string   `json:"description" validate:"omitempty,max=4096"`
        Scopes      []string `json:"scopes"      validate:"max=32,dive,oneof=read write admin"`
    }
    ```

### SQL Injection

External: [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) — covers parameterised queries (Defense Option 1) and the [allow-list input validation pattern](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html#defense-option-4-allowlist-input-validation) for dynamic identifiers (Defense Option 4) with worked examples.

WSO2 rule: parameterised queries with bind variables for every value. Where the value is a SQL identifier that cannot be parameterised (column name in `ORDER BY`, table name, sort direction), validate the input against an allow-list of legal values **server-side** before composing the statement — the worked example in the OWASP link above shows the shape.

=== "Java stack"

    ```java
    try (PreparedStatement ps = conn.prepareStatement(
            "SELECT id, name FROM users WHERE tenant_id = ? AND user_id = ?")) {
        ps.setInt(1, tenantId);
        ps.setString(2, userId);
        try (ResultSet rs = ps.executeQuery()) { /* ... */ }
    }
    ```

=== "Go stack"

    ```go
    row := db.QueryRowContext(ctx,
        "SELECT id, name FROM users WHERE tenant = $1 AND id = $2",
        tenantID, userID)
    ```

### LDAP Injection

External: [OWASP LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html) — covers the [search-filter character set](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html#defenses) that must be escaped (`*`, `(`, `)`, `\`, NUL) and the [distinguished-name character set](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html#distinguished-name-escaping) (different rules).

WSO2 rule: build every LDAP filter and DN through the escape helper provided by the LDAP client library (e.g., Spring Security's `LdapEncoder.filterEncode` / `nameEncode`, or the Apache Directory API's escaping utilities — pick whatever your library provides and use it consistently). Building a filter via `String.format` / `fmt.Sprintf` / string concatenation with user input is a security defect, even when the input "looks like" a username.

### OS Command Injection

External: [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html).

Argument array, no shell. Never the single-string form; never `sh -c "…"` with interpolated input.

=== "Java stack"

    ```java
    // Anti-patterns — reject in code review
    Runtime.getRuntime().exec("convert " + userFilename + " out.png");
    new ProcessBuilder("/bin/sh", "-c", "convert " + userFilename + " out.png").start();

    // Safe — argument array, no shell
    new ProcessBuilder("convert", userFilename, "out.png")
            .redirectErrorStream(true).start();
    ```

    **Current audit:** `Runtime.getRuntime().exec(command.toString())` style invocations remain in carbon-kernel's tooling (`tools/SPIProviderTool.java`, `tools/ICFProviderTool.java`, `tools/NativeLibraryProvider.java`) — open hardening items.

=== "Go stack"

    ```go
    // Anti-pattern — reject in code review
    exec.CommandContext(ctx, "sh", "-c", "convert "+userFilename+" out.png")

    // Safe — argument slots, no shell
    cmd := exec.CommandContext(ctx, "convert", userFilename, "out.png")
    cmd.Stdin = nil
    out, err := cmd.CombinedOutput()
    ```

### Cross-Site Scripting (XSS)

External: [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) · [OWASP DOM-based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html). Pair output encoding with a strict CSP — see [HTTP Security Headers]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/security-related-http-headers/).

=== "Java stack"

    [OWASP Java Encoder](https://owasp.org/www-project-java-encoder/) per output context: `Encode.forHtml`, `Encode.forHtmlAttribute`, `Encode.forJavaScript`, `Encode.forUriComponent`. JSPs: encoder taglib (`<e:forHtml/>`) preferred over JSTL `<c:out/>`. Never write user-supplied data into a JSP with raw `<%= %>`.

=== "Go stack"

    Render HTML with `html/template`, never `text/template`. Auto-escaping is per-context (HTML attribute vs. script vs. URL).

### HTTP Response Splitting (CRLF Injection)

External: [OWASP HTTP Response Splitting](https://owasp.org/www-community/attacks/HTTP_Response_Splitting).

Modern servlet containers and `net/http` reject raw CR/LF, but code that builds headers manually (downstream HTTP clients, proxy filters) must also strip.

### Log Injection / Log Forging

Strip CR/LF from any user-controlled value before logging; see [Logging and Alerting Failures](#logging-and-alerting-failures).

=== "Java stack"

    Carbon 4.4.3+ supports the `%K` token in the log4j pattern, which appends a per-entry UUID so forged log lines from log-injection attempts lack a valid UUID. **Don't enable `%K` in the default `log4j2.properties` you ship** — appending a UUID to every log line carries real cost (CPU per line, larger log volume) and most deployments don't need it. Make sure `%K` works in your product's log4j layout and document it as an operator-enabled hardening option for deployments whose security or compliance requirements call for tamper-evident log lines.

### Server-Side Template Injection (SSTI)

External: [OWASP SSTI](https://owasp.org/www-community/attacks/Server-Side_Template_Injection).

User input is substituted into pre-defined parameters of an already-compiled template — never into the template *source*. Anti-pattern: `engine.evaluate(userSuppliedTemplate, context)`.

### NoSQL and XPath injection

External: [OWASP — Testing for NoSQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection) · [OWASP XPath Injection](https://owasp.org/www-community/attacks/XPATH_Injection).

Construct queries with the driver's structured API (MongoDB filters, BSON documents, XPath with bound variables) — never by concatenating user input into a query string.

### Regex denial of service (ReDoS)

External: [OWASP ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS).

Never compile user-supplied regex patterns. Cap input length before matching.

=== "Java stack"

    `java.util.regex.Pattern` uses a backtracking engine — catastrophic backtracking on patterns like `(a+)+` consumes CPU exponentially. Prefer possessive quantifiers (`a++`) or atomic groups (`(?>…)`); for high-risk surfaces use a separate evaluation thread with a timeout.

=== "Go stack"

    `regexp` uses RE2 (linear time, no backtracking) — safe by design. Bounding input length still applies to cap memory.

### Email header injection

External: [OWASP Email Injection](https://owasp.org/www-community/attacks/Email_Injection).

Code that sends email and substitutes input into RFC 5322 headers must strip CR/LF and validate per-header. Prefer libraries that build headers programmatically over string formatting.

---

## Insecure Design

External: [OWASP A04](https://owasp.org/Top10/A04_2021-Insecure_Design/) · [OWASP Threat Modeling Process](https://owasp.org/www-community/Threat_Modeling_Process) · [OWASP Proactive Controls](https://owasp.org/www-project-proactive-controls/). WSO2 review process: [Secure Software Development Process]({{#base_path#}}/security-processes/secure-software-development-process/).

Any feature introducing a new external attack surface, authentication/authorisation surface, credential or secret store, or privilege grant goes through STRIDE-LM design review with the security lead before code review begins.

WSO2-specific design rules:

* Workflow state transitions enforced by an explicit state machine (enum + transition table) checked at the service layer before persistence — never derived from caller input.
* Every endpoint that performs work is rate-limited (per-user *and* per-IP *and* global).
* Trust boundaries named and enforced; tenant identity carried in context and re-checked at the data layer.

=== "Java stack"

    State machines: `APIStatus` (`CREATED`, `PUBLISHED`, `DEPRECATED`, `RETIRED`) with `APIStatusObserver`/`APIStatusHandler` enforcing transitions; workflow approvals use `WorkflowStatusEnum`. New domains follow the same shape.

    Idempotency via atomic database operations (`INSERT ... ON CONFLICT` / unique index) — never `SELECT` then `INSERT`. For one-time init of shared state, `synchronized (cacheName.intern())`; for higher-throughput state, `java.util.concurrent` primitives.

    Rate limiting via the APIM gateway's `ThrottleHandler` (application / subscription / API / resource / hard-limit). Endpoints outside the gateway (IS admin services, custom inbound, OAuth token endpoint) need explicit throttling — APIM tier policies or a custom `IdentityEventListener` with per-user and per-IP counters.

=== "Go stack"

    Trust model documented in `ARCHITECTURE.md`. Every public path enumerated explicitly; everything else default-deny. Operation-level security expressed as declarative data in the API spec, not ad-hoc handler code. Long-running workflows modelled as typed state machines with optimistic locking on `(instance_id, current_state)`.

    `sync.Once` for one-time init; `sync.RWMutex` for high-throughput maps; database uniqueness for idempotency. Rate limiting at middleware, not per handler.

### Pagination, list limits, and resource ceilings

External: [OWASP API4:2023](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/).

WSO2-specific:

* Every list endpoint paginates with a server-enforced maximum page size (typically 100–1000).
* Reject `limit=` parameters above the configured maximum at the handler.
* Total counts only where the table is small enough to scan cheaply — otherwise return `hasMore` and let callers page until empty.
* Per-tenant ceilings (queries-per-minute, max stored objects, max attachment size) prevent one tenant exhausting shared resources.
* Operations that could touch unbounded data require an admin role or a deliberate batch-job path.

### Sensitive business flows and anti-automation

External: [OWASP API6:2023](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/).

WSO2 sensitive flows to identify at STRIDE-LM review: signup, password reset, OTP send, MFA enrolment, gift-code redemption, refund initiation, free-tier resource creation. Apply layered budgets (per-user, per-device, per-IP, per-tenant, global) plus behavioural signals (CAPTCHA after first few failures, device fingerprinting). Every invocation emits an audit event so that velocity anomalies are observable; alerts on the highest-value flows are wired into the deployment's security monitoring.

### Unrestricted File Upload

External: [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).

WSO2 enforcement order: container size limit → handler size limit → content-type allow-list (validated against magic bytes, not the `Content-Type` header) → filename sanitisation → storage outside any web-served directory. Files served back: separate hostname (or at minimum a separate path), no execute permissions, `Content-Type` set explicitly.

---

## Authentication Failures

WSO2 baselines to:

* **[NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)** — memorised-secret (password) requirements, lifecycle, recovery, MFA assurance levels. Follow current NIST guidance for length, composition, rotation, and breached-password checking; do **not** impose mandatory composition rules ("at least one of each character class"), which NIST explicitly disallows.
* **[OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)** and **[Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)** — operational rules.
* **[RFC 9700 — OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/rfc9700)** — PKCE (`S256` only), exact `redirect_uri` matching, refresh-token rotation, public-client constraints, prohibited grant types.
* **[OWASP Top 10 A07](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)** — threat model.

WSO2-specific additions:

* **Breached-password check is required for products that handle personal data** (Identity Server, on-prem APIM with end-user accounts). Use the [HIBP k-Anonymity API](https://haveibeenpwned.com/API/v3#PwnedPasswords) or a locally hosted mirror; consult at password-set time.
* **Lockout is honoured by every authentication path.** Interactive login, OAuth `password` grant, token endpoint, SCIM provisioning. Enforced on one path but not another is the bug pattern that lets attackers move sideways; reviewers explicitly check parity across paths.
* **MFA defaults on for administrative or sensitive-data access.** TOTP and FIDO2 / WebAuthn as primary factors; SMS/email OTP as step-up or fallback only — never as sole factor for privileged accounts.
* **Token storage on clients.** Browsers: `HttpOnly; Secure; SameSite=Strict` cookies or BFF; never `localStorage` / `sessionStorage` for refresh tokens. Mobile: platform secret store (Keychain / Android Keystore), device-bound where supported.
* **"Log out everywhere"** revokes every active token family for the principal; implement RFC 7009 revocation and OIDC back-channel logout. Account recovery forces MFA re-enrollment.
* **Step-up for sensitive actions** — password change, MFA config changes, email change, key issuance, role grant. Email change notifies the *old* address and requires verification of the *new* one.

=== "Java stack"

    Password policies through `PolicyEnforcer` registered against `IdentityMgtEventListener.doPreUpdateCredential()`. **The shipped `DefaultPasswordLengthPolicy` defaults (`MIN_LENGTH=6`, `MAX_LENGTH=10`) are demo defaults — your product must register a stronger policy.** For products handling personal data, add a custom `PolicyEnforcer` that consults the HIBP k-Anonymity API at password-set time.

    MFA authenticators in `carbon-identity-framework/components/authenticator/` (TOTP, FIDO2, SMS-OTP, Email-OTP). Adaptive authentication scripts select the second factor based on ACR / enrolled factors / risk signals.

    Account lockout: `IdentityMgtEventListener` + `AccountLockHandler`. Failed attempts tracked in `UserIdentityClaimsDO`; the `http://wso2.org/claims/identity/accountLocked` claim is set on threshold and consulted in `doPreAuthenticate()` before any credential check.

    OAuth: PKCE enforced at the authz request; `redirect_uri` exact match; refresh-token rotation with reuse detection emits a security event and revokes the token family.

=== "Go stack"

    Password hashing parameters from configuration (Argon2id or PBKDF2), not hard-coded constants. Store algorithm name and parameters alongside the hash.

    OTP delivery built around a short-lived signed session token rather than a server-side OTP store:

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

    Refresh-token rotation issues a new token and invalidates the old; presenting an invalidated token revokes the entire token family and emits a security event.

### Session Fixation

=== "Java stack"

    Carbon 4 pattern: `session.invalidate()`, then `request.getSession()` for a fresh session, then set the authenticated attribute on the new session.

=== "Go stack"

    Issue a fresh session token after authentication; invalidate any prior token associated with the principal.

---

## Software and Data Integrity Failures

External: [OWASP A08](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/) · [SLSA](https://slsa.dev/) · [sigstore / cosign](https://docs.sigstore.dev/).

WSO2-specific operational rules:

* Sign every release artefact (JAR, container, Helm chart, OS package) on protected infrastructure with a short-lived signing identity. Publish the signature next to the artefact and document verification in the install guide. SHA-256 checksums alongside every release.
* Deployment manifests reference container images by digest, not tag.
* Every CI workflow declares an explicit minimum `permissions:` block. `pull_request_target` with secrets is gated behind an approval step.
* Subresource Integrity (SRI) on any third-party JS or CSS loaded from a CDN.
* API replay protection: sensitive write endpoints require a request-level `jti` or `nonce` and reject duplicates within a short window. Combine with a request expiry.

=== "Java stack"

    WSO2 Maven artefacts published to Maven Central carry `.asc` (GPG) signatures per Maven Central's signing requirement; verification instructions for consumers belong in the product's install guide. Target shape for the release pipeline going forward: signed `.asc` (or sigstore equivalent) for every artefact, SHA-256 checksums in the release notes, container images signed with cosign before push. HMAC verification on inbound payloads uses `MessageDigest.isEqual(byte[], byte[])` — never `Arrays.equals` (not constant-time in older JDKs).

=== "Go stack"

    Target shape for a new Go service's release pipeline — sign every artefact with [cosign](https://docs.sigstore.dev/cosign/overview/), publish the signature and a SHA-256 checksum alongside, and document verification in the install guide:

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

External: [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html).

=== "Java stack"

    Use `ObjectInputFilter` (JEP 290, Java 9+) — e.g. `-Djdk.serialFilter=com.wso2.expected.**;!*` — to restrict deserialisable classes. On older Java, subclass `ObjectInputStream` and override `resolveClass()` to allow-list. Mark sensitive fields `transient`. Prefer JSON/XML over Java serialisation for any cross-trust-boundary payload. Audit dependencies for known gadget libraries (Commons Collections, Spring Beans, Groovy).

    **Current audit:** multiple sites in identity-framework and registry components construct `ObjectInputStream` without `ObjectInputFilter` or `resolveClass()` override (workflow-mgt DAO, application-mgt DAO, `JavaSessionSerializer`, registry common utilities) — open hardening items.

    For inbound payloads that must remain dynamic (webhooks, plug-in config), require the producer to sign the payload, verify the signature, then construct the typed object.

=== "Go stack"

    `encoding/json`, `encoding/xml`, `encoding/gob` don't reconstruct arbitrary types by default — typed DTOs are the safe path. For binary protocols (Protobuf, MessagePack), use the generated typed code, not generic decoders.

---

## Logging and Alerting Failures

WSO2 baselines to:

* **[OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)** — the audit-event field schema, the "what to log" / "what never to log" guidance, and the retention and integrity model.
* **[OWASP Logging Vocabulary Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html)** — the canonical event-name registry (`auth.login`, `iam.role.grant`, `key.rotate`, …). Use these names in WSO2 audit events.
* **[OWASP Top 10 A09](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)** — threat model.

WSO2-specific operational rules on top of the OWASP baseline:

* **Operational logs and audit logs are different sinks.** Operational logs: short-retention, standard log aggregator. Audit logs: long-retention, append-only sink, stable schema, no stack traces or framework chatter. In Carbon products the audit log uses the `AUDIT_LOG` logger wired to a separate appender. In Go services it's a dedicated `*slog.Logger` (e.g., a separate `audit` package) with its own handler.
* **`source_ip` is resolved through a proxy-aware extraction**, never read raw from `X-Forwarded-For`. The engineer's job is to use the proxy-aware helper (which consults the trusted-proxy list); the operator's job is to populate that trusted-proxy list per deployment. Make the trusted-proxy setting operator-configurable in your product (e.g., a `[transport.proxy]` block in `deployment.toml`) and document it.
* **Tenant id comes from the authenticated context**, never from request input — same rule as everywhere else in the Carbon stack.
* **Events that should trigger alerts** beyond the OWASP Logging Cheat Sheet baseline — emit audit events for these, and wire the alerts into whatever monitors the deployment:
    * Cross-tenant deny attempts.
    * Refresh-token reuse-detection trigger (a strong signal of stolen tokens).
    * Read of a privileged key.
    * Change to a security-relevant setting (CORS allow-list, lockout thresholds, JWT issuers, federated IdPs, MFA enforcement).
    * N authentication failures from one source / one principal within a window (lockout-rate signal).
* **Retention** — long enough for security investigation and any applicable compliance horizon. Forward to a dedicated audit sink separate from operational logs; consider signing or hash-chaining log batches for tamper evidence.
* **Where a value needs to appear for correlation** (e.g., a token id), log its **hash** or **truncated prefix** with explicit ellipsis (`abcd1234…`) — never the full value. WSO2-shipped masking helpers are extended for this; reviewers reject ad-hoc redactors.

=== "Java stack"

    `log.error(message, throwable)` — the two-arg form captures the full stack. `log.error("..." + e.getMessage())` is lossy. Make sure the `%K` UUID token (Carbon 4.4.3+) works in your product's log4j layout and document it as an operator-enabled hardening option — see the rule in [Injection — Log Injection / Log Forging](#log-injection-log-forging) for why this is off in the shipped default. Sensitive values are masked with local helpers — extend those rather than building ad-hoc redactors.

=== "Go stack"

    Structured logger built on `log/slog`:

    ```go
    logger.ErrorContext(ctx, "token validation failed",
        slog.String("tenant", tenantID),
        slog.String("request_id", traceID),
        slog.Any("cause", err),
    )
    ```

    Redact at the call site — pass already-masked values into `slog` attributes; never interpolate raw secrets or PII into a message string. Reviewers reject logger calls that violate this.

---

## Mishandling of Exceptional Conditions

External: [OWASP Improper Error Handling](https://owasp.org/www-community/Improper_Error_Handling) · [CWE-703](https://cwe.mitre.org/data/definitions/703.html).

WSO2-specific:

* On any exception during a security decision, default to deny. Initialise the decision variable to the safe value before `try`; never set it to the permissive value inside `catch`.
* At every external boundary (REST / SOAP / gRPC / JMS / scheduled job), install a centralised exception mapper. Sanitised response only — no stack traces, file paths, SQL fragments, class names, framework identifiers.
* Tenant cleanup (`endTenantFlow`, context cancellation) is part of the exception path — see the Java stack tab below.

=== "Java stack"

    **Catch typed exceptions** (not `Exception`/`Throwable`):

    ```java
    try {
        URITemplate uriTemplate = new URITemplate(uri);
    } catch (URITemplateException e) {
        String msg = "Error parsing URI " + uri;
        log.error(msg, e);
        throw new APIManagementException(msg, e);
    }
    ```

    OSGi `BundleActivator.start(BundleContext)` / `stop(BundleContext)` is allowed to declare `throws Exception` — the framework expects bootstrap failures to surface.

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

    Empty `catch` blocks are acceptable only for best-effort cleanup (`closeQuietly`); those helpers themselves log at `WARN`.

=== "Go stack"

    `panic` is reserved for unrecoverable initialisation failures; use `error` returns for ordinary control flow. Recover from `panic` only at safe boundaries — request handlers, goroutine entry points, transaction wrappers — and convert to `error`:

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

    Wrap errors with `fmt.Errorf("...: %w", err)`. Sentinel errors at package level; inspect with `errors.Is` / `errors.As`. Never serialise a raw Go `error` into a client-facing JSON response — translate to a canonical `ErrorResponse` envelope at the handler layer.

    `defer` cleanup immediately after acquisition:

    ```go
    tx, err := r.db.Begin()
    if err != nil {
        return err
    }
    defer tx.Rollback() // safe: Rollback is a no-op after Commit
    ```

    Do not `defer` inside a loop — each iteration accumulates a deferred call that doesn't run until the function returns; wrap the loop body in a closure if a per-iteration defer is needed.

    `context.Context` is the first parameter on every function that does I/O. Never replace the incoming context with `context.Background()` mid-flight.

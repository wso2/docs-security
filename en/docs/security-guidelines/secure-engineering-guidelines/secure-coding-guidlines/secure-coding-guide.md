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
3. **Centralise crypto behind audited helpers.** Carbon's `CryptoUtil`; a central encryption package (dispatcher + per-algorithm providers) in Go. Never call `Cipher.getInstance` / `crypto/aes` directly from product code.
4. **Configuration is code.** Security-relevant settings (CORS allow-lists, lockout thresholds, JWT issuers, federated IdPs, log layouts) are version-controlled and reviewed.

---

## Broken Access Control

Read these for the access-control model and enforcement patterns: [OWASP A01](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) · [Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) · [Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html) for the deny-by-default model these subsections enforce.

Two rules cut across everything below: deny by default (every function requires an explicit grant before it runs), and re-check authorization at the layer that touches data, not only at the edge. Authorization checks must complete before any state-changing operation runs.

### Object-level access control (IDOR)

Read [OWASP API1:2023](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) for the attack pattern and the test cases to run against each object-returning endpoint.

The enforcement point is the data layer, not the handler. An authenticated user is authorized to act on *their* objects; the object id in the request is attacker-controlled and proves nothing. Bind every lookup to the caller's tenant and subject identity inside the query, so an id belonging to another tenant or owner simply returns no rows.

=== "Java stack"

    Read the tenant identity from `PrivilegedCarbonContext` (the request-scoped tenant context) and pass it as a query parameter on every repository read and write; the repository refuses rows whose tenant does not match. Do not trust a tenant id carried in the request body or path.

    Reject the anti-pattern of a handler-level "is this id in the user's allowed list?" check: it doubles query cost, leaves a TOCTOU window between the check and the use, and is silently bypassed by any code path that reaches the repository without going through the handler.

=== "Go stack"

    Repository functions take `context.Context` first and read tenant from a typed context key (never a bare `string` key, which collides across packages). Defaulting to a super tenant or to the empty string when the context is missing the tenant is cross-tenant data exposure, not a safe fallback — return an error instead.

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

    Every service that handles tenant-scoped data carries these helpers (or an equivalent typed context key) and uses them at every repository call; the tenant predicate belongs in the `WHERE` clause, not in a post-fetch filter.

### Object property-level access control (mass assignment)

Read [OWASP API3:2023](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/) for how mass assignment lets a client set fields it should never control (role, tenant, internal status).

Never serialise a persistence entity directly, and never bind an inbound request onto an open property bag or onto the domain object by reflection. Drive both directions through an explicit Data Transfer Object: the request DTO declares exactly the fields a client may set, and the response DTO declares exactly the fields it may see. Map field-by-field at the service layer.

=== "Java stack"

    Define a request DTO and a response DTO per endpoint and build each one field-by-field from the domain object. Configure the JSON parser to fail on unknown properties (e.g. Jackson `FAIL_ON_UNKNOWN_PROPERTIES`) so a request carrying an unexpected field is rejected rather than silently ignored — this is the same fail-closed input-validation posture used under [Injection](#injection). Do not add a reflective copy pass over a domain object as a shortcut; a new privileged field on the entity would then become client-settable the moment it is added.

=== "Go stack"

    Separate `Request` and `Response` DTO structs per endpoint, map field-by-field at the service layer, and call `DisallowUnknownFields()` on every inbound `json.Decoder` so unexpected fields are an error, not a silent accept.

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

Read [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal) for the `../` escape technique and [Zip Slip](https://snyk.io/research/zip-slip-vulnerability) for the archive-extraction variant of the same flaw.

Do not accept absolute paths or path fragments from the end user, apart from administrative configuration. Where a path fragment must be accepted, build the final path against a fixed base directory, normalise it so `..` elements resolve, and confirm the result is still inside the base directory before using it.

!!! danger "Approval required"
    Any component that must accept an absolute path from the end user, outside administrative configuration, must have its use-case and the path-canonicalisation and containment controls protecting it reviewed and approved by the Security and Compliance Team before that component is released.

=== "Java stack"

    Resolve untrusted path fragments through the WSO2 `SecurityUtil.resolvePath(baseDir, userPath)` helper. It requires `baseDir` to be absolute and `userPath` to be relative, joins and normalises them (`baseDir.resolve(userPath).normalize()`), and throws `IllegalArgumentException` ("User path escapes the base path") when the normalised result does not `startsWith` the base. Wrap the call in a `try`/`catch` on `IllegalArgumentException` and return an error to the caller.

    Reject the anti-pattern of building a `File` by string-concatenating user input, e.g. `new File(base + File.separator + userDirectory + File.separator + fileName)` — this never detects a `..` escape. Where symlinks must not be followed, use `Path.toRealPath(LinkOption.NOFOLLOW_LINKS)` and apply the same boundary check.

=== "Go stack"

    Join under a fixed base, clean, resolve both to absolute, then check containment:

    ```go
    full := filepath.Clean(filepath.Join(base, userDirectory, logFile))
    baseAbs, err := filepath.Abs(base)         // 500 on error
    fullAbs, err := filepath.Abs(full)         // 500 on error
    if !strings.HasPrefix(fullAbs, baseAbs) {  // 400 "Invalid path"
        http.Error(w, "Invalid path", http.StatusBadRequest)
        return
    }
    ```

    Reject the anti-pattern of concatenating the path and opening it without a boundary check, e.g. `os.Open(base + "/" + userDirectory + "/" + logFile)`. For archive extraction, compute `filepath.Rel(baseAbs, target)` per entry and reject any entry whose relative path begins with `..`.

### Missing Function Level Access Control

Read [OWASP API5:2023](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/) for the attack pattern — sensitive handlers reachable because the authentication or authorization check is missing or insufficient.

Every restricted handler must check authentication and then role permission before it does any work; the enforcement mechanism must deny all access by default and require an explicit grant to specific roles for each function. If the function is part of a workflow, also verify the workflow is in a state that allows the operation. Log authentication- and authorization-related changes to the audit trail.

=== "Java stack"

    Declare the permission requirement where it is enforced — the service descriptor or the JAX-RS resource annotation — not by string-matching role names inside business logic, which is easy to forget on a new method and invisible to review.

    On Carbon (Carbon 4), the Carbon Management Console gate is the "login" permission: it must **not** be granted to any user that does not need console access. The canonical case is the API Manager Store self-registered user, who must never be able to reach the admin console. Treat any grant of "login" to a self-registration or store-facing role as a finding.

=== "Go stack"

    Authn/authz middleware sits in front of every protected handler; on failure it writes the response and stops the chain (`c.Abort()` in Gin, or `return` after writing for `net/http`). Maintain a single list that enumerates every public path; anything not on the list is protected by default. New routes are protected unless someone deliberately adds them to the public list, so the failure mode of forgetting is a locked door, not an open one.

### Cross-Site Request Forgery (CSRF)

Read the [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) for the Synchronizer Token and Double-Submit-Cookie patterns.

CSRF targets state change, so the first rule is that no state-changing operation may use HTTP `GET` — use `POST`/`PUT`/`DELETE` and validate the token before processing the operation. Bearer-token APIs with no browser-session cookie typically do not need CSRF tokens, but each such endpoint must document why it is exempt.

The strategy is keyed to the Carbon Kernel version:

* Carbon Kernel prior to 4.4.6 used Referer-header-based prevention — no longer recommended; do not carry it forward.
* Carbon Kernel 4 (4.4.6+) products use the Synchronizer Token Pattern via OWASP CSRFGuard.
* Carbon Kernel 5+ products and any new application use the Double-Submit-Cookie approach.

=== "Java stack"

    Use OWASP CSRFGuard for the Synchronizer Token Pattern, paired with `SameSite=Lax`/`Strict` on session cookies. The listener/filter/servlet wiring (`CsrfGuardServletContextListener`, `CsrfGuardHttpSessionListener`, `CsrfGuardFilter`, `JavaScriptServlet`), the per-application properties file `repository/conf/security/Owasp.CsrfGuard.Carbon.properties`, JSP taglib usage, and AJAX/multipart integration are all in the companion reference: [OWASP CSRFGuard]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/owasp-csrf-guard/). Reject any HTML form that posts a state-changing request without a hidden CSRF token.

=== "Go stack"

    Use the established [`gorilla/csrf`](https://github.com/gorilla/csrf) middleware (double-submit cookie) with cryptographically secure token generation, wired in front of every state-changing handler at the router root, plus `SameSite=Strict` cookies. Mark bearer-token-only API routes as exempt — they carry the `Authorization` header explicitly, which the browser does not attach cross-site.

    !!! danger "Approval required"
        If `gorilla/csrf` does not meet a requirement, or a custom CSRF implementation is needed, reach the Security and Compliance Team for review before building it.

### Server Side Request Forgery (SSRF)

Read the [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) for the full list of bypasses; this is a high-severity class because the server can be turned into a proxy for internal port scanning, `file://` access, and `gopher://`/`tftp://` protocol smuggling.

WSO2 surfaces that take URLs from input are the back-channel operations where the product acts as the client (e.g. webhook destinations, OIDC discovery, or federated-IdP metadata fetches). Validate the *resolved* address, not the host string, because DNS rebinding makes a host-string allow-list bypassable.

Prevention techniques:

* Avoid using user input in backend requests — URLs, IP addresses, and file paths used in back-channel operations, and unvalidated XML passed to a parser without XXE protections (see [Injection](#injection)).
* Strict error handling: return an identical generic error (e.g. "Invalid Data Retrieved") whether the backend request fails or invalid data is returned, so the response cannot be used as an open/closed-port oracle.
* Strict response handling: validate the response server-side (expected content-type, schema) before processing it or returning it to the client.

=== "Java stack"

    Enforce SSRF defence at the application layer, not the JVM. The Java Security Manager — and the `SocketPermission` policy grants that previously fenced outbound connections — was deprecated for removal by [JEP 411](https://openjdk.org/jeps/411) and is permanently disabled as of JDK 24 by [JEP 486](https://openjdk.org/jeps/486): the startup flag makes the JVM exit, `System.setSecurityManager` and `Policy.setPolicy` throw `UnsupportedOperationException`, and the permission checks always deny. Do not rely on it on any JDK current products run (17/21+).

    Apply the same resolved-address validation the Go stack uses below:

    * Maintain an allow-list of permitted destination hosts and require `https` only.
    * Resolve the host (`InetAddress.getAllByName`) and reject the request if any resolved address is private (RFC 1918), loopback, link-local, IPv6 unique-local (`fc00::/7`), or a cloud-metadata address (`169.254.169.254`, `fd00:ec2::254`) — validate the resolved `InetAddress`, never the host string.
    * Pin the validated resolved IP for the connection that actually runs, so an attacker cannot swap the name to an internal address between the check and the connect (the check-then-connect / DNS-rebinding TOCTOU window).
    * Disable automatic redirect following (`HttpClient.Redirect.NEVER`, or `setInstanceFollowRedirects(false)` on `HttpURLConnection`), or re-run the resolved-IP validation after every redirect.

    Implement the resolve-and-validate step at the connection layer — inside a custom `SocketFactory` or an HTTP-client connection interceptor that validates the resolved address immediately before `connect` — or route all egress through a vetted forward proxy that enforces the allow-list.

=== "Go stack"

    Use a custom `http.Transport.DialContext` that resolves the host (`net.DefaultResolver.LookupIPAddr`) and rejects private, link-local, and loopback ranges — validate the resolved IP, not the host string, so a name that resolves to an internal address is blocked at dial time.

### Unvalidated Redirects and Forwards

Read the [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html) for how an open redirect enables phishing under a trusted server name and how a forward can reach a restricted resource through a less-restricted one.

Do not accept absolute forward URLs, or absolute redirect URLs (apart from administrative configuration), or URL fragments used to build them, from the end user. Where an absolute URL is unavoidable, match it against a registered allow-list before redirecting. Where only a fragment is expected, validate that the fragment is exactly the expected type of value (e.g. an integer id). The same exact-match rule that governs OAuth `redirect_uri` applies here (see [Authentication Failures](#authentication-failures)).

!!! danger "Approval required"
    Accepting an absolute forward URL from the end user, by any means, must have its use-case and protective controls reviewed and approved by the Security and Compliance Team before release.

!!! danger "Approval required"
    Accepting an absolute redirect URL from the end user, outside administrative configuration, must have its use-case and protective controls reviewed and approved by the Security and Compliance Team before release.

=== "Java stack"

    Validate the absolute URL against the allow-list through the WSO2 `SecurityUtil.validateRedirectUrl(allowedRedirectUrls, url)` helper and redirect only if it returns allowed. Reject the anti-pattern `response.sendRedirect(request.getParameter("url"))`. For the fragment case, check the fragment's type (e.g. `isInteger(index)`) before building `BASE_URL + "/info/" + index`.

=== "Go stack"

    Validate the absolute URL against the allow-list (`security.ValidateRedirectURL(allowedRedirectURLs, url)`) and return `http.StatusBadRequest` when it is not allowed. Reject the anti-pattern `http.Redirect(w, r, r.URL.Query().Get("url"), http.StatusFound)`. For the fragment case, gate on `strconv.Atoi(index)` succeeding before building the redirect, and return `http.StatusBadRequest` otherwise.

---

## Security Misconfiguration

External: [OWASP A05](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) · [HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html). Read these for the category model; this section covers what to set in WSO2 code and deployments.

Production hardening (per-product, per-version) is a separate concern from code defaults. Follow the version-indexed [Security Guidelines for Production Deployment](https://docs.wso2.com/display/ADMIN44x/Security+Guidelines+for+Production+Deployment) for your product and version; the controls below are the ones you own in code and manifests regardless of deployment.

### HTTP security headers

The header set your code should emit, and how to wire it on Carbon/Tomcat, Go services, the WSO2 API Gateway, reverse proxies, and Kubernetes ingresses, is in [HTTP Security Headers — Configuration Reference]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/security-related-http-headers/). Do not hand-roll header logic per service; delegate to that reference.

Distinguish the two tiers when reviewing a change:

* **Mandatory** on every response from a WSO2 service: framing defence (`X-Frame-Options` / CSP `frame-ancestors 'none'`, see [ClickJacking](#clickjacking-and-cross-frame-scripting) below) and `X-Content-Type-Options: nosniff`, plus any other header the companion page marks as required. Do not emit `X-XSS-Protection: 1; mode=block` — the header is deprecated, browsers have removed the XSS Auditor, and the companion page lists it under headers your code must not emit; rely on a strict nonce-based Content-Security-Policy for reflected and stored XSS defence instead. If any legacy code still emits it, set the value to `0`.
* **Configurable** (CSP source lists, HSTS `max-age` — `Strict-Transport-Security: max-age=31536000; includeSubDomains` — CORS allow-lists): version-controlled and reviewed as configuration, never hardcoded per build. Ship a long `max-age` (at least one year) with `includeSubDomains`; treat `preload` as an operator decision — an irreversible per-hostname commitment that engineers never hardcode. See [HTTP Security Headers]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/security-related-http-headers/) for the authoritative split and the recommended values.

=== "Java stack"

    Add headers through the Tomcat/Catalina `org.apache.catalina.filters.HttpHeaderSecurityFilter` servlet filter rather than setting them ad hoc in handlers, so the set is uniform across the product. The init-params (`hstsEnabled`/`hstsMaxAgeSeconds`, `antiClickJackingEnabled`/`antiClickJackingOption`, `blockContentTypeSniffingEnabled`) and wiring are in [HTTP Security Headers]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/security-related-http-headers/). Leave `xssProtectionEnabled` disabled: `X-XSS-Protection` is deprecated, the filter defaults it to `false`, and the param is removed in Tomcat 11. Where a surface is not served by Tomcat, wire the same headers through a project-local servlet filter rather than per handler.

=== "Go stack"

    Set headers in a single `securityHeadersMiddleware` that wraps the mux, so every route inherits the same set before the response is written. Do not set headers per handler.

### Container security defaults

This is net-new general engineering guidance, not extracted from the secure-coding source: the controls below are external-standard baselines adopted as the WSO2 baseline. Read [Kubernetes Pod Security Standards (Restricted)](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted) for the exact field set the Restricted profile enforces, and [NIST SP 800-190](https://csrc.nist.gov/publications/detail/sp/800-190/final) for the container-platform threat model. Pod Security, `NetworkPolicy`, and image-pinning follow those standards.

Apply at the workload and namespace level:

* **Pod Security: Restricted.** Run as non-root, drop all Linux capabilities, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault`. Enforce the profile with the namespace label `pod-security.kubernetes.io/enforce: restricted` so non-conforming pods are rejected at admission, not merely warned.
* **Distroless or minimal base image.** No shell, no package manager, no build tooling in the runtime image. This shrinks both the attack surface and the CVE-bearing dependency set.
* **Pin images by digest, not tag.** Reference `image@sha256:...`, not `image:latest` or a floating version tag, so the running artifact is the one that was scanned and approved.
* **`NetworkPolicy` default-deny per namespace.** Every namespace starts with a deny-all ingress and egress policy; each service gets an explicit allow for exactly the peers it needs. Internal services use `ClusterIP`, never `LoadBalancer`. Deny by default is the rule, not the exception.
* **`PodDisruptionBudget`** for critical workloads, so voluntary disruptions cannot drain a service below quorum.
* No secrets in images, manifests, or `ConfigMap`s. Mount them from a secret store at runtime.

Configuration is code: these belong in version-controlled manifests reviewed in the same flow as application changes, not applied imperatively against a live cluster.

!!! danger "Approval required"
    As with the other relax-a-recommended-control exceptions in this guide, relaxing any Restricted-profile field for a workload (for example, requiring a writable root filesystem, a privileged capability, or host networking) must be reviewed and approved by the Security and Compliance Team before release. State the exact field relaxed and the compensating controls in the request.

### XML External Entity (XXE)

External: [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) — see it for the per-parser flag matrix and test payloads.

!!! danger "Approval required"
    If a component requires that any of the recommended XXE-prevention flags not be set on an XML parser, the use case and the compensating controls must be reviewed and approved by the Security and Compliance Team before release.

=== "Java stack"

    Disable DTD processing and external-entity resolution on every parser instance before use, and cap entity expansion to defeat the billion-laughs DoS. Configure `DocumentBuilderFactory` (DOM) as a secured static factory:

    ```java
    // imports org.apache.xerces.impl.Constants
    private static final int ENTITY_EXPANSION_LIMIT = 0;

    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    dbf.setXIncludeAware(false);
    dbf.setExpandEntityReferences(false);
    dbf.setFeature(Constants.SAX_FEATURE_PREFIX + Constants.EXTERNAL_GENERAL_ENTITIES_FEATURE, false);
    dbf.setFeature(Constants.SAX_FEATURE_PREFIX + Constants.EXTERNAL_PARAMETER_ENTITIES_FEATURE, false);
    dbf.setFeature(Constants.XERCES_FEATURE_PREFIX + Constants.LOAD_EXTERNAL_DTD_FEATURE, false);

    SecurityManager securityManager = new SecurityManager();
    securityManager.setEntityExpansionLimit(ENTITY_EXPANSION_LIMIT);
    dbf.setAttribute(Constants.XERCES_PROPERTY_PREFIX + Constants.SECURITY_MANAGER_PROPERTY, securityManager);
    ```

    Wrap each `setFeature` in a try/catch on `ParserConfigurationException` and log the failure, then attach a custom `EntityResolver` to the resulting `DocumentBuilder` as defence in depth. For StAX, configure `XMLInputFactory` the same way:

    ```java
    private static final int ENTITY_EXPANSION_LIMIT = 0;

    XMLInputFactory xif = XMLInputFactory.newInstance();
    xif.setProperty(XMLInputFactory.IS_NAMESPACE_AWARE, true);
    xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
    // Woodstox StAX 5+: also disable entity expansion
    // xif.setProperty("com.ctc.wstx.maxEntityDepth", 1);
    ```

    Wrap each `setProperty` in a try/catch on `IllegalArgumentException` and log the failure. **Version note:** when the Woodstox StAX parser 5+ is on the classpath, additionally set `com.ctc.wstx.maxEntityDepth` to `1`. Apply the equivalent disabling flags to any other parser family you construct (`SAXParserFactory`, `TransformerFactory`, `SchemaFactory`, `Validator`); enabling `XMLConstants.FEATURE_SECURE_PROCESSING` is the JAXP-portable way to cap expansion where the Xerces `SecurityManager` is not available. Where the same parser is built in several places, centralise the configuration in a project-local helper so the flags cannot drift between call sites.

    Anti-pattern: `DocumentBuilderFactory.newInstance()` then `parse(inputStream)` (or `XMLInputFactory.newInstance()` then `createXMLEventReader(...)`) with no security configuration.

=== "Go stack"

    `encoding/xml` does not process DTDs or external entities, so standard parsing (`xml.Unmarshal` into a struct, or `xml.NewDecoder(r).Decode(&t)`) is not XXE-vulnerable by default. The risk reappears when XML is routed through a third-party library or a custom entity resolver that does process DTDs; check such a library's defaults explicitly before adopting it, and prefer the standard package.

### ClickJacking and Cross Frame Scripting

External: [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html) — read for the framing-defence test cases.

Emit both the standard CSP directive and the legacy header on every page, especially admin consoles:

* `Content-Security-Policy: frame-ancestors 'none'` in all cases, except where the product must frame a page exposed elsewhere in the **same product**, where `frame-ancestors 'self'` may be used.
* `X-Frame-Options: DENY` in all cases, or `SAMEORIGIN` for the same-product framing exception.

Set the values through the [HTTP Security Headers]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/security-related-http-headers/) configuration; do not invent per-page values.

=== "Java stack"

    Add the framing headers via the `org.apache.catalina.filters.HttpHeaderSecurityFilter` servlet filter so coverage is uniform.

=== "Go stack"

    Set `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'` in the shared `securityHeadersMiddleware` that wraps the mux.

!!! danger "Approval required"
    If a component requires that framing of a page be allowed globally, the use case and the compensating controls must be reviewed and approved by the Security and Compliance Team before release.

### Cross-Origin Resource Sharing

External: [MDN — CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) · [OWASP HTML5 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing).

* Reject `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true` at code review — the combination is invalid and browsers will not honour it, but shipping it signals a misunderstanding of the trust boundary.
* A wildcard `Access-Control-Allow-Origin` is appropriate only for content that is fully public to any site. It must not be the default in WSO2 products. Where a wildcard option exists, an admin must be able to switch it to domain-level restriction; the allow-list is configuration, version-controlled and reviewed.
* Admin and management APIs must be domain-restricted, never wildcard.

!!! danger "Approval required"
    If a component requires that `Access-Control-Allow-Origin` be used with a wildcard and the admin is not given the option to switch to domain-level restriction, the use case and the compensating controls must be reviewed and approved by the Security and Compliance Team before release.

### API inventory, versioning, deprecation

This topic is not covered by the secure-coding source; the guidance here is general engineering practice plus standard stack technique. Read [OWASP API9:2023](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/) for the inventory-management failure modes, and [RFC 8594 — Sunset header](https://datatracker.ietf.org/doc/html/rfc8594) for the deprecation-signalling contract before emitting deprecation signals.

Unmanaged versions and undocumented endpoints are the misconfiguration here: an old `/v1` left running, a debug route never removed, a host with no spec. Controls:

* **Inventory is authoritative and generated, not maintained by hand.** Every reachable endpoint, on every host and version, appears in a machine-readable spec. Routing is driven from that spec; a handler that is not in the spec is a defect.
* **Deny by default for non-public surfaces.** Internal, debug, and management endpoints are not reachable from public ingress. Bind them to localhost or an internal network and front them with a deny-default `NetworkPolicy`.
* **Signal deprecation in the response using the standard contract.** Per RFC 8594, emit `Sunset` (with the retirement date), `Deprecation`, and a `Link` to the migration guide on deprecated resources so consumers can detect and act before removal. Use your stack's normal response-header mechanism; this is standard HTTP technique, not a WSO2-specific control.
* **Retire on a schedule.** Track deprecated versions to a removal date; do not leave superseded versions serving traffic indefinitely.

=== "Java stack"

    Drive routing from a machine-readable spec and fail the CI build when a handler exists that is not declared in the spec, so the inventory stays honest. Emit `Sunset`/`Deprecation`/`Link` on deprecated resources through your normal response-header path. Product-specific inventory tooling (gateway publisher portals, federated-trust lists, and similar) is out of scope of this guide; follow the relevant product documentation.

=== "Go stack"

    Generate the router from the OpenAPI spec, or fail the CI build when a handler exists that is not declared in the spec — this keeps the inventory honest. Expose internal endpoints through `ClusterIP` services plus a `NetworkPolicy`, never a `LoadBalancer`.

### Default credentials, sample apps, management console exposure

WSO2-specific operational rules — these are the defaults attackers try first:

* **Rotate the Carbon admin password before any exposure.** Replace all shipped keystore and truststore passwords as well. Store the rotated secrets in the product's secure secret store or an external secret manager; never leave them in plaintext config or commit them.
* **Remove or isolate sample apps and demo content** before production. Do not ship demo artifacts on a public surface.
* **Keep the Carbon Management Console, JMX, debug/profiling, and any reflection or diagnostic endpoints off public ingress** — bind them to localhost or an internal network. Document every default credential, default certificate, and open port in the product documentation so operators can harden them.
* **Suppress version-disclosing response banners and headers** so the running version is not advertised; follow the version-indexed production-deployment guide for the exact settings.
* **Do not grant the Management Console "login" permission to self-registered users.** Deny it by default and grant it explicitly only to roles that need console access. This is particularly important for API Manager Store users, who must not reach the admin console.
* Keep production and staging configured identically, with config and artifact promotion automated through change management, so no unreviewed configuration change lands directly in production.

---

## Software Supply Chain Failures

External: [SLSA](https://slsa.dev/) for the build-integrity levels to target · [OWASP SCVS](https://owasp.org/www-project-software-component-verification-standard/) for the component-verification checklist. Read these for the threat model and the maturity targets; the controls below are what they translate to in WSO2 product code.

Deployments that diverge from the official release baseline are the recurring supply-chain failure pattern: an artefact, dependency, or build step that no longer matches what was reviewed and released.

Operational rules:

* Pin every dependency to an exact version. Commit lock files (`go.sum`, `package-lock.json`, `pnpm-lock.yaml`). CI installs from the lock file, never re-resolving: `npm ci`, `pnpm install --frozen-lockfile`, `GOFLAGS=-mod=readonly`.
* Resolve every dependency from a single organisation-controlled source per ecosystem; resolution from any other source is a reviewable change.
* Generate an SBOM (CycloneDX or SPDX) for each release and attach it to the artefact, so a newly disclosed CVE can be mapped to shipped releases without a rebuild.
* Sign every released artefact on protected infrastructure with a short-lived signing identity, and verify the signature before promoting or deploying the artefact.
* Least-privilege `permissions:` on every CI workflow. Never run `pull_request_target` with secrets without an explicit approval gate — a fork PR runs attacker-controlled code with the base repo's token.

=== "Java stack"

    Restrict resolution to the organisation-controlled repositories and inherit that configuration from the parent POM, so any addition to the trusted set goes through one reviewable diff rather than being re-declared per component. Set `checksumPolicy` to `fail` so a corrupted or tampered artefact aborts the build instead of being silently accepted. Do not add `<repository>` entries pointing at arbitrary third-party or personal repositories — a new resolution source is a reviewable change, not a convenience edit.

=== "Go stack"

    Commit `go.sum` alongside every `go.mod` change and run CI with `GOFLAGS=-mod=readonly` so the build fails rather than silently rewriting the module graph:

    ```yaml
    env:
      GOFLAGS: "-mod=readonly"
    on:
      pull_request:
        paths:
          - '**/go.mod'
          - '**/go.sum'
    ```

    `replace` directives in `go.mod` are review-required — they redirect a module to an unverified source. For air-gapped builds, document the required `GOPROXY` (an internal mirror, never `direct`). Scope checksum-database exemptions to internal module paths with `GOPRIVATE` (which sets the defaults for `GONOPROXY`/`GONOSUMDB`) and only with explicit approval — never disable checksum verification globally.

### Using Known Vulnerable Components

Read [OWASP A06:2021 — Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/) for why this is a top-ranked risk, and consult [NVD](https://nvd.nist.gov/) and [Exploit-DB](https://www.exploit-db.com/) to assess a specific component's exposure. The operational scanning workflow — CLI versus Maven-plugin usage, suppression-file format, NVD sync intervals, and the report walkthrough — lives in [Dependency Vulnerability Analysis]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/external-dependency-analysis-analysis-using-owasp-dependency-check/). This section covers the engineering rules and the governance gates around it.

**Introducing a new dependency**

* Select the most up-to-date version of the component, then scan that version — and all transitive dependencies it pulls in — for known vulnerabilities with OWASP Dependency Check before proposing it.
* Attach the generated Dependency Check report to the Approval Request and copy the request to the Security Leads Group.
* If the latest version still carries a known vulnerability and the component is no longer actively developed, prefer a maintained alternative over the vulnerable library.

!!! danger "Approval required"
    A dependency Approval Request submitted **without** the OWASP Dependency Check report will be downvoted by the Security and Compliance Team. Introducing any component with a known vulnerability is prohibited outside the reviewed exception path: the Security and Compliance Team must be informed and must review the use case, source code, the known vulnerabilities, and the controls mitigating impact along the usage path. SC Team approval is required **before** that dependency is introduced.

**Handling a vulnerability found in a current dependency**

When a scan flags an existing dependency, do not jump straight to a suppression. Triage it:

1. Open a thread on the Security Group mailing list with the subject `Dependency Vulnerability - [DependencyName] - [DependencyVersion] - [CVE]`.
2. Analyse whether WSO2's actual usage of the component is reachable by the vulnerability.
    * **Reachable, fix available:** migrate to a version with no known vulnerability.
    * **Reachable, no fixed version:** nullify the impact in WSO2's usage path with additional validation or security checks (this hardening is itself approval-gated, below).
    * **Not reachable in WSO2's usage:** document the reasoning on the thread and request approval to record it in the Dependency Check suppression file. Suppress only genuine non-exploitable findings after this per-vulnerability analysis — never blanket-suppress to make a build pass.

!!! danger "Approval required"
    When no newer version exists and the component is unmaintained, the Security and Compliance Team must review any validations or security constraints added to nullify the vulnerability's impact. Separately, any pull request adding entries to a component's OWASP Dependency Check suppression file must be reviewed **and merged** by the Security and Compliance Team; the review covers the mitigated reason, the dependency source, and the usage path.

=== "Java stack"

    Integrate the OWASP Dependency Check Maven plugin (`org.owasp:dependency-check-maven`, goal `check`) into the product build so scheduled CI runs surface vulnerable transitive dependencies automatically. Engineers reproduce a scan locally with the `dependency-check:check` goal. Set `failBuildOnCVSS` so the build fails when a dependency's CVE has a CVSS score at or above the agreed threshold (the linked doc uses `7`, then `8`) rather than reporting and continuing, and set `cveValidForHours` to control how often a build re-checks the NVD (the linked doc uses `12`). The first run downloads the NVD into a local database and reuses it within the default 4-hour sync window. A suppression entry is a `<suppress>` element in the `<suppressions>` XML document that identifies a library by its `<sha1>` and the specific `<cve>` — never a blanket suppression. See [Dependency Vulnerability Analysis]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/external-dependency-analysis-analysis-using-owasp-dependency-check/) for plugin configuration and suppression-file syntax.

=== "Go stack"

    The Dependency Check tooling is Maven/JAR-oriented; for Go modules run `govulncheck ./...` in CI as the equivalent SCA gate — it reports only vulnerabilities reachable from your call graph, which keeps triage focused. Fail the pipeline on a reported vulnerability and route any proposed exception through the same Security and Compliance Team gate as above; there is no Go suppression-file equivalent, so document accepted findings in the Approval Request.

    For front-end (npm) packages, complete the dependency onboarding process before adopting a new package, run `npm audit` to confirm it carries no known vulnerabilities, and reject packages that default to insecure handling of HTML or script content.

### Unsafe consumption of upstream APIs

Read [OWASP API10:2023 — Unsafe Consumption of APIs](https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/) for the test cases; the failure mode is trusting a third-party or partner API more than direct user input. Every upstream response is untrusted.

* Validate the response before using it: check the HTTP status, assert the `Content-Type`, parse against an expected schema, and bound the body size before decoding so a hostile or runaway upstream cannot exhaust memory.
* Apply the outbound TLS rules from [Cryptographic Failures](#cryptographic-failures) to every outbound call — verify the chain and hostname; never disable verification to "make it work".
* Bound every call with a connect/read timeout and wrap it in a circuit breaker so a slow or failing upstream cannot cascade into your own request threads.
* Treat the JWKS (or any key/trust-material) endpoint as **configured trust**. Resolve it from a value you control in configuration, not from a URL, `kid`, or `Location` the token or upstream supplies at runtime — letting the caller name where to fetch the verification key defeats the signature check.
* Never forward an upstream redirect (`Location`), error body, or supplied URL into a server-side request without allow-list validation — that is the SSRF path (see [Broken Access Control](#broken-access-control) for redirect/forward allow-listing).

=== "Java stack"

    Pin each upstream's trust material in configuration you control, not from a runtime-supplied URL or `kid`, and rotate it with an overlap window so a rotation does not cause an outage. Configure explicit connection and socket timeouts on the HTTP client (defaults are often unbounded). Validate the deserialised response into a typed DTO and reject anything that does not match, rather than consuming a loosely-typed `Map`.

=== "Go stack"

    Set a deadline per request with `context.WithTimeout` (never rely on the zero-value `http.Client`, which has no timeout), and read the body through `http.MaxBytesReader` before decoding. Wrap outbound calls in a circuit breaker (`sony/gobreaker` or equivalent). Decode into a typed struct with `json.Decoder` and call `DisallowUnknownFields()` so an unexpected payload shape fails loudly instead of being silently accepted.

---

## Cryptographic Failures

Cryptographic failures cover weak or misused algorithms, mishandled keys, broken transport, forgeable tokens, and sensitive material left readable in memory. Most of this is net-new relative to the upstream guideline, so the canonical reading lives outside WSO2; the WSO2 rules are about *where* crypto lives in product code and *which* deviations need approval.

Read these for the parameters; do not restate them in code or comments, reference the current version at implementation time:

* **[NIST SP 800-131A](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final)** — read it for the approved-algorithm list and the transition schedule. Anything NIST currently marks legacy or disallowed (MD5, SHA-1, 3DES, RC4, RSA without padding, AES without an authenticated mode) is banned in WSO2 product code.
* **[NIST SP 800-52 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)** — read it for the TLS protocol and cipher selection rules that apply to government-grade deployments.
* **[OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)** — read it for symmetric/asymmetric primitive choice, nonce/IV handling, and key lifecycle.
* **[OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)** — read it for the current Argon2id / scrypt / bcrypt / PBKDF2 work-factor parameters. These move over time: use the values current at implementation time, store the algorithm name and parameters alongside the hash so they can be migrated, and re-evaluate every release.
* **[Mozilla TLS configuration generator](https://ssl-config.mozilla.org/)** — generate the cipher suite, protocol, OCSP, and HSTS config for the terminator from the "Intermediate" or "Modern" profile and pin to it rather than hand-rolling.
* **[RFC 8725 — JWT BCP](https://datatracker.ietf.org/doc/html/rfc8725)** — read it for algorithm allow-listing, the alg-confusion attack, `kid`/`jwk` header handling, and required claim validation.

WSO2 rules that apply on top of the external baselines:

* **Centralise crypto behind the platform facade — do not hand-roll.** Product code that encrypts or decrypts a secret (refresh tokens, IdP credentials, vault-managed configuration) goes through the platform crypto facade, not a raw `Cipher` / `crypto/aes` call scattered through a component. Centralising keeps algorithm, mode, and key selection in one auditable place that can be upgraded when NIST guidance moves.
* **A JWT algorithm allow-list is data, not code.** Each verifier accepts an explicit, configured set of algorithms. **Reject `alg: none`**, and reject HMAC algorithms where the verifier holds an asymmetric (public) key — that is the alg-confusion attack RFC 8725 describes.
* **Never honour an inline `jwk` (or `jku`) header.** Resolve keys by `kid` against a JWKS pinned to the trusted issuer. An inline key in the token lets the sender choose their own verification key.
* **Hardcoded TLS-verification bypasses are defects.** A literal hostname-verification or certificate-verification disable in a production path fails review. An operator-configurable bypass is acceptable only with a secure default of "verify" and a deployment-time warning when it is switched off (see the approval gate below).

=== "Java stack"

    **Use the platform facade.** Route all secret encryption and decryption through the Carbon `CryptoUtil` facade (or a crypto service injected where the component runs) rather than calling `Cipher.getInstance(...)` directly from product code. Resolve the exact encrypt/decrypt method names against the `CryptoUtil` API at implementation time (e.g. an `encrypt`/`decrypt` or base64-wrapping pair — method names illustrative).

    Where a code path genuinely must construct a `Cipher` (a legacy or framework boundary), name the transformation explicitly and use an authenticated mode:

    * `AES/GCM/NoPadding` — 96-bit random IV per message, persist `iv || ciphertext`, **never reuse an IV with the same key**.
    * `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` for asymmetric wrapping. Never `RSA/ECB/PKCS1Padding` or no-padding.

    **JWT verification** uses an explicit algorithm allow-list before any signature check. The shape (illustrative — restrict to the algorithms the verifier actually supports, then look up the key by `kid`):

    ```java
    JWSAlgorithm alg = signedJWT.getHeader().getAlgorithm();
    if (alg == null
            || !ALLOWED_ALGORITHMS.contains(alg)          // e.g. RS256/RS384/RS512
            || JWSAlgorithm.NONE.equals(alg)) {
        throw new SecurityException("Unsupported or disallowed JWT algorithm");
    }
    // resolve the verification key by kid from the issuer's pinned JWKS — never an inline jwk header
    ```

    Private-key passphrases and other secrets must never live in source or plaintext config. Resolve them at runtime through the platform's secret-resolution facility (a secret-vault facility such as the platform's configured secret store) so the cleartext value exists only in memory.

    **TLS.** New `SSLContext` construction sets a minimum of TLS 1.2 but prefers TLS 1.3 where available — include `TLSv1.3` in the enabled protocols and let the handshake negotiate it, falling back to 1.2 only for compatibility (TLS 1.3 brings mandatory forward secrecy and AEAD-only suites). Enable hostname verification with `SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")`, and never install an all-trusting hostname verifier or trust manager. New components must not add an "allow all / trust all" opt-out, even behind a system property.

    **Constant-time comparison.** Compare MACs and other secret-derived values with `MessageDigest.isEqual(byte[], byte[])`, never `Arrays.equals` (not constant-time in older JDKs).

=== "Go stack"

    **Use the central crypto package** — never call `crypto/aes`, `crypto/rsa`, or `crypto/sha256` directly from scattered product code. A central encryption package (a dispatcher plus per-algorithm providers) is the established shape; new services follow it so the algorithm and key choice stay in one auditable place.

    AES-GCM with a fresh random nonce per call, error handled:

    ```go
    func encryptAESGCM(key, plaintext []byte) ([]byte, error) {
        block, err := aes.NewCipher(key)
        if err != nil {
            return nil, fmt.Errorf("create AES cipher: %w", err)
        }
        aesgcm, err := cipher.NewGCM(block)
        if err != nil {
            return nil, fmt.Errorf("create GCM mode: %w", err)
        }
        nonce := make([]byte, aesgcm.NonceSize())
        if _, err := rand.Read(nonce); err != nil { // crypto/rand
            return nil, fmt.Errorf("generate nonce: %w", err)
        }
        return aesgcm.Seal(nonce, nonce, plaintext, nil), nil
    }
    ```

    **JWT** — restrict the accepted algorithm at parse time inside the keyfunc, then resolve the key by `kid`:

    ```go
    token, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
        switch t.Method.Alg() {
        case "RS256", "RS384", "ES256": // explicit allow-list; "none" never reaches here
        default:
            return nil, fmt.Errorf("unsupported alg %q", t.Method.Alg())
        }
        kid, _ := t.Header["kid"].(string)
        return jwks.GetKey(kid) // pinned issuer JWKS — never an inline jwk header
    })
    ```

    **TLS** — set `tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}` on every outbound client and server config as the minimum floor, but expect the negotiated protocol to prefer TLS 1.3: Go's `crypto/tls` negotiates 1.3 by default when `MinVersion` permits, with 1.2 retained only for compatibility. `InsecureSkipVerify: true` is acceptable only when operator-configured with a secure default of `false`; a hardcoded `true` is a defect.

    **Constant-time comparison** with `crypto/subtle.ConstantTimeCompare` (or `hmac.Equal` for MACs).

### Random Number Generation

Security-sensitive values (tokens, salts, IVs, nonces, session IDs, password prefixes) must come from a cryptographically secure PRNG. The risk is low available entropy at PRNG initialisation, which makes some output values more likely than others — read the OWASP guidance referenced in the upstream guideline for the failure modes. In containers this is sharper: entropy gathering takes significant time at instance spawn.

=== "Java stack"

    Use `java.security.SecureRandom`, never `java.util.Random`, for anything security-sensitive (`new Random().nextInt(...)` for a token or password prefix is the anti-pattern).

    For per-request security values (tokens, salts, IVs, nonces, session IDs) use the no-arg `new SecureRandom()`. On a modern JDK/Linux its default provider (NativePRNG) draws its `nextBytes` output from `/dev/urandom`, which is non-blocking, and the instance self-seeds on first use — so there is no manual reseeding to manage and no stall to design around. Do not pin a fixed legacy algorithm string.

    Reuse a single `SecureRandom` instance (for example via a `static` field or a `ThreadLocal`) rather than constructing one per call. Do **not** rotate the instance after a usage count, periodically discard and recreate it, or call `setSeed` / `generateSeed` for routine generation: NativePRNG (and the DRBG providers) are reseeded from the OS CSPRNG, so a usage-count rotation mitigates no real degradation, `generateSeed` can map to the blocking `/dev/random` source on some configurations, and per the [`SecureRandom` javadoc](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/SecureRandom.html) `setSeed` supplements rather than replaces the existing seed, so self-supplied material does not add entropy.

    Reserve `SecureRandom.getInstanceStrong()` for generating long-lived, high-value secrets such as RSA/EC key pairs, where it maps to a strong (typically `/dev/random`-backed) source and occasional blocking to gather extra entropy is acceptable. If an explicit algorithm string is mandated for compliance, use `SecureRandom.getInstance("DRBG")` (NIST SP 800-90A), never the legacy `SHA1PRNG`, which is weaker than the approved DRBG mechanisms and is flagged by static analysers.

=== "Go stack"

    Use `crypto/rand`, never `math/rand`, for security-sensitive values (`math/rand` seeded from `time.Now().UnixNano()` is the anti-pattern — it is deterministic). **Always check the error** returned by `crypto/rand` functions; a non-nil error signals an entropy problem and the value must not be used.

    When range-limiting a random integer, use a method that preserves uniformity (`crypto/rand.Int` with a `*big.Int` bound) — **avoid modulo bias** from `value % n`. Ensure containers have a working entropy source. `golang.org/x/crypto` covers higher-level primitives that need randomness.

### Heap Inspection

If a password or key is left in memory after use, an attacker with a memory dump (or similar access) can read it — a heap inspection attack. Hold secrets in a mutable type and zero them as soon as the operation that needs them completes, before the variable goes out of scope. (See also the [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) for in-memory key handling.)

=== "Java stack"

    Collect and store secrets as `char[]` (or another mutable type), never `java.lang.String` — `String` is immutable, has no method to overwrite its contents, and can survive multiple GC cycles after it is unreferenced. Clear the array after use, e.g. `Arrays.fill(pw, '\0')`, before it leaves scope.

    The anti-patterns are (1) reading a password into a `String`, and (2) reading it into a `char[]` but never clearing it. Carbon's `SecurityUtil` provides helpers for this: `SecurityUtil.getSensitiveDataMap(request, SENSITIVE_PARAMETER_NAME_LIST)` returns the sensitive parameters as a `Map<String, Object>` from which a parameter is retrieved as `char[]`, and `SecurityUtil.clearSensitiveDataMap(...)` zeroes them after use.

=== "Go stack"

    Go strings are immutable and cannot be zeroed, so keep secret material in `[]byte` from the point it is read. Explicitly zero the slice before it goes out of scope:

    ```go
    func clearSensitiveData(data []byte) {
        for i := range data {
            data[i] = 0
        }
    }
    ```

    The anti-patterns are returning a secret as a `string`, or holding it in a `[]byte` that is never cleared.

### Securing Cookies

External: read the [OWASP Session Management Cheat Sheet — Cookies](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies) for the attribute rationale and test cases.

Sensitive cookies such as `JSESSIONID` are stolen over insecure networks or through an XSS vulnerability when their attributes are weak. WSO2 baseline for every session and authentication cookie:

* **`Secure`** — set it so the browser only sends the cookie over HTTPS. Java: `cookie.setSecure(true)`. Go: `Secure: true` on the `http.Cookie`.
* **`HttpOnly`** — set it so client-side JavaScript cannot read the cookie, mitigating XSS-driven session theft. Java: `cookie.setHttpOnly(true)`. Go: `HttpOnly: true` on the `http.Cookie`.
* **`SameSite=Lax`** (or `Strict` for high-sensitivity flows) to blunt CSRF.
* **`Path`** set to the narrowest scope that works; `Domain` only when cross-subdomain sharing is genuinely required.
* **No `expires` / `max-age`** — a sensitive cookie must be a session cookie so it dies with the browser session.

Wiring response headers (and HSTS at the terminator) is in [HTTP Security Headers — Configuration Reference]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/security-related-http-headers/).

!!! danger "Approval required"
    Omitting the `Secure` attribute, or omitting the `HttpOnly` attribute, on a sensitive cookie must be reviewed and approved by the Security and Compliance Team before release.

---

## Injection

External: [OWASP A03](https://owasp.org/Top10/A03_2021-Injection/) · [Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html) · [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html).

### Input validation

The general rules (allow-list not deny-list, length caps, format validation, canonicalisation before validation, refuse unknown JSON fields, bound parser cost) are in the OWASP Input Validation Cheat Sheet. Read it for the canonical allow-list/canonicalisation order; below is what to do in WSO2 code.

Validation must run server-side — front-end validation is for UX only and is trivially bypassed. In Carbon 4 based products, input validation is given a lower priority and is performed only on essential screens, so it cannot be the line of defence on its own. Treat output encoding and output sanitization (see [Cross-Site Scripting](#cross-site-scripting-xss)) as mandatory and treat parameterisation/escaping at each sink (see the subsections below) as the primary control. Input validation is defence in depth, not the boundary.

=== "Java stack"

    Jakarta Bean Validation (`@Email`, `@Pattern`, `@Size`, `@Min`/`@Max`, custom validators) on DTOs. Refuse unknown JSON fields with `mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)` or `@JsonIgnoreProperties(ignoreUnknown = false)`. Configure `StreamReadConstraints` to bound Jackson parser cost on adversarial input. Set `maxRequestSize` at the servlet container.

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

External: [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) — read it for parameterised queries (Defense Option 1) and the [allow-list input validation pattern](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html#defense-option-4-allowlist-input-validation) for dynamic identifiers (Defense Option 4), which has the worked code shapes.

WSO2 rule: use a compiled/prepared statement with bind variables for every *value*. SQL *identifiers* — table names, column names, an `ORDER BY` column, sort direction, offset — **cannot** be bound as parameters; an `ORDER BY` column name in particular is not a legal `PreparedStatement` parameter. Where the query needs a dynamic identifier, restructure the method so it does not accept the raw identifier from the caller; map a fixed set of user-facing keys to real column/table names through a static allow-list and reject anything not in the set. Concatenating an identifier into the query string is injectable even when every other value is bound.

=== "Java stack"

    `PreparedStatement` with `?` placeholders and `setXxx` for every value. For non-parameterisable segments, keep a class-level `static final Map<String, String>` from allowed input keys to real column/table names; look up the value and reject (return / throw) on a `null` result. Normalise sort direction by equality check — `orderDirection.equalsIgnoreCase("DESC")` selects `DESC`, otherwise fall back to `ASC`.

    ```java
    // Values — always bound
    try (PreparedStatement ps = conn.prepareStatement(
            "SELECT id, name FROM users WHERE tenant_id = ? AND user_id = ?")) {
        ps.setInt(1, tenantId);
        ps.setString(2, userId);
        try (ResultSet rs = ps.executeQuery()) { /* ... */ }
    }

    // Identifier — allow-list, never concatenated raw
    private static final Map<String, String> VALID_ORDER_COLUMNS = Map.of(
            "name", "NAME", "created", "CREATED_AT");
    String column = VALID_ORDER_COLUMNS.get(orderColumn);   // user-facing key
    if (column == null) { throw new IllegalArgumentException("invalid sort column"); }
    String direction = "DESC".equalsIgnoreCase(orderDirection) ? "DESC" : "ASC";
    String sql = "SELECT id, name FROM users WHERE tenant_id = ? ORDER BY " + column + " " + direction;
    ```

    Anti-pattern — reject in code review: concatenating `request.getParameter(...)` into a `Statement.executeQuery` string, and concatenating an `order`/`column`/`table` value into the query even when the other params are bound.

=== "Go stack"

    `database/sql` with placeholders (`?`, `$1`, `:name` — the syntax is driver-specific, check the driver docs). For a one-shot query use `db.QueryContext(ctx, query, args...)`; for a reused statement, `db.PrepareContext` then `stmt.QueryContext`, with `defer stmt.Close()` / `defer rows.Close()`. Prepared statements cannot parameterise identifiers, so allow-list them through a package-level `map[string]string` with a comma-ok lookup.

    ```go
    // Value — always a placeholder
    row := db.QueryRowContext(ctx,
        "SELECT id, name FROM users WHERE tenant = $1 AND id = $2",
        tenantID, userID)

    // Identifier — allow-list with comma-ok, never concatenated raw
    var validOrderColumns = map[string]string{
        "name": "NAME", "created": "CREATED_AT",
    }
    column, ok := validOrderColumns[orderColumn]
    if !ok { return fmt.Errorf("invalid sort column %q", orderColumn) }
    direction := "ASC"
    if strings.ToUpper(orderDirection) == "DESC" { direction = "DESC" }
    query := "SELECT id, name FROM users WHERE tenant = $1 ORDER BY " + column + " " + direction
    ```

    Anti-pattern — reject in code review: `db.Query("... WHERE user_name = '" + name + "'")` and concatenating `order`/`column`/`table` into the query string.

### LDAP Injection

External: [OWASP LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html) — read it for the [search-filter character set](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html#defenses) that must be escaped (`*`, `(`, `)`, `\`, NUL) and the separate [distinguished-name character set](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html#distinguished-name-escaping) (different rules — filter escaping and DN escaping are not interchangeable).

WSO2 rule: every user input appended to an LDAP filter or DN must pass through a proper LDAP encoding function before it reaches the search request. Building a filter with `String.format` / `fmt.Sprintf` / string concatenation on raw input is a security defect even when the input "looks like" a username.

=== "Java stack"

    Escape each filter value through the escaping helper your LDAP client library provides before substituting it into the filter — an `escapeSpecialCharactersForFilter(...)`-style helper, applied consistently to every value. (Library-specific equivalents exist — e.g. Spring Security's `LdapEncoder.filterEncode` / `nameEncode`, or the Apache Directory API escaping utilities — these are illustrative examples, not a prescribed WSO2 API; pick whatever your library ships.) Filter values and DN components use different escaping; do not reuse one for the other.

    ```java
    // Anti-pattern — raw value in the filter
    searchFilter.replace("?", role);
    // Safe — escaped before substitution
    searchFilter.replace("?", escapeSpecialCharactersForFilter(role));
    ```

=== "Go stack"

    Escape filter values with `ldap.EscapeFilter` from `github.com/go-ldap/ldap/v3` before building the search request.

    ```go
    import "github.com/go-ldap/ldap/v3"

    // Anti-pattern — raw value in the filter
    f := strings.Replace(searchFilter, "?", role, -1)
    // Safe — escaped
    f := strings.Replace(searchFilter, "?", ldap.EscapeFilter(role), -1)
    ```

### OS Command Injection

External: [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html).

WSO2 products and applications should not construct OS commands from user input at all. The guideline gives no "safe" sanitisation recipe for running a user-derived command — the prescribed control is to avoid it. If a use case genuinely requires execution, pass a fixed program with arguments as an argument array so no shell parses the input. Never the single-string form; never `sh -c "…"` with interpolated input.

!!! danger "Approval required"
    Any code path that must append user input to an OS command, or interpret user input as an OS command, must have the use case **and** the protective controls reviewed and approved by the Security and Compliance Team before the component is released.

=== "Java stack"

    Do not run user-derived commands via `Runtime.getRuntime().exec(...)`, `ProcessBuilder`, or any other command-execution API.

    ```java
    // Anti-patterns — reject in code review
    Runtime.getRuntime().exec("convert " + userFilename + " out.png");
    new ProcessBuilder("/bin/sh", "-c", "convert " + userFilename + " out.png").start();

    // If execution is unavoidable (after SC Team approval): argument array, no shell
    new ProcessBuilder("convert", userFilename, "out.png")
            .redirectErrorStream(true).start();
    ```

=== "Go stack"

    Do not run user-derived commands via the `os/exec` package (`exec.Command` / `exec.CommandContext`).

    ```go
    // Anti-pattern — reject in code review
    exec.CommandContext(ctx, "sh", "-c", "convert "+userFilename+" out.png")

    // If execution is unavoidable (after SC Team approval): argument slots, no shell
    cmd := exec.CommandContext(ctx, "convert", userFilename, "out.png")
    cmd.Stdin = nil
    out, err := cmd.CombinedOutput()
    ```

### Cross-Site Scripting (XSS)

External: [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) · [OWASP DOM-based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html). Pair output encoding with a strict CSP — see [HTTP Security Headers]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/security-related-http-headers/).

Three controls, applied per field by whether the field is meant to carry HTML:

- **Output encoding** — for output that should *not* contain HTML (e.g. an API description field): convert special characters to HTML entity references at the output context.
- **Output sanitization** — for output that *is* expected to contain HTML (e.g. API documentation content): allow a safe subset of tags/attributes and strip dangerous ones (`<script>`, event-handler attributes).
- **Browser-level protection** — the legacy `X-XSS-Protection` header is deprecated and the browser XSS auditor it controlled is gone from modern browsers (removed from Chrome in v78, never implemented in Firefox) and could itself introduce vulnerabilities. Do not rely on it. Send `X-XSS-Protection: 0` (or omit it) and rely on a strict Content-Security-Policy together with output encoding/sanitization. Wire CSP and the rest of the header set through [HTTP Security Headers]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/security-related-http-headers/).

In Carbon 4 based products, input validation is low-priority, so output encoding and sanitization are mandatory — do not rely on input validation to stop XSS.

=== "Java stack"

    **Output encoding.** [OWASP Java Encoder](https://owasp.org/www-project-java-encoder/), which encodes per output context — pick the method for the context the data lands in: `Encode.forHtml` (HTML body), `Encode.forHtmlAttribute`, `Encode.forJavaScript` (inside an `onclick` handler or a `<script>` block), `Encode.forUri` (an `href`). In JSPs, the encoder taglib (`<e:forHtml/>`) is preferred over JSTL `<c:out/>`. Never write user-supplied data into a JSP with raw `<%= %>`.

    **Output sanitization** (distinct from encoding — for fields that must accept HTML rather than have it escaped). Use the [OWASP Java HTML Sanitizer](https://owasp.org/www-project-java-html-sanitizer/), limited to a pre-packaged policy: start with `Sanitizers.FORMATTING`, and combine with `LINKS` / `IMAGES` / `TABLES` only if those are needed — `Sanitizers.FORMATTING.and(Sanitizers.LINKS)`, then `policy.sanitize(html)`.

    !!! danger "Approval required"
        Defining a custom sanitizer policy or rule, rather than using the pre-packaged policies, must have the policy and its use cases reviewed and approved by the Security and Compliance Team before release.

    **Browser-level protection.** Do not emit `X-XSS-Protection: 1; mode=block`. The header is deprecated and the auditor it enabled is gone from modern browsers and can itself introduce vulnerabilities. Focus browser-level defence on a strict nonce-based Content-Security-Policy alongside the OWASP Java Encoder output encoding above. If you wire the standard `org.apache.catalina.filters.HttpHeaderSecurityFilter` for other headers, note that its `X-XSS-Protection` support (`xssProtectionEnabled`) is deprecated, defaults to false, and is removed in Tomcat 11 — leave it disabled. Full product and deployment config lives on [HTTP Security Headers]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/security-related-http-headers/).

=== "Go stack"

    **Output encoding.** Render HTML with `html/template`, never `text/template` — `html/template` auto-escapes per context (HTML body vs. attribute vs. `<script>` vs. URL). For manual encoding outside a template, wrap input with `html.EscapeString`; for a value injected into a script context, marshal it with `encoding/json` and inject it as `template.JS`; for a URL, use `template.URLQueryEscaper`.

    **Output sanitization** (for fields that must accept HTML). Use an established sanitizer such as `bluemonday` with a strict pre-built policy — `bluemonday.UGCPolicy()` allows only a limited subset of HTML; inject the sanitized result as `template.HTML`.

    !!! danger "Approval required"
        Defining a custom sanitization policy (in `bluemonday` or any other library), rather than using a strict pre-built policy, must be reviewed and approved by the Security and Compliance Team before release.

    **Browser-level protection.** Do not emit `X-XSS-Protection: 1; mode=block`. The header is deprecated and the auditor it enabled is gone from modern browsers and can itself introduce vulnerabilities. If anything is set, disable the legacy auditor with `w.Header().Set("X-XSS-Protection", "0")`, or omit the header entirely. Put browser-level defence into a strict nonce-based Content-Security-Policy set via the shared `securityHeadersMiddleware` instead. Full config lives on [HTTP Security Headers]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/security-related-http-headers/).

=== "Client-side (JavaScript)"

    Encode at the DOM sink, not by hand-building HTML strings. Avoid `.innerHTML` / jQuery `.html()` and similar HTML-insertion APIs with dynamic content. Use `.textContent` / jQuery `.text()` for dynamic text; when you must build HTML, create DOM nodes programmatically and append text to them. If dynamic input forms an HTML attribute value, additionally escape quotes — `.replace(/"/g, "&quot;").replace(/'/g, "&#39;")`. See the DOM-based XSS cheat sheet above for the full sink list.

### HTTP Response Splitting (CRLF Injection)

External: [OWASP HTTP Response Splitting](https://owasp.org/www-community/attacks/HTTP_Response_Splitting) — read it for how a CR/LF (`%0d`/`%0a`) smuggled into a header lets an attacker emit a second, attacker-controlled response (cache poisoning, reflected XSS).

For Carbon 4 based products, Apache Tomcat handles this internally by disallowing CR and LF in header names and values, so application code on the Tomcat transport does not need its own filter. If HTTP responses are generated by a different component or transport implementation, confirm it performs equivalent CR/LF filtering; if it does not, a central filter must read all headers and sanitise them before the response reaches the transport.

!!! danger "Approval required"
    Any transport or component that generates HTTP responses directly and relies on a custom-written CR/LF-filtering filter must have that filter reviewed and approved by the Security and Compliance Team before release.

=== "Go stack"

    `net/http` rejects raw CR/LF in header values, but validate or sanitise any user-controlled value before placing it in a header or cookie rather than relying on that alone.

    ```go
    // Anti-pattern — untrusted value straight into a cookie
    http.SetCookie(w, &http.Cookie{Name: "author", Value: r.URL.Query().Get("author")})
    // Safe — validate first, reject on failure
    author := r.URL.Query().Get("author")
    if err := validateAuthorInput(author); err != nil {
        http.Error(w, "Invalid author input", http.StatusBadRequest)
        return
    }
    http.SetCookie(w, &http.Cookie{Name: "author", Value: author})
    ```

### Log Injection / Log Forging

External: [OWASP Log Injection](https://owasp.org/www-community/attacks/Log_Injection) — read it for how CR/LF in a logged value forges separate log entries, which matters when logs feed reconciliation or other automated action.

Strip CR/LF from any user-controlled value before logging it; never log raw user input via string concatenation (e.g. `log.info("payment to author: " + author)`). See [Logging and Alerting Failures](#logging-and-alerting-failures) for the broader logging controls.

=== "Java stack"

    Carbon 4.4.3+ supports the `%K` token in the log4j pattern, which appends a per-entry UUID (generated at server startup, with configurable regeneration); a forged log line lacks the valid UUID and so can be isolated. This is an operator-enabled hardening option, not a default: **don't enable `%K` in the default log4j layout you ship** — appending a UUID to every line costs CPU per line and inflates log volume, and most deployments don't need it. Verify `%K` works in your product's layout and document it as an opt-in for deployments whose compliance requirements call for tamper-evident logs. Configuration is in the Administration Guide.

### Server-Side Template Injection (SSTI)

For the attack pattern across template engines, read [OWASP SSTI](https://owasp.org/www-community/attacks/Server-Side_Template_Injection) for how a user-controlled template string reaches the engine's expression evaluator.

Substitute user input only into pre-defined parameters of an already-compiled template — never into the template *source*. Anti-pattern: `engine.evaluate(userSuppliedTemplate, context)` or any path where user input is parsed as template syntax. Treat any feature that lets users supply template text as a risky exception: deny by default, and route it through the Security and Compliance Team before release. Re-check authorisation at the data layer for any data the template can reach, since SSTI escalates to data disclosure and RCE.

### NoSQL and XPath injection

For test cases and payloads, read [OWASP — Testing for NoSQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection) and [OWASP XPath Injection](https://owasp.org/www-community/attacks/XPATH_Injection) for the operator-injection and predicate-injection shapes specific to each.

Build queries with the driver's structured API — MongoDB filters / BSON documents, an XPath API with bound variables — never by concatenating user input into a query string or by passing raw user input where the driver accepts query operators. Keep every lookup scoped to the caller's tenant/organisation identity from the request context, and re-check that scope at the data layer; a missing tenant filter is the same class of defect as a missing `WHERE` clause.

### Regex denial of service (ReDoS)

For how catastrophic backtracking arises, read [OWASP ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS) for the vulnerable pattern shapes (nested quantifiers, overlapping alternations).

Never compile a user-supplied regex pattern. Cap input length before matching any pattern against user input.

=== "Java stack"

    `java.util.regex.Pattern` uses a backtracking engine — patterns like `(a+)+` go exponential on adversarial input. Prefer possessive quantifiers (`a++`) or atomic groups (`(?>…)`); for high-risk surfaces, run the match on a separate thread with a timeout so a runaway match can be interrupted.

=== "Go stack"

    `regexp` uses RE2 (linear time, no backtracking) — safe by design against catastrophic backtracking. Bounding input length still applies to cap memory use.

### Email header injection

For the attack pattern, read [OWASP Email Injection](https://owasp.org/www-community/attacks/Email_Injection) for how CR/LF in a value substituted into an RFC 5322 header (To, Subject, From) lets an attacker add headers or recipients.

Code that sends email must build headers programmatically through a mail library rather than formatting raw header strings, and must strip CR/LF and validate per-header on any user-controlled value. Treat header values as deny-by-default: reject anything outside the expected character set for that header field.

---

## Insecure Design

For the threat-modelling method and proactive design controls, read [OWASP A04](https://owasp.org/Top10/A04_2021-Insecure_Design/) for the failure class, [OWASP Threat Modeling Process](https://owasp.org/www-community/Threat_Modeling_Process) for the STRIDE workflow, and [OWASP Proactive Controls](https://owasp.org/www-project-proactive-controls/) for the control catalogue to design against. Run a design review through your team's normal design-review process before code review begins.

Insecure Design is a missing-control problem, not a coding bug. A perfectly coded feature can still be insecure if the design never accounted for abuse. Design review therefore happens *before* code review, not after.

!!! danger "Approval required"
    Any feature that introduces a new external attack surface, a new authentication or authorisation surface, a new credential or secret store, or a new privilege grant should have its design and threat model reviewed and approved by the Security and Compliance Team before code review begins. Work the threat model with the [OWASP Threat Modeling Process](https://owasp.org/www-community/Threat_Modeling_Process) and bring the trust boundaries and the control chosen for each threat as the review artefacts.

Design rules that apply across stacks:

* **Model state explicitly.** Workflow and resource lifecycles are an enum plus a transition table, checked at the service layer before persistence. Never derive the next state from caller input or infer it from the current request — an attacker who can name the target state can skip the steps that guard it (approval, payment, ownership check).
* **Enforce idempotency at the data layer.** Use an atomic database operation (a unique constraint or an upsert) rather than a `SELECT`-then-`INSERT` window that two concurrent requests can both pass.
* **Rate-limit everything that does work.** Apply layered budgets — per-user *and* per-IP *and* global. A single global limit lets one tenant exhaust the budget for all.
* **Name and enforce trust boundaries.** Carry tenant identity in the request context and re-check it at the data layer, never trust it from a header or path parameter alone. Make the default deny: enumerate the paths that are public and treat everything else as protected.

=== "Java stack"

    Carry tenant identity through `PrivilegedCarbonContext` rather than passing a tenant ID as a method argument that a caller can forge, and re-resolve it at the persistence layer before scoping any query.

    Express lifecycle state as an enum and a transition table, and validate the requested transition at the service layer before writing. The product's own lifecycle handlers follow this shape — when you add a new domain, register your transition check on the same service-layer entry point rather than scattering status comparisons through handlers. Reject any transition not present in the table; do not fall through to a default "allow".

    Idempotency: prefer `INSERT ... ON CONFLICT` or a unique index over `SELECT`-then-`INSERT`. For one-time initialisation of shared state, guard with `synchronized (key.intern())`; for higher-throughput counters and maps, use `java.util.concurrent` primitives.

    Rate limiting: APIs fronted by the gateway may inherit gateway-level throttling, but verify what limits actually apply in your deployment rather than assuming a tier is in place. Any endpoint not fronted by gateway throttling must enforce its own per-user and per-IP budgets. Treat every new always-on endpoint as un-throttled until you have added an explicit limit.

=== "Go stack"

    Document the trust model in `ARCHITECTURE.md` and enumerate every public path explicitly; everything else is default-deny. Carry tenant identity in `context.Context`, propagate it through every call, and re-check it at the query layer — do not read it back off the inbound request once authenticated.

    Model long-running workflows as typed state machines and persist transitions with optimistic locking on `(instance_id, current_state)` so a stale client cannot replay an old transition. Express operation-level authorisation as declarative data on the API spec, not as ad-hoc checks inside handlers.

    Use `sync.Once` for one-time initialisation, `sync.RWMutex` for high-throughput maps, and a database uniqueness constraint for idempotency. Apply rate limiting as middleware in front of the router, not per handler, so no new route ships un-throttled by omission.

### Pagination, list limits, and resource ceilings

For the resource-consumption attack pattern and its test cases, see [OWASP API4:2023](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/).

An unbounded list endpoint is a denial-of-service primitive: a caller asking for everything forces an expensive scan and a large response, and one tenant's request degrades the service for all. Controls:

* **Server-enforced maximum page size.** The handler clamps or rejects any `limit=` above the configured ceiling; never honour a client-supplied page size unconditionally. Pick a default page size and a hard maximum, and apply both at the handler before the query is built.
* **Avoid expensive total counts.** Return a `hasMore` flag and let callers page until the result is empty, rather than running a `COUNT(*)` over a large table on every request. Reserve total counts for tables small enough to scan cheaply.
* **Per-tenant ceilings.** Cap queries-per-minute, maximum stored objects, and maximum attachment size per tenant so one tenant cannot exhaust shared capacity. Resolve the tenant from context (see the trust-boundary rule above), not from caller input.
* **Gate unbounded operations.** Any operation that could legitimately touch unbounded data (full export, bulk re-index) requires an admin role or a deliberate, separately-rate-limited batch path — not the ordinary list endpoint.

Reject the anti-pattern of "the client passed `limit=1000000`, so we returned a million rows": the maximum is a server property, enforced server-side, regardless of what the client asks for.

### Sensitive business flows and anti-automation

For how attackers automate high-value flows and the controls that frustrate them, see [OWASP API6:2023](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/).

The first step is identification: during threat modelling, enumerate the flows where automated, high-volume invocation has business cost. Typical sensitive flows include signup, password reset, OTP send, MFA enrolment, gift-code or coupon redemption, refund initiation, and free-tier resource creation. For each, decide the abuse budget and the layered controls before the flow ships.

Controls to layer (no single one suffices):

* **Layered budgets** — per-user, per-device, per-IP, per-tenant, and global. An attacker rotating IPs is still bounded by the per-account and global limits; an attacker hammering one account is bounded by the per-user limit.
* **Behavioural friction** — escalate after the first few failures (a CAPTCHA or step-up challenge), and use device fingerprinting where the flow warrants it. Apply friction progressively so legitimate users are not penalised on the first attempt.
* **State-changing requests are POST-only and CSRF-protected.** For the synchroniser-token, cookie, and multipart-form integration, see [OWASP CSRFGuard]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/owasp-csrf-guard/).
* **Observability** — every invocation of a sensitive flow emits an audit event, so velocity anomalies are detectable, and the highest-value flows have alerts wired into the deployment's security monitoring. A flow you cannot observe is a flow you cannot defend.

### Unrestricted File Upload

For the full set of upload checks and known bypasses, see the [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) — use it as the bypass checklist your validation must survive.

Unrestricted file upload occurs when the server accepts an upload without adequately validating the file's name, type, content, and size. The risk taxonomy:

* **Overwriting critical files** — an upload named after an existing critical file replaces it.
* **Arbitrary file placement** — if the path is also attacker-influenced (directory traversal), a malicious script or executable lands in a sensitive directory.
* **Backdoor installation** — a web shell stored where the server will execute it gives persistent, code-level control.

Enforce the checks in this order, and stop at the first failure (each check assumes the previous one passed, so order matters — reject by size before you spend cycles parsing content):

1. **Container size limit** — cap the request body at the container/transport layer so an oversized upload is refused before it reaches your handler.
2. **Handler size limit** — re-assert the size cap in the handler; the container limit may be looser or absent in some deployments.
3. **Content-type allow-list, validated against the bytes** — allow only specific types, and confirm the type by **inspecting the file content (magic bytes), not the client-supplied `Content-Type` header or the filename extension**. The `Content-Type` header is attacker-controlled and the extension proves nothing.
4. **Filename sanitisation** — normalise the filename and assign a unique stored name; never persist the client-supplied name verbatim (overwrite risk).
5. **Storage outside any web-served directory** — store uploads outside the webroot, with no execute permission and least-privilege filesystem permissions, so a stored file can never be requested and run.

Log all upload activity for monitoring.

**Serving files back:** serve user-uploaded content from a separate hostname (or, at minimum, a separate path with no server-side execution), grant no execute permission, and set the `Content-Type` explicitly. Send `X-Content-Type-Options: nosniff` so the browser does not MIME-sniff an upload into an executable type — this header is part of the mandatory set in [HTTP Security Headers]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/security-related-http-headers/).

=== "Java stack"

    Validate the extension against a server-side allow-list (for example `ALLOWED_FILE_EXTENSIONS = new String[]{".xml"}`) and throw `FileUploadException` on a disallowed type — but treat the extension check as a convenience filter, not the authority.

    The authoritative type check is content inspection with **Apache Tika**: parse the file with `AutoDetectParser` (a `Parser`) into a `BodyContentHandler`, capturing `Metadata` (`TikaCoreProperties.RESOURCE_NAME_KEY` for the resource name, and `HttpHeaders.CONTENT_TYPE` for the detected type) via a `ParseContext`, and compare Tika's detected content type against the expected type. Catch `SAXException` and `TikaException` and reject the file on parse failure rather than letting it through. A sample shape:

    ```java
    void checkMetaData(File f, String expectedContentType) throws FileUploadException {
        BodyContentHandler handler = new BodyContentHandler();
        Metadata metadata = new Metadata();
        metadata.set(TikaCoreProperties.RESOURCE_NAME_KEY, f.getName());
        Parser parser = new AutoDetectParser();
        try (InputStream stream = new FileInputStream(f)) {
            parser.parse(stream, handler, metadata, new ParseContext());
        } catch (SAXException | TikaException | IOException e) {
            throw new FileUploadException("Unable to inspect file content", e);
        }
        if (!expectedContentType.equals(metadata.get(HttpHeaders.CONTENT_TYPE))) {
            throw new FileUploadException("File content does not match the expected type");
        }
    }
    ```

    When building the storage path from any user-influenced component, resolve it through the boundary-checked `SecurityUtil.resolvePath(baseDir, userPath)` helper (see [Path Traversal](#path-traversal)) so the file cannot escape the upload directory. CSRF-protect multipart upload forms: inject the token into the form action via the csrf taglib, for example `action="../../fileupload/webapp?<csrf:tokenname/>=<csrf:tokenvalue/>"` (see [OWASP CSRFGuard]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/owasp-csrf-guard/)).

=== "Go stack"

    Validate the extension against a server-side allow-list — normalise with `strings.ToLower(filepath.Ext(filename))` and look it up in an `allowedExts` map (for example `.jpg`, `.jpeg`, `.png`, `.pdf`), returning an error on an unsupported extension — then confirm the type from the content.

    For content validation, read the first 512 bytes, rewind with `file.Seek(0, io.SeekStart)`, and pass the buffer to `http.DetectContentType`, then check the result with `strings.HasPrefix(contentType, expectedType)` (for example `"application/pdf"`). 512 bytes is the window `http.DetectContentType` inspects:

    ```go
    func validateFileContent(file multipart.File, expectedType string) error {
        buffer := make([]byte, 512)
        if _, err := file.Read(buffer); err != nil {
            return err
        }
        if _, err := file.Seek(0, io.SeekStart); err != nil {
            return err
        }
        contentType := http.DetectContentType(buffer)
        if !strings.HasPrefix(contentType, expectedType) {
            return fmt.Errorf("file content does not match expected type %s", expectedType)
        }
        return nil
    }
    ```

    Build the storage path with `filepath.Clean` (and a boundary check, per [Path Traversal](#path-traversal)) so a crafted filename cannot traverse out of the upload directory, and assign a unique stored name rather than reusing the upload's filename.

Reject these anti-patterns regardless of stack: trusting client-side file-type checks or the `Content-Type` header; persisting the client-supplied filename without sanitisation; storing uploads inside the webroot or with execute permission; and accepting uploads with no size limit.

---

## Authentication Failures

The authoritative guideline does not prescribe a fixed set of authentication rules, so this section points at the canonical sources and gives general WSO2 engineering guidance for building against them. Read these for the threat model and the rules; do not reimplement what they specify — implement against them:

* **[NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)** — read for memorised-secret (password) length, lifecycle, recovery, and MFA assurance levels, and for which legacy rules it now disallows (mandatory composition, routine forced rotation). Take the actual length floor and breached-password expectations from the current text, not from a number hard-coded here.
* **[OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)** and **[Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)** — read for the operational rules and the test cases each control must pass.
* **[RFC 9700 — OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/rfc9700)** — read for the required OAuth posture: PKCE (`S256` only), exact `redirect_uri` matching, refresh-token rotation, public-client constraints, and prohibited grant types.
* **[OWASP Top 10 A07](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)** — read for the broader threat model and the failure categories to test against.

General WSO2 engineering guidance for building authentication on top of those sources:

* **Carry tenant identity in the request context** and key every credential, lock-state, and session lookup by it, so one tenant can never observe or affect another tenant's authentication.
* **Keep policy parameters in configuration, not in code.** Password length floor, hashing parameters, lockout thresholds, and breached-password behaviour should be config-as-code so they can be tuned and reviewed without a code change, and the chosen algorithm/parameters stored alongside each hash so they can evolve without breaking verification.
* **Deny by default.** An authentication or authorisation decision that cannot be made affirmatively must fail closed; never treat an absent or unrecognised result as "allow".
* **Make the authentication decision live below the UI.** Re-check the account-lock and authorisation decision at the data/credential layer, not only in the interactive login flow, so OAuth, token, and provisioning paths inherit the same decision rather than each re-implementing it.
* **For breached-password checking, never let the secret leave the boundary.** If you consult an external corpus, use a k-anonymity range query (send only a hash prefix) or a locally hosted mirror; never send the full password or its full hash off-box.
* Treat OWASP/NIST controls (breached-password rejection, MFA factor strength, token storage on clients) as the authority. Browsers should keep refresh tokens in `HttpOnly; Secure; SameSite` cookies or behind a backend-for-frontend, never in `localStorage`/`sessionStorage`; mobile clients should use the platform secret store. These are the cheat-sheet rules, not WSO2-specific inventions.

!!! danger "Approval required"
    Any risky exception to the authentication posture above — relaxing a control the canonical sources require — must be reviewed and approved by the Security and Compliance Team before release. State the exception, the reason, and the compensating control in the request.

=== "Java stack"

    **Password policy.** Enforce the policy server-side at the single extension point every credential write passes through (e.g. a pre-update-credential handler in the identity-management layer), so it runs before any credential is stored — do not assume a shipped default is strong enough, and do not validate strength only in the front end where it is trivially bypassed. The policy implements the current NIST rules (length floor from config, no mandatory composition, no forced rotation) and, where required, performs the breached-password check at set-time via a k-anonymity range query.

    **MFA.** Compose the second factor through the identity framework's authentication mechanism (e.g. an authenticator / adaptive-authentication step) rather than branching on factor type in product code. Select the factor from the principal's enrolled factors / requested ACR / risk signals; do not hard-code a single factor.

    **Account lockout.** Track failed attempts and make the lock state a decision the credential layer consults — e.g. expose it as an identity attribute that every authentication path checks before the credential comparison, not just the interactive login servlet. The lock decision must live below the UI so the OAuth and provisioning paths inherit it.

    **OAuth.** Per RFC 9700, enforce PKCE at the authorization request (`S256` only), exact-match `redirect_uri`, and refresh-token rotation with reuse detection. The RFC's intended outcome on detecting a replayed (already-rotated) refresh token is to revoke the whole token family; treat that as the target behaviour to implement against, not a guaranteed product default.

    **Password in memory.** Hold the submitted password as `char[]`, never `String`, and clear it after use — see [Cryptographic Failures](#cryptographic-failures) for the clearing helper and the heap-inspection rationale.

=== "Go stack"

    **Password hashing.** Take hashing parameters from configuration (Argon2id or PBKDF2), not hard-coded constants, and store the algorithm name and parameters alongside the hash so they can be tuned without breaking verification. Enforce the current NIST rules and the breached-password check before hashing.

    **OTP.** Never persist or transmit the OTP in plaintext. Hash it before it leaves the issuing function, bind it to a short-lived, signed, single-use token, and verify with a constant-time comparison (`crypto/subtle.ConstantTimeCompare`):

    ```go
    type otpSession struct {
        Recipient string
        Channel   string
        OTPHash   []byte // SHA-256 of the OTP; never the plaintext
        ExpiresAt int64
    }
    sum := sha256.Sum256([]byte(otp))
    sess := otpSession{Recipient: recipient, Channel: channel, OTPHash: sum[:], ExpiresAt: expiresAt}
    // sign sess into a short-lived, single-use token; the server never stores the plaintext OTP
    ```

    **PKCE.** Per RFC 9700, accept only `S256`; reject `plain` by construction:

    ```go
    if codeChallengeMethod != CodeChallengeMethodS256 {
        return ErrInvalidChallengeMethod
    }
    ```

    **Refresh-token rotation.** Per RFC 9700, issue a new token and invalidate the old on every use. The RFC's intended outcome is that presenting an invalidated (already-rotated) token revokes the entire token family; implement toward that outcome.

    **Lockout.** Carry the principal's lock state in the request `context.Context` and re-check it in the credential-verification function, so every entry point (login handler, token endpoint, provisioning) shares one decision.

### Session Hijacking

A session is recognised by a token carried in a cookie; in WSO2 products the session ID is a cookie communicated over HTTP headers. Hijacking compromises that token by sniffing it on the wire, a man-in-the-middle, predicting it, or stealing it client-side (XSS). Read the [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) for the full control set.

What to do:

* **Transport.** Emit HSTS so a conformant browser refuses plain HTTP to the domain (defeats SSLStrip and stops a session cookie leaking over an HTTP link to an HTTPS site). Where certificate pinning is in scope, pin the server key (TOFU) to blunt a compromised-CA MITM. The header values and how to wire them on Carbon/Tomcat, Go services, the API Gateway, reverse proxies, and ingresses are in [HTTP Security Headers — Configuration Reference]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/security-related-http-headers/).
* **Cookie attributes.** Set `HttpOnly; Secure; SameSite` so the session cookie cannot travel over an unencrypted channel or be read by script — see [Securing Cookies](#securing-cookies) for the WSO2 baseline.
* **Unpredictable tokens.** See [Session Prediction](#session-prediction).
* **Client-side theft.** Defeat the XSS that steals tokens — see [Injection](#injection) output-encoding rules.

=== "Java stack"

    Carbon 4 products run on Tomcat, which manages the session cookie; keep the cookie `HttpOnly`/`Secure` and serve over TLS only. Do not move the session token into a URL or response body where it is exposed in logs, referrers, and history.

    ```html
    <!-- correct: session-bearing cookie is HttpOnly + Secure, set by the container -->
    ```

=== "Go stack"

    Set `Secure` and `HttpOnly` (and a strict `SameSite`) on the session cookie so a stolen-via-XSS or sniffed token is prevented:

    ```go
    store := sessions.NewCookieStore([]byte(secretKey))
    store.Options = &sessions.Options{
        Path:     "/",
        MaxAge:   86400,
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteStrictMode,
    }
    ```

### Session Fixation

If the application keeps the same session ID across the authentication boundary, an attacker who plants a known guest session ID on the victim can ride the session once the victim logs in. The fix is the same on every stack: issue a brand-new session on login and destroy the session on logout.

=== "Java stack"

    **Login.** After authentication completes and *before* setting any authenticated attribute, invalidate the guest session and obtain a fresh one:

    ```java
    session.invalidate();
    session = request.getSession();   // fresh session
    session.setAttribute(AUTHENTICATED, true);
    ```

    Anti-pattern: setting the authenticated attribute on the existing session without invalidating it first.

    **Logout.** Invalidate the session — do not merely remove the user attributes:

    ```java
    session.invalidate();             // not session.removeAttribute(...)
    ```

    **URL rewriting.** Do not call `HttpServletResponse#encodeRedirectURL()` or `encodeURL()`; they append the session ID to the URL, exposing it. WSO2 products depend on cookies, so there is no functional cost to skipping them — build the redirect target directly and call `response.sendRedirect(redirectUrl)`.

=== "Go stack"

    **Login.** Invalidate the existing session, create a new one, then set values:

    ```go
    session.Options.MaxAge = -1       // invalidate the pre-auth session
    session.Save(r, w)
    session, _ = store.New(r, "session-name")
    session.Values["authenticated"] = true
    session.Save(r, w)
    ```

    Anti-pattern: setting `session.Values["authenticated"]` on the pre-auth session and saving it.

    **Logout.** Delete the session, do not just clear attributes:

    ```go
    session.Options.MaxAge = -1       // not delete(session.Values, "authenticated")
    session.Save(r, w)
    ```

### Session Prediction

If session IDs are derived from usernames, timestamps, or client IPs — or merely base64-encoded — an attacker who collects a few can reconstruct the generator and forge a valid ID; weak generators are also brute-forceable. Read the [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) for the entropy and generation requirements.

What to do: use a long random session key with **at least 128 bits** of entropy, from a CSPRNG. Reject the anti-pattern of building an ID from predictable inputs or encoding instead of randomness.

=== "Java stack"

    Carbon 4 products generate the session ID through Tomcat's `context.xml`; the default ID length is **16 bytes (exactly 128 bits)**, which already meets the OWASP recommendation. If a longer ID is later required, configure the `SessionIdGenerator` element of `context.xml` (Tomcat's *SessionIdGenerator Component* documentation has the parameters). Do not roll your own session-ID scheme.

=== "Go stack"

    Generate IDs from `crypto/rand`, never `math/rand` (which is deterministic), with at least 16 bytes of entropy:

    ```go
    func GenerateSessionID() (string, error) {
        b := make([]byte, 16) // >= 128 bits
        if _, err := rand.Read(b); err != nil {
            return "", err
        }
        return base64.URLEncoding.EncodeToString(b), nil
    }
    ```

### Password AutoComplete

Help the user's password manager identify credential fields by tagging them with the semantic `autocomplete` tokens: `current-password` on login forms and `new-password` on registration and password-change forms.

```html
<!-- login form -->
<input type="password" name="password" autocomplete="current-password"/>

<!-- registration / password-change form -->
<input type="password" name="new-password" autocomplete="new-password"/>
```

Do **not** set `autocomplete="off"` on credential fields. All major browsers deliberately ignore `autocomplete="off"` for password inputs so that password managers keep working, so the attribute does not suppress storage or autofill — it only fights the password manager and works against [WCAG 2.2 SC 1.3.5](https://www.w3.org/WAI/WCAG22/Understanding/identify-input-purpose.html). Enabling password-manager support is the secure default; OWASP and modern scanners (ZAP, PortSwigger) no longer treat a missing `autocomplete="off"` as a finding, and disabling autocomplete on credential fields is no longer a recognised security control. This is a front-end control and applies to every rendered authentication form; see also the [React secure-coding guidance]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-react-secure-coding/) for component-level forms.

### Heap Inspection

A password or key left in memory after use can be read from a heap dump. The defence is the same as for any sensitive value: hold it in a mutable buffer (`char[]` in Java, `[]byte` in Go), never an immutable `String`, and zero the buffer as soon as the credential operation completes. The clearing helpers and the full rationale live with the rest of the secret-handling rules in [Cryptographic Failures](#cryptographic-failures).

---

## Software and Data Integrity Failures

Integrity failures are about trusting code, configuration, or data whose provenance was never verified: an unsigned release, an image pulled by mutable tag, a CI job with more privilege than it needs, a serialized object that reconstructs into a gadget chain. Read [OWASP A08:2021](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/) for the threat model, [SLSA](https://slsa.dev/) for the build-provenance levels to target, and [sigstore / cosign](https://docs.sigstore.dev/) for the keyless signing workflow used below. Dependency pinning, single-source resolution, and SBOM generation are integrity controls too, but they live in [Software Supply Chain Failures](#software-supply-chain-failures) — this section covers what happens to an artefact after it is built and what you accept across a trust boundary at runtime.

WSO2-specific operational rules:

* Sign every release artefact (JAR, container image, Helm chart, OS package) on protected infrastructure with a short-lived signing identity. Publish the signature next to the artefact, a SHA-256 checksum in the release notes, and the verification steps in the install guide.
* Deployment manifests reference container images by digest (`@sha256:...`), never by mutable tag. A tag can be repointed under you; a digest cannot.
* Every CI workflow declares an explicit minimum `permissions:` block. A `pull_request_target` trigger that exposes secrets runs only behind an approval step — untrusted PR code must never reach a secret-bearing job unreviewed.
* Subresource Integrity (SRI) on any third-party JS or CSS loaded from a CDN, so a tampered asset fails to load rather than executing.
* Sensitive write endpoints carry replay protection: a request-level `jti` or `nonce` that the server rejects on reuse within a bounded window, combined with a short request expiry.

=== "Java stack"

    Artefacts published to Maven Central must carry `.asc` (GPG) signatures per Maven Central policy; the consumer-facing verification steps belong in the product's install guide, not buried in the pipeline. The target shape for any release pipeline: a signed `.asc` (or sigstore equivalent) for every artefact, SHA-256 checksums in the release notes, and container images signed with cosign before push.

    When you verify an inbound HMAC or compare a signature, use a constant-time comparison — `MessageDigest.isEqual(byte[], byte[])`. Do not use `Arrays.equals`, which short-circuits on the first differing byte and leaks timing in older JDKs.

=== "Go stack"

    For a new Go service, sign every artefact with [cosign](https://docs.sigstore.dev/cosign/overview/), publish the signature and a SHA-256 checksum alongside it, and document verification in the install guide:

    ```yaml
    - name: Sign release artefacts
      run: |
        for f in dist/*.zip; do
          cosign sign-blob --yes --bundle "${f}.cosign.bundle" "${f}"
          sha256sum "${f}" > "${f}.sha256"
        done
        cosign sign --yes "ghcr.io/.../${IMAGE}:${VERSION}"
    ```

    Verify webhook and signature comparisons with `hmac.Equal` — never `==`, which is not constant-time on byte slices:

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

Deserialization rebuilds an object from a byte or text stream. When that stream is attacker-controlled, a weak deserializer can be coerced into constructing arbitrary types — the classic route to remote code execution and data tampering. Read the [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) for the gadget-chain mechanics and the per-language defences; the controls below are what to apply in WSO2 code.

Two rules apply regardless of stack: never hand an untrusted stream to a generic decoder, and treat a deserialization failure as a security event. Add an integrity check (a digital signature or HMAC) over any serialized payload that crosses a trust boundary, and log every deserialization failure — an unexpected type or a thrown exception is a signal worth alerting on, not swallowing.

=== "Java stack"

    Prefer JSON or XML with a typed mapper over native Java serialization for any cross-trust-boundary payload. Where Java serialization is unavoidable, allow-list the classes that may be reconstructed — deny by default.

    A serialization filter gives you class allow-listing at the deserializer: `ObjectInputFilter` (JEP 290). The filter is built into every JDK any supported WSO2 product runs on — JEP 290 shipped in Java 9 and was backported to Java 6, 7, and 8, so no supported runtime needs a third-party library for this. Set it globally for the JVM, for example `-Djdk.serialFilter=com.wso2.expected.**;!*`, which permits the expected package tree and rejects everything else. On JDK 17+ you can additionally layer context-specific filters through a filter factory — `ObjectInputFilter.Config.setSerialFilterFactory(...)` (JEP 415) — to combine a JVM-wide filter with per-context ones.

    When filtering must be scoped to a single deserializer rather than the whole JVM, set a per-stream filter in code with `ObjectInputStream.setObjectInputFilter(...)`. As a code-level alternative, subclass `java.io.ObjectInputStream` and override `resolveClass()` to allow-list expected types, throwing `InvalidClassException` for anything else:

    ```java
    @Override
    protected Class<?> resolveClass(ObjectStreamClass osc)
            throws IOException, ClassNotFoundException {
        if (!ALLOWED_CLASSES.contains(osc.getName())) {
            throw new InvalidClassException("Unauthorized deserialization attempt",
                                            osc.getName());
        }
        return super.resolveClass(osc);
    }
    ```

    Two complementary measures:

    * Mark sensitive fields `private transient` on any `Serializable` class so they are neither emitted on serialization nor populated from an attacker-supplied stream.
    * If a class implements `Serializable` only because of its hierarchy and should never be deserialized, give it a `final readObject` that refuses outright:

        ```java
        private final void readObject(ObjectInputStream in) throws java.io.IOException {
            throw new java.io.IOException("Cannot be deserialized");
        }
        ```

    Audit dependencies for known gadget libraries (Commons Collections, Spring Beans, Groovy) — these supply the chains that turn a permissive deserializer into RCE. For inbound payloads that must stay dynamic (webhooks, plug-in config), require the producer to sign the payload, verify the signature, then construct the typed object.

    !!! warning "High-risk exception"
        Treat any deserialization of untrusted input that cannot enforce a class allow-list — relying on a blocklist, or accepting arbitrary types — as a high-risk exception. Surface it for team review before release rather than shipping it silently.

    Anti-pattern to reject — handing an untrusted stream straight to a stock `ObjectInputStream`:

    ```java
    ObjectInputStream ois = new ObjectInputStream(untrustedInputStream);
    String message = (String) ois.readObject(); // no class filtering — RCE surface
    ```

=== "Go stack"

    `encoding/json`, `encoding/xml`, and `encoding/gob` do not reconstruct arbitrary types the way native Java serialization does, so typed DTOs are the safe path. Decode untrusted input into a defined struct, never into a generic container.

    * Deserialize into specific structs, not `map[string]interface{}` or `interface{}` — generic containers defeat type safety and let unexpected shapes through.
    * Validate the decoded struct even after a successful decode; a well-formed payload can still carry an invalid `Role` or `Username`.
    * Avoid `encoding/gob` for untrusted input — it can decode arbitrary registered types. Prefer JSON or explicit typing across trust boundaries.
    * Reject unexpected fields with `dec.DisallowUnknownFields()`, and cap the payload with `io.LimitReader` so a hostile stream cannot exhaust memory.

    ```go
    dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20)) // 1 MB cap
    dec.DisallowUnknownFields()
    var in LoginRequest // a defined struct, not interface{}
    if err := dec.Decode(&in); err != nil {
        http.Error(w, "invalid payload", http.StatusBadRequest)
        return
    }
    if err := in.Validate(); err != nil { // re-check after decode
        http.Error(w, "invalid payload", http.StatusBadRequest)
        return
    }
    ```

    For binary protocols (Protobuf, MessagePack), use the generated typed code, not a generic decoder.

    Anti-pattern to reject — decoding untrusted input into a generic container, or using `gob` on it:

    ```go
    var data map[string]interface{}
    json.Unmarshal(untrustedInput, &data) // unvalidated, untyped

    gob.NewDecoder(r.Body).Decode(&anyValue) // gob on untrusted input
    ```

---

## Logging and Alerting Failures

Insufficient logging and weak integration with incident response let an attacker pivot and persist for weeks or months before detection, and high-value transactions without tamper-evident trails can be altered or deleted after the fact. The controls below make security-relevant events observable, attributable, and trustworthy.

Read these for the canonical model, then apply the WSO2 rules that follow:

* **[OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)** — read it for the audit-event field schema, the "what to log" / "what never to log" lists, and the retention and integrity model.
* **[OWASP Logging Vocabulary Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html)** — read it for the canonical event-name registry (`auth.login`, `iam.role.grant`, `key.rotate`, …). Use these names verbatim in WSO2 audit events so events correlate across products and SIEM rules.
* **[OWASP Top 10 A09](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)** — read it for the threat model behind this section.

### What the WSO2 guideline requires

These four controls are the load-bearing WSO2 requirements for this section. Everything else below is general engineering guidance layered on top of them.

* **Log the security-relevant events.** All login events, access-control failures, and server-side input-validation failures must be *capable* of being logged, with sufficient user context to identify a suspicious or malicious account.
* **Make logs consumable by centralized log management.** Generate logs in a format a centralized log management solution can ingest directly, never free-text prose a regex has to reconstruct.
* **Retain for delayed forensic analysis.** Keep security-relevant logs long enough that an investigation opened well after the fact still has the evidence it needs.
* **Protect high-value transactions with an integrity-controlled audit trail.** High-value transactions must have an audit trail with integrity controls to prevent tampering or deletion — for example append-only database tables or an equivalent append-only sink.

Reject these as explicit anti-patterns:

* **Insufficient or absent logging** of login events, access-control failures, and input-validation failures, and **no integration with incident response** — events that reach a file nobody watches are not monitoring.
* **Audit trails without integrity controls** — mutable or deletable logs for high-value transactions, where a record can be silently rewritten or removed.

### What every security event must capture

Build each audit event so it satisfies the "sufficient user context" requirement above.

* Every audit event carries: the canonical event name, an outcome (`success`/`failure`/`deny`), the authenticated principal, the **tenant identity**, a correlation/request id, the client source IP, and a timestamp. Make events machine-parseable (structured key/value or JSON).
* **Tenant id comes from the authenticated context, never from request input** — the same rule applied throughout the Carbon stack. Resolve it from the established server context, not from a header, query parameter, or body field an attacker controls.
* Re-establish *who* and *what tenant* at the point you write the audit record, so an event cannot be attributed to the wrong principal by a request that changed identity mid-flight.

### Operational logs and audit logs are different sinks

Operational logs and audit logs serve different consumers and must not share a sink.

* **Operational logs**: short retention, the standard log aggregator, free to carry stack traces and framework chatter for debugging.
* **Audit logs**: long retention, an append-only sink, a stable schema that downstream SIEM rules parse, and **no stack traces or framework noise**. This is where the integrity-controlled audit trail for high-value transactions lives: append-only storage so records cannot be silently tampered with or deleted.

=== "Java stack"

    Route audit events through a dedicated audit logger wired to its own appender — for example a dedicated `AUDIT_LOG` logger in your log4j2 configuration with a separate appender and retention from the operational logs (logger and appender names here are a convention; confirm your product's actual configuration). Do not let audit events fall through to the root logger, where they inherit operational retention and get buried in framework output.

=== "Go stack"

    Use a dedicated `*slog.Logger` with its own handler and destination — e.g. a separate `audit` package whose handler writes to the append-only sink — kept distinct from the operational logger. Do not emit audit events through the operational logger.

### Resolving the client source IP behind proxies

WSO2 products typically sit behind load balancers, gateways, and reverse proxies, so the immediate TCP peer is rarely the real client. Getting the client IP right is standard stack technique plus operator configuration, not a guideline-defined WSO2 control.

* **Never trust the raw `X-Forwarded-For` header.** It is attacker-controllable and can be spoofed or padded with bogus hops, so a forged value will be attributed to the wrong client and can poison alerting.
* Resolve the client IP via a proxy-aware extraction against a **trusted-proxy list**: walk the forwarded chain and accept only hops you trust, taking the first untrusted address as the client. This is your framework's or proxy tier's standard capability, not a documented Carbon helper.
* Make the trusted-proxy list operator-configurable in your product's deployment config and document it. A control that depends on an unset list silently falls back to either the raw header or the proxy address; neither is the client.
* For the actual header set involved (which headers the proxy tier emits and consumes), see the companion **HTTP Security Headers** doc referenced under [Companion configuration](#companion-configuration) below — that is where the header set is wired per platform.

### Mask or hash sensitive values

Audit events frequently need to reference something sensitive (a token, a key id, a credential-bearing field) for correlation. Reference it without disclosing it.

* Where a value is needed only for correlation, log its **hash** or a **truncated prefix with an explicit ellipsis** (`abcd1234…`), never the full value.
* Never log passwords, full tokens or session ids, private keys, or PII — not in audit events and not in operational logs. The OWASP Logging Cheat Sheet "what never to log" list is the baseline; treat it as mandatory.
* Redact at the call site: pass already-masked values into the logger, never interpolate a raw secret into a message string and rely on a downstream filter to catch it. Reviewers reject ad-hoc redactors — extend the shared masking helpers your product already ships rather than hand-rolling one per call site.

### Integrity and tamper evidence

An audit trail an attacker can rewrite is not evidence. This is the integrity-controls requirement from the WSO2 guideline made concrete.

* Forward audit events to a dedicated, append-only sink separate from operational logs, with retention long enough for security investigation and any applicable compliance horizon.
* Consider signing or hash-chaining log batches so a removed or altered record is detectable.
* **Log forging via CR/LF is an integrity attack on the log itself.** Strip CR/LF from any user-controlled value before it reaches a log statement, and prefer structured fields over string concatenation so injected newlines cannot fabricate a second event. For the per-entry UUID tamper-evidence control, see [Injection — Log Injection / Log Forging](#log-injection-log-forging).

=== "Java stack"

    Use the two-arg `log.error(message, throwable)` form so the full stack is captured for operational debugging; `log.error("..." + e.getMessage())` is lossy and loses the chain. Keep stack traces out of the audit sink — they belong in operational logs.

    For tamper-evident lines, add the Log4j2 UUID conversion character `%u` to the appender's pattern — for example {% raw %}`[%u] [%d] %5p {%c} - %m%ex%n`{% endraw %} in your product's `log4j2.properties` — so each entry carries a UUID a forged line cannot reproduce (`%u{RANDOM}` for a random type-4 UUID, the time-based default otherwise). Current WSO2 products (Identity Server, API Manager, Micro Integrator) ship on Log4j2, where `%u` is the supported token; the legacy `%K` token applies only to products still on the Log4j 1.x stack (Carbon 4.4.3+). Frame it as an operator-enabled hardening option for deployments whose compliance needs call for tamper-evident lines, not a default. See [Injection — Log Injection / Log Forging](#log-injection-log-forging).

=== "Go stack"

    Build the structured logger on `log/slog` and pass context plus already-masked attributes:

    ```go
    logger.ErrorContext(ctx, "token validation failed",
        slog.String("tenant", tenantID),
        slog.String("request_id", traceID),
        slog.Any("cause", err),
    )
    ```

    Redact at the call site — never interpolate raw secrets or PII into the message string. Reviewers reject logger calls that violate this.

### Recommended high-signal events to monitor

Beyond the OWASP Logging Cheat Sheet baseline, the following are recommended high-signal events to wire into whatever monitors the deployment. This is general detection guidance — pick the ones your product can actually produce — not an enumerated set of WSO2 product features.

* **Cross-tenant deny attempts** — a strong signal of probing or a broken-isolation bug.
* **Refresh-token reuse, where the deployment detects it** — a strong signal of a stolen token being replayed.
* **Read of a privileged key.**
* **Change to a security-relevant setting** — CORS allow-list, lockout thresholds, JWT issuers, federated IdPs, MFA enforcement.
* **N authentication failures from one source or one principal within a window** — the lockout-rate / credential-stuffing signal.

An event nobody watches is not monitoring. Wire these into the incident-response pipeline rather than letting them sit in a file — the WSO2 guideline calls out lack of integration with incident response as an anti-pattern.

### Companion configuration

The header set your code emits (and which headers feed client-IP resolution at the proxy tier) is wired per platform in [HTTP Security Headers]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/security-related-http-headers/).

!!! danger "Approval required"

    Changing what audit events are emitted, suppressed, or redacted for a security-relevant flow — or relaxing audit-trail integrity or retention below the documented baseline — must be reviewed and approved by the WSO2 Security and Compliance Team before release. Reducing logging on a security-relevant flow removes the evidence a future investigation depends on.

---

## Mishandling of Exceptional Conditions

For the error-handling failure modes — swallowed exceptions, fail-open security decisions, and information leakage through error responses — read [OWASP Improper Error Handling](https://owasp.org/www-community/Improper_Error_Handling) · [CWE-703: Improper Check or Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/703.html) for the catalogue of failure modes the controls below defend against.

Three rules cut across every stack:

* **Fail secure.** When an exception interrupts a security decision (authentication, authorisation, signature or token validation, policy evaluation), the outcome must default to deny. Initialise the decision variable to the safe value *before* the `try`; never assign the permissive value inside `catch`.
* **Catch the exception you can handle, not the one you can't.** Catch typed exceptions, not the broad `Exception`/`Throwable` (Java) or a blanket `recover()` (Go). A broad catch hides the unexpected failures — `NullPointerException`, `OutOfMemoryError`, programming bugs — that should surface, not be silently absorbed into a security path.
* **Sanitise at the boundary.** Internal failure detail (stack traces, file paths, SQL fragments, class names, framework identifiers, host/port reachability) must never reach a client. Map exceptions to a sanitised response at every external boundary, and keep error messages indistinguishable so a response cannot be used as an oracle.

The last rule connects to [SSRF](#server-side-request-forgery-ssrf), the canonical WSO2 example of the *no-oracle* rule: there, strict error handling means returning an *identical* generic error whether a back-channel request failed or returned invalid data, so the response cannot be used as an open/closed-port oracle. The same discipline applies to every error path — distinguishable errors leak structure.

The complement of the no-oracle rule is *log the cause*: the client gets nothing distinguishing, but the server must record why the failure happened. The [Insecure Deserialization](#insecure-deserialization) control to log deserialization exceptions and failures — an incoming type that is not the expected type, or deserialization throwing — is a concrete instance: deny the operation, return a generic error, and log the real cause so the failed attempt is investigable.

!!! danger "Approval required"
    Any code path that, by design, allows a security decision (authentication, authorisation, signature/token validation, policy evaluation) to resolve to *permit* on an exception, or that exposes internal error detail to an untrusted client, must be reviewed and approved by the Security and Compliance Team before release.

### Fail-secure security decisions

A `catch` block sits on the failure path of a security check. If control reaches it, the check did not complete — which means you do not know the answer, which means the answer is *deny*.

=== "Java stack"

    Initialise to the safe value, run the check inside the `try`, and only the success path can flip it. The `catch` logs and leaves the decision denied:

    ```java
    boolean isAuthorized = false;                 // safe default, set before try
    try {
        isAuthorized = authorizationManager.isUserAuthorized(user, resource, action);
    } catch (UserStoreException e) {              // typed, not Exception/Throwable
        log.error("Authorisation check failed for user " + maskedUser(user)
                  + " on resource " + resource, e);
        // isAuthorized stays false — fail secure
    }
    if (!isAuthorized) {
        throw buildForbiddenException(resource, id);   // e.g. RestApiUtil helper
    }
    ```

    Log the user identifier masked, never the credential. The class names here are illustrative — use whatever typed exception and authorisation helper your component already exposes.

=== "Go stack"

    Treat the error from a security check as a deny, not a continue. The zero value of `bool` is `false`, so a check that returns `(allowed bool, err error)` is fail-secure only if you return on error before reading `allowed`:

    ```go
    allowed, err := authz.IsUserAuthorized(ctx, user, resource, action)
    if err != nil {
        log.GetLogger().Error("authorisation check failed",
            log.String("user", maskedUser(user)),
            log.String("resource", resource),
            log.Any("error", err),
        )
        return false, fmt.Errorf("authorisation check failed: %w", err)
    }
    return allowed, nil
    ```

    Never `return true` from an error branch, and never ignore the error with `allowed, _ :=`.

**Anti-patterns reviewers must reject (both stacks):**

* The decision variable initialised to the permissive value (`boolean allowed = true;` / returning `true` from an error branch) — fail open.
* `catch (Exception ignored) {}` / a bare `recover()` that swallows and continues a security path.
* A lossy log that drops the cause (`log.error("Something failed: " + e.getMessage())` without the throwable; logging only `err.Error()` without wrapping context).

### Catching the right exceptions

=== "Java stack"

    Catch the specific checked exception the call can throw, log it with the throwable (not just `getMessage()`), and rethrow as a domain exception so the boundary mapper can translate it:

    ```java
    try {
        URITemplate uriTemplate = new URITemplate(uri);
    } catch (URITemplateException e) {            // the exception this call declares
        String msg = "Error parsing URI " + uri;
        log.error(msg, e);                        // include the throwable
        throw new APIManagementException(msg, e); // domain exception, cause preserved
    }
    ```

    The exception and wrapper types above are illustrative — match your module's conventions. One legitimate exception to the typed-catch rule: an OSGi `BundleActivator.start(BundleContext)` / `stop(BundleContext)` is allowed to declare `throws Exception`, because the framework expects bootstrap failures to surface and abort component activation rather than be absorbed.

    Empty `catch` blocks are acceptable only for genuine best-effort cleanup (a `closeQuietly`-style helper); those helpers must log at `WARN` rather than discard the failure entirely.

=== "Go stack"

    `panic` is for unrecoverable initialisation failures only; ordinary control flow returns an `error`. Recover from `panic` only at a safe boundary — a request handler, a goroutine entry point, a transaction wrapper — and convert it to an `error` so the program continues in a defined state:

    ```go
    defer func() {
        if p := recover(); p != nil {
            stack := string(debug.Stack())
            log.GetLogger().Error("panic during transaction",
                log.String("dbName", t.dbName),
                log.Any("panic", p),
                log.String("stack", stack),     // stack goes to the log, never to the client
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

    Wrap errors with `fmt.Errorf("...: %w", err)` so callers can unwrap them; declare sentinel errors at package level and inspect with `errors.Is` / `errors.As` instead of string-matching messages. A bare `recover()` that does not log and does not convert to an error silently masks the bug — reject it.

### Centralised exception mapping at the boundary

Every external boundary — REST, SOAP, gRPC, JMS, scheduled jobs — needs a single place that turns an exception into a client-safe response. Scattering `try/catch` with hand-built error responses across handlers guarantees that one of them eventually leaks a stack trace.

The pattern: a centralised mapper at the boundary that (1) maps the exception to a canonical error envelope (a stable error code, a safe human-readable message, an optional correlation/trace id), (2) decides *server-side* whether to log the full stack — and logs it to the server log, never the response, and (3) returns only the sanitised envelope to the caller. The client gets the code and the correlation id; the operator gets the stack trace in the log, keyed by that id.

=== "Java stack"

    In JAX-RS boundaries, implement this as an `ExceptionMapper` (or your framework's equivalent provider) registered once per REST module, returning a fixed error-DTO shape — `code`, `message`, `description`, `moreInfo` — and choosing internally whether to log the stack. Do not let each resource method assemble its own error body. The exact mapper/DTO class names vary by module; follow the convention already established in the module you are working in rather than inventing a new one.

=== "Go stack"

    Translate the `error` to a canonical `ErrorResponse` envelope at the handler layer; never `json.Marshal` a raw Go `error` into a client response (its `Error()` string can contain internal paths, SQL, or host details). Centralise the translation in one middleware or helper so every handler returns the same envelope shape and the same generic message for the same class of failure.

### Resource and tenant cleanup on the exception path

The exception path is exactly where cleanup gets skipped — and skipped cleanup of *security-scoped* state is a vulnerability, not just a leak. Cleanup must run whether the body succeeds or throws.

=== "Java stack"

    Use `try`-with-resources for anything `AutoCloseable` so connections, statements, and result sets close on every path:

    ```java
    try (Connection conn = getConnection();
         PreparedStatement ps = conn.prepareStatement(SQL_ORGANIZATION_EXISTS)) {
        ps.setString(1, orgId);
        try (ResultSet rs = ps.executeQuery()) {
            return rs.next();
        }
    } catch (SQLException e) {
        throw new APIManagementException("Failed to look up organisation", e);
    }
    ```

    **Security-scoped thread-local state is the critical case.** State such as tenant identity or trace context that is set at the start of a unit of work MUST be torn down in a `finally` block, because worker threads are reused — leaked scope crosses requests, and a request that inherits a previous tenant's identity is a cross-tenant isolation breach. Treat the tear-down as mandatory on the exception path, not a nicety.

    Concretely: pair the start of the scoped flow with its matching end in a `finally`, so the end runs whether the body succeeds or throws. In Carbon, `PrivilegedCarbonContext` exposes such a start/end pair for tenant scope (method names below are illustrative — use the start/end pair and tenant-scope setter your `PrivilegedCarbonContext` version actually exposes):

    ```java
    // illustrative — confirm the exact API against your PrivilegedCarbonContext version
    PrivilegedCarbonContext.startTenantFlow();
    try {
        // set the tenant scope on the thread-local carbon context, then do tenant-scoped work
    } finally {
        PrivilegedCarbonContext.endTenantFlow();   // runs even if the body throws — scope torn down
    }
    ```

=== "Go stack"

    `defer` the cleanup immediately after acquiring the resource, so it runs on every return path including a `panic` that is recovered upstream:

    ```go
    tx, err := r.db.Begin()
    if err != nil {
        return err
    }
    defer tx.Rollback()   // safe: Rollback is a no-op after a successful Commit
    ```

    Do not `defer` inside a loop — each iteration stacks a deferred call that does not run until the function returns; wrap the loop body in a closure if you need a per-iteration `defer`. Propagate the request `context.Context` as the first parameter of every function that does I/O, and never swap the incoming context for `context.Background()` mid-flight — doing so detaches the work from request cancellation, deadlines, and any tenant or trace values carried in the context, the Go analogue of dropping the Carbon tenant scope.

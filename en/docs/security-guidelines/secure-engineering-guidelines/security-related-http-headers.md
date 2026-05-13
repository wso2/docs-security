---
title: HTTP Security Headers — Configuration Reference
category: security-guidelines
version: 3.4
---

# HTTP Security Headers — Configuration Reference

<p class="doc-info">Version: 3.4</p>
___

When you build a WSO2 product or service that serves HTTP, this is the security header set your code should emit and how to wire it. The companion section in the Secure Coding Guide is [Security Misconfiguration]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#security-misconfiguration); the operator-facing per-product reference is [Security Guidelines for Production Deployment]({{#base_path#}}/security-guidelines/security-guidelines-for-production-deployment/).

## The header set

Identify whether the surface you're building is an **admin-only UI**, a **customer-facing or themable UI**, or a **JSON API**. The header defaults differ.

| Header | Engineer default | Per-surface tuning |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` on every response | Same for all surfaces. |
| `Referrer-Policy` | `strict-origin-when-cross-origin` on every response | Stricter (`no-referrer`) for token-bearing endpoints. |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=(), payment=(), interest-cohort=()` on every response | Add directives for any other features the surface doesn't use. |
| `X-Frame-Options` | `DENY` on every HTML response | Same for all HTML-serving surfaces. Inert on JSON. |
| `Content-Security-Policy` | Nonce-based on every HTML response: `script-src 'self' 'nonce-{n}'`; no `'unsafe-inline'`, no `'unsafe-eval'`; `frame-ancestors 'none'`; `object-src 'none'`; `base-uri 'none'`; `form-action 'self'`. | Customer-facing UIs that load customer-hosted images / scripts: extend `img-src` / `script-src` with the customer allow-list (operator-configurable). Inert on JSON. |
| `Cross-Origin-Opener-Policy` | Admin UI: `same-origin`. Customer-facing: `same-origin` (still safe). JSON: omit. | — |
| `Cross-Origin-Embedder-Policy` | Admin UI: `require-corp`. **Customer-facing: omit** (would break customer-hosted logos / images / fonts). JSON: omit. | — |
| `Cross-Origin-Resource-Policy` | Admin UI: `same-site`. Customer-facing: `cross-origin` on resources customers may embed; omit on document responses. JSON: omit. | — |
| `Strict-Transport-Security` | **Off by default in the shipped code.** Operator enables per deployment. | Engineers ship the wiring; operators choose `max-age`, `includeSubDomains`, and `preload`. **Never hardcode `preload`** — it's an irreversible per-hostname commitment that the engineer can't make on behalf of every future deployment. |
| `Cache-Control` | `no-store` on token / session / PII responses | Set at the handler, not globally. |
| `Clear-Site-Data` | `"cache", "cookies", "storage"` on the logout response only | Engineer-time, at the logout handler. |

**Cookies carrying authentication or session state:** `HttpOnly; Secure; SameSite=Strict; Path=<narrow>`. Set `Domain` only when cross-subdomain sharing is required.

**Note on surface classification.** Admin-only UIs are Carbon Console, APIM Publisher (admin role), IS Console. Customer-facing or themable UIs are IS authentication endpoints (login / consent), IS My Account, APIM DevPortal, and any UI that loads a customer logo or other customer-controlled assets. JSON APIs are everything that returns `application/json` (or similar) and isn't rendered as HTML by a browser.

## Headers your code must not emit

Deprecated, ignored, or actively harmful. If you find existing code emitting one of these, remove it.

| Header | Status |
|---|---|
| `X-XSS-Protection` | Chrome removed the XSS Auditor in v78 (Oct 2019); Firefox never implemented it. **Deprecated.** If any code still emits it, set the value to `0` (explicitly disable) rather than `1; mode=block` — the heuristics it enabled were themselves a source of XSS. |
| `Public-Key-Pins` (HPKP) | **Removed** from browsers — Chrome v72 (Jan 2019), Firefox v72 (Jan 2020). Operational misuse can also lock customers out of an upgraded TLS chain in legacy browsers that still parse it. |
| `Feature-Policy` | Replaced by `Permissions-Policy`. Same intent, different syntax. |
| `Expect-CT` | Deprecated by the IETF in 2024; CT enforcement is unconditional in modern browsers. |

## Wiring it up

=== "Carbon / Tomcat (Java products)"

    **`X-Frame-Options`, `X-Content-Type-Options`** — wire the standard Tomcat `org.apache.catalina.filters.HttpHeaderSecurityFilter` for your webapp. The init-params `antiClickJackingEnabled` / `antiClickJackingOption` (for `X-Frame-Options`) and `blockContentTypeSniffingEnabled` (for `X-Content-Type-Options`) are safe to enable in the shipped default. Do **not** enable `xssProtectionEnabled` — `X-XSS-Protection` is deprecated.

    **HSTS** — also wired through `HttpHeaderSecurityFilter`, but **ship it off by default**. HSTS pins HTTPS in the browser cache for `max-age` seconds and is irreversible during that window; enabling it on a developer's local instance with a self-signed cert breaks the browser until cache expiry, and submitting `preload` is impossible to undo. Make sure HSTS can be turned on per deployment and document the operator action — two equivalent ways:

    * Product-wide via `deployment.toml`: [APIM — Enable HSTS Headers](https://apim.docs.wso2.com/en/latest/install-and-setup/setup/deployment-best-practices/security-guidelines-for-production-deployment/#enable-http-strict-transport-security-hsts-headers).
    * Per-webapp via `web.xml` at `<PRODUCT_HOME>/repository/deployment/server/webapps/<WEBAPP>/WEB-INF/web.xml`: [IS — Enable HSTS Headers](https://is.docs.wso2.com/en/latest/deploy/security/enable-hsts/).

    **CSP, COOP, COEP, CORP, `Permissions-Policy`, `Cache-Control` on token / PII responses, `Clear-Site-Data` on logout** — not covered by `HttpHeaderSecurityFilter`. When you add a new Carbon webapp, ship a project-local servlet filter that runs after `HttpHeaderSecurityFilter` so the built-in filter's `X-Frame-Options` is preserved alongside.

    For a new **admin-only UI** (one that customers don't theme or embed — Carbon Console, Publisher Admin, IS Console), the strict default is:

    ```java
    public class AdminUiSecurityHeadersFilter implements Filter {
        @Override
        public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
                throws IOException, ServletException {
            HttpServletResponse r = (HttpServletResponse) res;
            String nonce = generatePerRequestNonce(); // 16 bytes, base64
            req.setAttribute("cspNonce", nonce);

            r.setHeader("Content-Security-Policy",
                "default-src 'self'; "
                + "script-src 'self' 'nonce-" + nonce + "'; "
                + "style-src 'self' 'nonce-" + nonce + "'; "
                + "object-src 'none'; frame-ancestors 'none'; "
                + "base-uri 'none'; form-action 'self'");
            r.setHeader("Cross-Origin-Opener-Policy", "same-origin");
            r.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
            r.setHeader("Cross-Origin-Resource-Policy", "same-site");
            r.setHeader("Permissions-Policy",
                "geolocation=(), microphone=(), camera=(), payment=(), interest-cohort=()");
            r.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
            chain.doFilter(req, res);
        }
    }
    ```

    Add a sibling filter that sets `Cache-Control: no-store` on token / PII endpoints and one that sets `Clear-Site-Data` on the logout response.

    For **customer-themable surfaces** (IS authentication endpoints / login pages, IS My Account, APIM DevPortal) the same filter is wrong by default — customers theme these UIs with their own logos and may embed them. Use a relaxed variant that:

    * Drops `Cross-Origin-Embedder-Policy: require-corp` so customer-hosted images and fonts load.
    * Sets `Cross-Origin-Resource-Policy: cross-origin` (or omits CORP) on resources customers may embed.
    * Keeps strict CSP (`frame-ancestors`, `object-src`, `base-uri`) and `Permissions-Policy`.
    * Makes the embedded-image-origin allow-list configurable so operators can extend it for their customers.

    **CSP nonce migration shape.** New admin UIs ship the strict nonce-based policy from day one — the bundler must emit no inline scripts and no inline event handlers. The legacy `/carbon/*` admin console still uses `unsafe-inline` in places that have not been migrated; when wiring CSP into a product that includes the legacy console, scope the strict policy to your new paths and apply a per-URL relaxed override to `/carbon/*` as a tracked hardening item until the legacy pages are migrated. Don't relax CSP globally to accommodate legacy.

    **Preventing browser caching of dynamic pages** — Carbon ships `URLBasedCachePreventionFilter` and `ContentTypeBasedCachePreventionFilter` in `org.wso2.carbon.ui.filters.cache`. Wire them into your webapp's `web.xml` when adding any dynamic page that carries sensitive content. Reference: [IS — Prevent Browser Caching](https://is.docs.wso2.com/en/latest/deploy/security/prevent-browser-caching/).

    **Server header** — override via `[transport.https.properties]` in `deployment.toml` so the response doesn't return `Server: WSO2 Carbon Server`. Reference: [IS — Configure Transport-Level Security](https://is.docs.wso2.com/en/latest/deploy/security/configure-transport-level-security/).

    **Jaggery.** Jaggery is deprecated. New WSO2 features should not ship Jaggery applications; existing Jaggery surfaces should be migrated.

=== "Go services"

    Ship the security-headers middleware at the router root from day one, with the headers that are always safe to default on, and operator-configurable settings for the ones that aren't.

    * **Always default on** (no per-deployment decision needed): `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `X-Frame-Options` for HTML responses, nonce-based CSP for HTML responses.
    * **HSTS — off by default; operator opts in per deployment.** HSTS pins HTTPS in the browser cache for `max-age` seconds and is irreversible during that window; hardcoding it on breaks local dev. **Never hardcode `preload`** — it's a per-hostname commitment to the global preload list that no engineer can make on behalf of every future deployment.
    * **COOP / COEP / CORP — depend on the surface.** Strict policy is correct for admin-only services; it breaks customer integrations on customer-themable surfaces and is inert on JSON-only APIs. Make the caller pick a surface profile.

    ```go
    package web

    import (
        "crypto/rand"
        "encoding/base64"
        "fmt"
        "net/http"
    )

    // HSTSConfig is operator-tunable. Defaults to disabled.
    type HSTSConfig struct {
        Enabled           bool
        MaxAgeSeconds     int  // typical production: 31536000
        IncludeSubDomains bool
        Preload           bool // only enable with preload-list submission discipline
    }

    // SurfaceProfile picks the COOP/COEP/CORP shape.
    type SurfaceProfile int

    const (
        AdminUI         SurfaceProfile = iota // strict: COOP same-origin, COEP require-corp, CORP same-site
        CustomerFacing                        // relaxed COEP/CORP for customer theming/embedding
        JSONAPI                               // COOP/COEP/CORP not set (don't apply to JSON responses)
    )

    type Config struct {
        HSTS    HSTSConfig
        Surface SurfaceProfile
    }

    func SecurityHeaders(cfg Config, next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            h := w.Header()

            // Always-on headers
            h.Set("X-Content-Type-Options", "nosniff")
            h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
            h.Set("Permissions-Policy",
                "geolocation=(), microphone=(), camera=(), payment=(), interest-cohort=()")

            // HSTS only when operator opts in
            if cfg.HSTS.Enabled {
                v := fmt.Sprintf("max-age=%d", cfg.HSTS.MaxAgeSeconds)
                if cfg.HSTS.IncludeSubDomains {
                    v += "; includeSubDomains"
                }
                if cfg.HSTS.Preload {
                    v += "; preload"
                }
                h.Set("Strict-Transport-Security", v)
            }

            // Surface-typed COOP / COEP / CORP
            switch cfg.Surface {
            case AdminUI:
                h.Set("Cross-Origin-Opener-Policy", "same-origin")
                h.Set("Cross-Origin-Embedder-Policy", "require-corp")
                h.Set("Cross-Origin-Resource-Policy", "same-site")
            case CustomerFacing:
                h.Set("Cross-Origin-Opener-Policy", "same-origin")
                // COEP require-corp deliberately dropped — customer-hosted images/fonts must load.
                h.Set("Cross-Origin-Resource-Policy", "cross-origin")
            case JSONAPI:
                // COOP/COEP/CORP don't apply to JSON responses; omit.
            }

            // CSP + X-Frame-Options for HTML-serving handlers; skip on JSON APIs.
            if cfg.Surface != JSONAPI {
                nonce := generateNonce()
                h.Set("Content-Security-Policy", fmt.Sprintf(
                    "default-src 'self'; "+
                        "script-src 'self' 'nonce-%s'; "+
                        "style-src 'self' 'nonce-%s'; "+
                        "object-src 'none'; frame-ancestors 'none'; "+
                        "base-uri 'none'; form-action 'self'",
                    nonce, nonce))
                h.Set("X-Frame-Options", "DENY")
                next.ServeHTTP(w, r.WithContext(contextWithNonce(r.Context(), nonce)))
                return
            }
            next.ServeHTTP(w, r)
        })
    }

    func generateNonce() string {
        b := make([]byte, 16)
        _, _ = rand.Read(b)
        return base64.RawStdEncoding.EncodeToString(b)
    }
    ```

    For responses carrying tokens or PII, add `Cache-Control: no-store` at the handler. For the logout response, add `Clear-Site-Data`:

    ```go
    func logoutHandler(w http.ResponseWriter, r *http.Request) {
        // ... server-side session invalidation + revocation_endpoint call ...
        w.Header().Set("Clear-Site-Data", `"cache", "cookies", "storage"`)
        http.Redirect(w, r, "/login", http.StatusSeeOther)
    }
    ```

    Reject at review: a router root that doesn't compose `SecurityHeaders`; middleware that hardcodes HSTS `preload` rather than reading it from config; admin profile applied to a customer-themable surface.

=== "WSO2 API Gateway"

    For APIs published through the gateway, set headers at two levels:

    * **Globally** in the gateway's transport handler — `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`. These are safe defaults across every surface. HSTS belongs here but only if the operator has enabled it for the deployment.
    * **Per-API or per-resource** — everything that depends on surface type: CSP (HTML-serving APIs vs JSON-only APIs), COOP / COEP / CORP (admin-facing vs customer-facing), `Cache-Control: no-store` on token endpoints, `Clear-Site-Data` on logout endpoints.

    Avoid setting COOP / COEP / CORP globally on the gateway — the gateway fronts a mix of admin APIs and customer-facing APIs, and a strict global policy will break legitimate customer integrations on the customer-facing ones. Choose per-API.

    The wiring pattern is a Synapse `class` mediator (or a sequence) in the OutSequence that appends the headers; attach the mediator per-API for per-API control. When publishing a new API, the API definition should include a security-headers policy attachment that picks the right surface profile.

=== "Reverse proxy / Kubernetes ingress"

    This is an operator path, not an engineer path — included here so you know what to document for operators. The reverse proxy or ingress can emit the header set on behalf of a deployment that the product hasn't fully wired itself; operators decide once per deployment which layer owns each header (don't double-set). The same surface-type rule applies — strict policy for admin-only deployments; relaxed COEP/CORP for customer-themable ones.

    **nginx — admin-only deployment**: `add_header` in the `server { }` block:

    ```nginx
    server {
        listen 443 ssl http2;
        server_name example.wso2.com;

        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), interest-cohort=()" always;
        add_header Cross-Origin-Opener-Policy "same-origin" always;
        add_header Cross-Origin-Embedder-Policy "require-corp" always;
        add_header Cross-Origin-Resource-Policy "same-site" always;
        add_header X-Frame-Options "DENY" always;
        add_header Content-Security-Policy "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'" always;
    }
    ```

    For a **customer-themable surface** (IS authentication endpoints, IS My Account, APIM DevPortal), drop `Cross-Origin-Embedder-Policy: require-corp` and set `Cross-Origin-Resource-Policy: cross-origin` on resources customers may embed. Extend `img-src` / `script-src` in the CSP to include the customer asset domain. HSTS `preload` is only safe once the operator has submitted the hostname tree to the [preload list](https://hstspreload.org/).

    The `always` parameter is required so headers also appear on 4xx / 5xx — exactly when they matter. `add_header` directives **do not inherit** into nested `location` blocks that have their own `add_header`; declare headers at the `server` level.

    **`ingress-nginx`** — use `server-snippet` (or `configuration-snippet` on older versions) with the same surface-type choice as above.

    For Envoy-based ingresses (Istio, Contour, Gloo), use the gateway resource's `responseHeadersToAdd`. An OPA Gatekeeper / Kyverno policy that fails apply when an `Ingress` is missing the security-snippet annotation enforces the operator discipline cluster-wide.

## Rollout notes you should document for operators

### HSTS

HSTS is engineer-wired, operator-enabled. Document the recommended incremental rollout in the operator-facing security guideline for your product, since the engineer can't know which `max-age` is right for each deployment: `max-age=300` → `max-age=86400` (one week) → `max-age=31536000; includeSubDomains` → add `preload` and submit to the [HSTS preload list](https://hstspreload.org/). **Preload submission is hard to reverse** — operators must confirm HTTPS coverage on every subdomain, including ones not yet built, before submitting. Once a browser caches HSTS, it refuses HTTP for the `max-age` duration.

### CSP

If you're rolling out CSP onto a webapp that doesn't currently emit one, start with `Content-Security-Policy-Report-Only` (controlled by your filter's mode), fix violations for a sprint, then flip to enforcing `Content-Security-Policy`. Nonces are per-request, generated server-side, and inserted into every `<script>` / `<style>` tag served by the same response. For SPAs, use the bundler's runtime nonce configuration (Vite, Webpack `__webpack_nonce__`, Next.js CSP) to thread the nonce into client bundles — see [React Secure Coding Guide]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-react-secure-coding/).

### Cache-Control on sensitive responses

Set `Cache-Control: no-store` (and `Pragma: no-cache` for HTTP/1.0 caches still in the wild) on:

* OAuth token endpoint responses.
* Endpoints returning user PII.
* Authenticated API responses where intermediary caches (CDN, browser, corporate proxy) are not under WSO2 control.

`no-cache` is not the same as `no-store`: `no-cache` allows storage with revalidation; `no-store` forbids storage entirely.

## Verification

After any header change to your code, verify the response shape end-to-end.

### `curl` check

```sh
curl -sI https://example.wso2.com/ \
  | grep -iE '^(strict-transport-security|content-security-policy|x-content-type-options|referrer-policy|permissions-policy|cross-origin-opener-policy|cross-origin-embedder-policy|cross-origin-resource-policy|x-frame-options|cache-control|clear-site-data|server):'
```

Each expected header should appear exactly once. `X-XSS-Protection` (or, if present, only with value `0`), `Public-Key-Pins`, `Feature-Policy`, `Expect-CT` must not appear. The `Server` header must not disclose product/version.

### Automated scanners

* [Mozilla Observatory](https://observatory.mozilla.org/) — aim for grade A or A+.
* [securityheaders.com](https://securityheaders.com/) — quick external scan.
* OWASP ZAP passive scan — see [Dynamic Analysis with OWASP ZAP]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/dynamic-analysis-with-owasp-zap/). Tune the ZAP policy to expect the modern header set; by default ZAP still flags missing `X-XSS-Protection`, which is no longer the right signal.

### CI gate

The PR builder runs a header smoke-test against a running instance:

```sh
HEADERS=$(curl -sI "$URL")
required=(
  "strict-transport-security"
  "content-security-policy"
  "x-content-type-options"
  "referrer-policy"
  "permissions-policy"
  "cross-origin-opener-policy"
  "cross-origin-embedder-policy"
  "cross-origin-resource-policy"
)
for h in "${required[@]}"; do
  echo "$HEADERS" | grep -iq "^$h:" || { echo "missing: $h"; exit 1; }
done
forbidden=(
  "x-xss-protection: 1"
  "public-key-pins"
  "feature-policy"
  "expect-ct"
)
for h in "${forbidden[@]}"; do
  echo "$HEADERS" | grep -iq "^$h" && { echo "forbidden header present: $h"; exit 1; }
done
echo "header check passed"
```

## External references

Per-header semantics, browser support, edge cases:

* MDN: [Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security) · [Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) · [X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options) · [Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy) · [Permissions-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy) · [COOP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy) · [COEP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy) · [CORP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy) · [Clear-Site-Data](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Clear-Site-Data) · [SameSite cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite).
* [OWASP HTTP Security Response Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html).
* [HSTS Preload List](https://hstspreload.org/).
* [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/) — TLS configuration; complements the header set.
* [Tomcat 10.1 `HttpHeaderSecurityFilter` documentation](https://tomcat.apache.org/tomcat-10.1-doc/config/filter.html#HTTP_Header_Security_Filter).
* [Security Guidelines for Production Deployment]({{#base_path#}}/security-guidelines/security-guidelines-for-production-deployment/) — operator-facing per-product reference.

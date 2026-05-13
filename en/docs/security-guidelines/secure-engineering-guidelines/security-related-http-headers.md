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

| Header | Value | Set on |
|---|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` (add `preload` only after the hostname tree is fully HTTPS) | Every TLS-terminating response |
| `Content-Security-Policy` | Nonce-based `script-src 'self' 'nonce-{n}'`; no `'unsafe-inline'`, no `'unsafe-eval'`; `frame-ancestors 'none'`; `object-src 'none'`; `base-uri 'none'`; `form-action 'self'` | Every HTML response |
| `X-Content-Type-Options` | `nosniff` | Every response |
| `Referrer-Policy` | `strict-origin-when-cross-origin` (stricter for admin / token-bearing surfaces) | Every response |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=(), payment=(), interest-cohort=()` (deny features the app doesn't use) | Every response |
| `Cross-Origin-Opener-Policy` | `same-origin` | Every HTML response; mandatory on auth UIs |
| `Cross-Origin-Embedder-Policy` | `require-corp` | Every HTML response |
| `Cross-Origin-Resource-Policy` | `same-site` | Every response |
| `Cache-Control` | `no-store` | Responses carrying tokens, session identifiers, or PII |
| `Clear-Site-Data` | `"cache", "cookies", "storage"` | Logout response only |
| `X-Frame-Options` | `DENY` (legacy fallback while CSP `frame-ancestors` is being rolled out) | Every HTML response |

**Cookies carrying authentication or session state:** `HttpOnly; Secure; SameSite=Strict; Path=<narrow>`. Set `Domain` only when cross-subdomain sharing is required.

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

    **HSTS, `X-Frame-Options`, `X-Content-Type-Options`** — wire the standard Tomcat `org.apache.catalina.filters.HttpHeaderSecurityFilter`. Two equivalent ways to wire it:

    * Product-wide via `deployment.toml` (applies to every Tomcat webapp). Syntax: [APIM — Enable HSTS Headers](https://apim.docs.wso2.com/en/latest/install-and-setup/setup/deployment-best-practices/security-guidelines-for-production-deployment/#enable-http-strict-transport-security-hsts-headers).
    * Per-webapp via `web.xml` at `<PRODUCT_HOME>/repository/deployment/server/webapps/<WEBAPP>/WEB-INF/web.xml`. Syntax: [IS — Enable HSTS Headers](https://is.docs.wso2.com/en/latest/deploy/security/enable-hsts/).

    The init-params include `antiClickJackingEnabled` / `antiClickJackingOption` (for `X-Frame-Options`) and `blockContentTypeSniffingEnabled` (for `X-Content-Type-Options`) — leave them at their secure defaults. Do **not** enable `xssProtectionEnabled` — `X-XSS-Protection` is deprecated. HSTS is off by default so local development is not pinned to HTTPS by self-signed certificates; turn it on for production builds.

    **CSP, COOP, COEP, CORP, `Permissions-Policy`, `Cache-Control` on token / PII responses, `Clear-Site-Data` on logout** — not covered by `HttpHeaderSecurityFilter`. When you add a new Carbon webapp, ship a project-local servlet filter that runs after `HttpHeaderSecurityFilter` so the built-in filter's HSTS and `X-Frame-Options` are preserved alongside. Recommended shape:

    ```java
    public class ModernSecurityHeadersFilter implements Filter {
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

    Add a sibling filter that sets `Cache-Control: no-store` for token / PII endpoints, and one that sets `Clear-Site-Data` on the logout response.

    **Preventing browser caching of dynamic pages** — Carbon ships `URLBasedCachePreventionFilter` and `ContentTypeBasedCachePreventionFilter` in `org.wso2.carbon.ui.filters.cache`. Wire them into your webapp's `web.xml` when adding any dynamic page that carries sensitive content. Reference: [IS — Prevent Browser Caching](https://is.docs.wso2.com/en/latest/deploy/security/prevent-browser-caching/).

    **Server header** — override via `[transport.https.properties]` in `deployment.toml` so the response doesn't return `Server: WSO2 Carbon Server`. Reference: [IS — Configure Transport-Level Security](https://is.docs.wso2.com/en/latest/deploy/security/configure-transport-level-security/).

    **Legacy considerations.** The legacy `/carbon/*` admin console emits `unsafe-inline` style and script in places that haven't been migrated. When migrating one of these pages, drop the per-URL override; until then, scope a looser CSP filter to that URL pattern as a tracked hardening item rather than relaxing the policy globally. New WSO2 features should not ship Jaggery applications; existing Jaggery surfaces should be migrated.

=== "Go services"

    Ship the security-headers middleware from day one. Apply at the router root so every `http.Handler` is wrapped; per-route overrides (looser CSP for embedded widgets) live in the handler.

    ```go
    package web

    import (
        "crypto/rand"
        "encoding/base64"
        "fmt"
        "net/http"
    )

    func SecurityHeaders(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            nonce := generateNonce()
            h := w.Header()
            h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
            h.Set("Content-Security-Policy", fmt.Sprintf(
                "default-src 'self'; "+
                    "script-src 'self' 'nonce-%s'; "+
                    "style-src 'self' 'nonce-%s'; "+
                    "object-src 'none'; frame-ancestors 'none'; "+
                    "base-uri 'none'; form-action 'self'",
                nonce, nonce))
            h.Set("X-Content-Type-Options", "nosniff")
            h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
            h.Set("Permissions-Policy",
                "geolocation=(), microphone=(), camera=(), payment=(), interest-cohort=()")
            h.Set("Cross-Origin-Opener-Policy", "same-origin")
            h.Set("Cross-Origin-Embedder-Policy", "require-corp")
            h.Set("Cross-Origin-Resource-Policy", "same-site")
            h.Set("X-Frame-Options", "DENY")

            ctx := contextWithNonce(r.Context(), nonce)
            next.ServeHTTP(w, r.WithContext(ctx))
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

    Reject any new Go service code that doesn't compose `SecurityHeaders` at the router root at review.

=== "WSO2 API Gateway"

    For APIs published through the gateway, set headers at two levels:

    * **Globally** in the gateway's transport handler — HSTS, `X-Content-Type-Options`, `Referrer-Policy`, COOP, COEP, CORP, `Permissions-Policy`. Applied to every response served through the gateway.
    * **Per-API or per-resource** — CSP (HTML-serving APIs differ from JSON-only APIs), `Cache-Control: no-store` on token endpoints, `Clear-Site-Data` on logout endpoints.

    The pattern is a Synapse `class` mediator (or a sequence) in the OutSequence that appends the headers to the outgoing response; attach the mediator per-API for per-API control. When publishing a new API, the API definition should include a security-headers policy attachment by default.

=== "Reverse proxy / Kubernetes ingress"

    When the WSO2 product is fronted by an nginx reverse proxy or a Kubernetes ingress, that layer can also emit the same header set. This is the path for hardening an existing deployment where the product hasn't yet wired the full set itself. Decide once per deployment which layer owns each header — don't double-set.

    **nginx** — `add_header` in the `server { }` block:

    ```nginx
    server {
        listen 443 ssl http2;
        server_name example.wso2.com;

        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
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

    The `always` parameter is required so headers also appear on 4xx / 5xx — exactly when they matter. `add_header` directives **do not inherit** into nested `location` blocks that have their own `add_header`; declare headers at the `server` level.

    **`ingress-nginx`** — use `server-snippet` (or `configuration-snippet` on older versions):

    ```yaml
    apiVersion: networking.k8s.io/v1
    kind: Ingress
    metadata:
      name: example
      annotations:
        nginx.ingress.kubernetes.io/server-snippet: |
          add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
          add_header X-Content-Type-Options "nosniff" always;
          add_header Referrer-Policy "strict-origin-when-cross-origin" always;
          add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), interest-cohort=()" always;
          add_header Cross-Origin-Opener-Policy "same-origin" always;
          add_header Cross-Origin-Embedder-Policy "require-corp" always;
          add_header Cross-Origin-Resource-Policy "same-site" always;
          add_header X-Frame-Options "DENY" always;
          add_header Content-Security-Policy "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'" always;
    ```

    For Envoy-based ingresses (Istio, Contour, Gloo), use the gateway resource's `responseHeadersToAdd`. Enforce cluster-wide with an OPA Gatekeeper / Kyverno policy that fails apply when an `Ingress` is missing the security-snippet annotation.

## Rollout notes

### HSTS

Roll out incrementally: `max-age=300` → `max-age=86400` (one week) → `max-age=31536000; includeSubDomains` → add `preload` and submit to the [HSTS preload list](https://hstspreload.org/). **Preload submission is hard to reverse** — confirm HTTPS coverage on every subdomain, including ones not yet built, before submitting. Once a browser caches HSTS, it refuses HTTP for the `max-age` duration.

### CSP

Adopt `Content-Security-Policy-Report-Only` first, fix violations for a sprint, then switch to enforcing `Content-Security-Policy`. Nonces are per-request, generated server-side, and inserted into every `<script>` / `<style>` tag served by the same response. For SPAs, the bundler's runtime nonce configuration (Vite, Webpack `__webpack_nonce__`, Next.js CSP) is the supported way to thread the nonce into client bundles — see [React Secure Coding Guide]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-react-secure-coding/).

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

---
title: HTTP Security Headers — Configuration Reference
category: security-guidelines
version: 3.3
---

# HTTP Security Headers — Configuration Reference

<p class="doc-info">Version: 3.3</p>
___

This document covers HTTP security headers for WSO2 products. It is split into two parts:

1. **What WSO2 products ship today** — the configuration current product docs prescribe, with the canonical per-product link for each setting.
2. **Practical desired state** — the broader modern header set we want WSO2 deployments to converge to, with the configuration shape on each deployment surface. This is direction for new code and for hardening existing deployments; not all of it ships enabled-by-default in current product versions.

The companion section in the Secure Coding Guide is [Security Misconfiguration]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#security-misconfiguration).

## What WSO2 products ship today

The Carbon-based products use Tomcat's `org.apache.catalina.filters.HttpHeaderSecurityFilter`, which covers HSTS, `X-Frame-Options`, and `X-Content-Type-Options`. **HSTS is disabled by default** so development environments are not pinned to HTTPS by self-signed certificates — production deployments enable it per webapp.

* **HSTS via `deployment.toml`** (applies to every Tomcat webapp): [APIM — Enable HSTS Headers](https://apim.docs.wso2.com/en/latest/install-and-setup/setup/deployment-best-practices/security-guidelines-for-production-deployment/#enable-http-strict-transport-security-hsts-headers).
* **HSTS via per-webapp `web.xml`**: [IS — Enable HSTS Headers](https://is.docs.wso2.com/en/latest/deploy/security/enable-hsts/).
* **CSP for framing / clickjacking** (set at the Load Balancer): [APIM — Configure CSP headers](https://apim.docs.wso2.com/en/latest/install-and-setup/setup/deployment-best-practices/security-guidelines-for-production-deployment/) — the documented value is `Content-Security-Policy: frame-src 'self'; frame-ancestors 'self';`.
* **Prevent browser caching** of dynamic pages: `URLBasedCachePreventionFilter` / `ContentTypeBasedCachePreventionFilter` from `org.wso2.carbon.ui.filters.cache`. See [IS — Prevent Browser Caching](https://is.docs.wso2.com/en/latest/deploy/security/prevent-browser-caching/).
* **Server header override** to hide `WSO2 Carbon Server`: [IS — Configure Transport-Level Security](https://is.docs.wso2.com/en/latest/deploy/security/configure-transport-level-security/).

For the full per-product / per-version baseline, see [Security Guidelines for Production Deployment]({{#base_path#}}/security-guidelines/security-guidelines-for-production-deployment/).

## Practical desired state

The header set above is the existing baseline. The desired state for new WSO2 deployments — and for hardening existing ones — is the modern set below. Adopt at the deployment layer first (LB / reverse proxy / ingress) for headers that don't yet have product-default support; track product-side defaults as a hardening item per product.

| Header | Target value | Set on |
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

### Headers that must not be set

These are deprecated and either ignored or actively harmful. Remove them from any deployment that still emits them, and update any tooling that flags their absence as a finding.

| Header | Status |
|---|---|
| `X-XSS-Protection` | Chrome removed the XSS Auditor in v78 (Oct 2019); Firefox never implemented it. **Deprecated.** If any code still emits it, set the value to `0` (explicitly disable) rather than `1; mode=block` — the heuristics it enabled were themselves a source of XSS. |
| `Public-Key-Pins` (HPKP) | **Removed** from browsers — Chrome v72 (Jan 2019), Firefox v72 (Jan 2020). Operational misuse can also lock customers out of an upgraded TLS chain in legacy browsers that still parse it. |
| `Feature-Policy` | Replaced by `Permissions-Policy`. Same intent, different syntax. |
| `Expect-CT` | Deprecated by the IETF in 2024; CT enforcement is unconditional in modern browsers. |

### Where to set the headers

Headers can be set at any layer between the client and the origin. The rule is **set once, as close to the edge as practical**, and document which layer owns each header.

Layers, edge to origin:

1. **Edge / CDN** (Cloudflare, CloudFront) — best for static, site-wide headers (HSTS, CORP).
2. **Reverse proxy or Kubernetes ingress** (nginx, Envoy, ingress-nginx) — owns the bulk of headers in cloud deployments.
3. **WSO2 API Gateway** — for headers that must be set per-API or per-resource.
4. **App server** — Carbon / Tomcat (Java), HTTP middleware (Go).

Don't double-set; if the edge owns HSTS, the app server doesn't. Verify the response after each release.

## Applying the desired state by deployment surface

=== "Carbon / Tomcat"

    **Already shipped.** Tomcat's `HttpHeaderSecurityFilter` covers HSTS, `X-Frame-Options`, and `X-Content-Type-Options`. Enable HSTS via either the `deployment.toml` block or the per-webapp `web.xml` shown in [What WSO2 products ship today](#what-wso2-products-ship-today). The same filter's init-params include `antiClickJackingEnabled` / `antiClickJackingOption` and `blockContentTypeSniffingEnabled` — leave them at their secure defaults. Do not enable `xssProtectionEnabled` (`X-XSS-Protection`) — see the deprecated-headers list above.

    **Not yet a product default.** CSP (nonce-based), `Cross-Origin-Opener-Policy`, `Cross-Origin-Embedder-Policy`, `Cross-Origin-Resource-Policy`, `Permissions-Policy`, `Cache-Control: no-store` on token/PII responses, and `Clear-Site-Data` on logout are not covered by the standard `HttpHeaderSecurityFilter`. Two paths to apply them today:

    1. **Set at the deployment layer** (reverse proxy or ingress — the recommended path for existing deployments). See the *nginx* and *Kubernetes ingress* tabs below.
    2. **Wire a project-local servlet filter** that runs after `HttpHeaderSecurityFilter` so the built-in filter's HSTS and `X-Frame-Options` are preserved alongside. Recommended shape:

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

        This is the target shape; the class doesn't ship in any current WSO2 product. Per-URL overrides (looser policy for the legacy `/carbon/*` admin console that hasn't been migrated off `unsafe-inline` yet) live as a second filter instance scoped to that URL pattern.

    **Note on Jaggery.** Jaggery is deprecated. New WSO2 features should not ship Jaggery applications; existing Jaggery surfaces should be migrated.

=== "Go service middleware"

    Go services are new — apply the full desired-state header set in middleware from day one. The middleware wraps every `http.Handler`; per-route overrides (looser CSP for embedded widgets, for instance) live in the handler.

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
            h.Set("X-Frame-Options", "DENY") // legacy fallback for CSP frame-ancestors

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

=== "nginx reverse proxy"

    For existing Carbon deployments, the reverse proxy is the easiest place to apply the desired-state headers that aren't yet product defaults. `add_header` in the `server { }` block:

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

    The `always` parameter is required so headers also appear on 4xx / 5xx responses — which is exactly when they matter. nginx `add_header` directives **do not inherit** into nested `location` blocks that have their own `add_header`; declare headers at the `server` level and avoid `add_header` inside `location` blocks.

=== "Kubernetes ingress"

    For `ingress-nginx`, use `server-snippet` (or `configuration-snippet` on older versions):

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

=== "WSO2 API Gateway"

    Set headers at two levels:

    * **Globally** in the gateway's transport handler — HSTS, `X-Content-Type-Options`, `Referrer-Policy`, COOP, COEP, CORP, `Permissions-Policy`. Applied to every response served through the gateway.
    * **Per-API or per-resource** — CSP (HTML-serving APIs differ from JSON-only APIs), `Cache-Control: no-store` on token endpoints, `Clear-Site-Data` on logout endpoints.

    The recommended shape is a Synapse `class` mediator (or a sequence) in the OutSequence that appends the headers to the outgoing response; attach the mediator per-API for per-API control. New APIs should include a security-headers policy attachment by default.

## Rollout notes

### HSTS

Roll out incrementally: `max-age=300` → `max-age=86400` (one week) → `max-age=31536000; includeSubDomains` → add `preload` and submit to the [HSTS preload list](https://hstspreload.org/). **Preload submission is hard to reverse** — confirm HTTPS coverage on every subdomain, including subdomains not yet built, before submitting. Once a browser caches HSTS, it refuses HTTP for the `max-age` duration.

### CSP

Adopt `Content-Security-Policy-Report-Only` first, fix violations for a sprint, then switch to enforcing `Content-Security-Policy`. Nonces are per-request, generated server-side, and inserted into every `<script>` / `<style>` tag served by the same response. For SPAs, the bundler's runtime nonce configuration (Vite, Webpack `__webpack_nonce__`, Next.js CSP) is the supported way to thread the nonce into client bundles — see [React Secure Coding Guide]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-react-secure-coding/).

### Cache-Control on sensitive responses

Set `Cache-Control: no-store` (and `Pragma: no-cache` for HTTP/1.0 caches still in the wild) on:

* OAuth token endpoint responses
* Endpoints returning user PII
* Authenticated API responses where intermediary caches (CDN, browser, corporate proxy) are not under WSO2 control

`no-cache` is not the same as `no-store`: `no-cache` allows storage with revalidation; `no-store` forbids storage entirely.

## Verification

After any header configuration change, verify the response headers end-to-end.

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

Recommended PR-builder smoke-test against a running instance:

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

Per-header semantics, browser support, and edge cases:

* MDN: [Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security) · [Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) · [X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options) · [Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy) · [Permissions-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy) · [COOP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy) · [COEP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy) · [CORP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy) · [Clear-Site-Data](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Clear-Site-Data) · [SameSite cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite).
* [OWASP HTTP Security Response Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html).
* [HSTS Preload List](https://hstspreload.org/).
* [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/) — TLS configuration; complements the header set.
* [Tomcat 10.1 `HttpHeaderSecurityFilter` documentation](https://tomcat.apache.org/tomcat-10.1-doc/config/filter.html#HTTP_Header_Security_Filter).
* WSO2 product production-deployment guides — index: [Security Guidelines for Production Deployment]({{#base_path#}}/security-guidelines/security-guidelines-for-production-deployment/).

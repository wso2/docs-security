---
title: HTTP Security Headers — Configuration Reference
category: security-guidelines
version: 3.1
---

# HTTP Security Headers — Configuration Reference

<p class="doc-info">Version: 3.1</p>
___

This document covers **how** to apply the security header set across the deployment surfaces WSO2 ships — Carbon / Tomcat, Go services, the WSO2 API Gateway, reverse proxies, and Kubernetes ingresses. The per-header rationale, semantics, and browser behaviour are covered by MDN and OWASP — see the [external references](#external-references) section.

The companion section in the Secure Coding Guide is [Security Misconfiguration]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#security-misconfiguration).

## WSO2 baseline values

| Header | Value | Set on |
|---|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` (add `preload` only after the hostname tree is fully HTTPS) | Every TLS-terminating response |
| `Content-Security-Policy` | Nonce-based `script-src 'self' 'nonce-{n}'`; no `'unsafe-inline'`, no `'unsafe-eval'`; `frame-ancestors 'none'`; `object-src 'none'`; `base-uri 'none'` | Every HTML response |
| `X-Content-Type-Options` | `nosniff` | Every response |
| `Referrer-Policy` | `strict-origin-when-cross-origin` (stricter for admin / token-bearing surfaces) | Every response |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=(), payment=(), interest-cohort=()` (deny features the app does not use) | Every response |
| `Cross-Origin-Opener-Policy` | `same-origin` | Every HTML response; mandatory on auth UIs |
| `Cross-Origin-Embedder-Policy` | `require-corp` | Every HTML response |
| `Cross-Origin-Resource-Policy` | `same-site` | Every response |
| `Cache-Control` | `no-store` | Responses carrying tokens, session identifiers, or PII |
| `Clear-Site-Data` | `"cache", "cookies", "storage"` | Logout response only |
| `X-Frame-Options` | `DENY` (legacy fallback to `frame-ancestors`) | Every HTML response during CSP rollout |

**Cookies carrying authentication or session state:** `HttpOnly; Secure; SameSite=Strict; Path=<narrow>`. Set `Domain` only when cross-subdomain sharing is required.

### Headers that must not be set

These are deprecated and either ignored or actively harmful. If present in a deployment today, remove them — and update any tooling that still reports their absence as a finding.

| Header | Status |
|---|---|
| `X-XSS-Protection` | Chrome removed the XSS Auditor in v78 (Oct 2019); Firefox never implemented it. **Deprecated.** If any code still emits it, set the value to `0` (explicitly disable) rather than `1; mode=block` — the heuristics it enabled were themselves a source of XSS. |
| `Public-Key-Pins` (HPKP) | **Removed** from browsers — Chrome v72 (Jan 2019), Firefox v72 (Jan 2020). The header does nothing. Operational misuse can also lock customers out of an upgraded TLS chain in legacy browsers that still parse it. |
| `Feature-Policy` | Replaced by `Permissions-Policy`. Same intent, different syntax. |
| `Expect-CT` | Deprecated by the IETF in 2024; CT enforcement is unconditional in modern browsers. |

## Where to set the headers

Headers can be set at any layer between the client and the origin. The WSO2 rule is **set once, as close to the edge as practical**, and document which layer owns each header.

A typical WSO2 deployment, edge to origin:

1. **Edge / CDN** (Cloudflare, CloudFront) — best for static, site-wide headers (HSTS, CORP).
2. **Reverse proxy or Kubernetes ingress** (nginx, Envoy, ingress-nginx) — owns the bulk of headers in cloud deployments.
3. **WSO2 API Gateway** — for headers that must be set per-API or per-resource.
4. **App server** — Carbon / Tomcat for the Java stack; Go HTTP middleware for the Go stack.

Don't double-set; if the edge owns HSTS, the app server doesn't. Verify the response after each release.

For customer deployments where WSO2 runs behind a customer-controlled proxy, the WSO2 product is responsible for setting headers at the app-server level so the security posture is correct out of the box. Customers may move enforcement to their proxy if they prefer.

## Configuration by deployment surface

=== "Carbon / Tomcat"

    Carbon products run on an embedded Tomcat (9 or 10 in current releases). Tomcat's `org.apache.catalina.filters.HttpHeaderSecurityFilter` covers HSTS, `X-Frame-Options`, and `X-Content-Type-Options`. The newer headers — CSP, COOP, COEP, CORP, Permissions-Policy, Cache-Control, Clear-Site-Data — need a custom filter.

    **`web.xml` — Tomcat's built-in filter for the headers it does cover:**

    ```xml
    <filter>
        <filter-name>HttpHeaderSecurityFilter</filter-name>
        <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
        <init-param><param-name>hstsEnabled</param-name><param-value>true</param-value></init-param>
        <init-param><param-name>hstsMaxAgeSeconds</param-name><param-value>31536000</param-value></init-param>
        <init-param><param-name>hstsIncludeSubDomains</param-name><param-value>true</param-value></init-param>
        <init-param><param-name>antiClickJackingEnabled</param-name><param-value>true</param-value></init-param>
        <init-param><param-name>antiClickJackingOption</param-name><param-value>DENY</param-value></init-param>
        <init-param><param-name>blockContentTypeSniffingEnabled</param-name><param-value>true</param-value></init-param>
        <!-- xssProtectionEnabled is omitted on purpose. X-XSS-Protection is
             deprecated; do not enable it. -->
    </filter>
    <filter-mapping>
        <filter-name>HttpHeaderSecurityFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
    ```

    In a development `web.xml`, set `hstsEnabled` to `false` so non-HTTPS local development is not pinned to HTTPS in the browser.

    **Custom filter for the headers Tomcat's built-in filter does not cover** (CSP, COOP, COEP, CORP, Permissions-Policy, Cache-Control on sensitive responses, Clear-Site-Data on logout):

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

    Map it in `web.xml` with `<url-pattern>/*</url-pattern>` **after** `HttpHeaderSecurityFilter` so the built-in filter's HSTS and `X-Frame-Options` are preserved alongside the additions.

    **Per-URL overrides.** Where a path needs a looser policy (e.g., the legacy `/carbon/*` admin console that has not yet been migrated off `unsafe-inline`), define a second filter instance scoped to that URL pattern. Document the deviation as a tracked hardening item.

    **Note on Jaggery.** Jaggery is deprecated; historical `HttpHeaderSecurityFilter` examples for Jaggery are no longer maintained here. New WSO2 features should not ship Jaggery applications; existing Jaggery surfaces should be migrated.

=== "Go service middleware"

    Apply the full header set in one middleware that wraps every `http.Handler`. Per-route overrides (looser CSP for embedded widgets, for instance) live in the handler itself.

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

    `add_header` in the `server { }` block. The `always` parameter is required so headers also appear on 4xx/5xx — which is exactly when they matter.

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

    nginx `add_header` directives **do not inherit** into nested `location` blocks that have their own `add_header`. Declare headers at the `server` level and avoid `add_header` inside `location` blocks, or restate the full set if you must.

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

    * **Globally** in the gateway's transport handler — for HSTS, `X-Content-Type-Options`, `Referrer-Policy`, COOP, COEP, CORP, `Permissions-Policy`. Applied to every response served through the gateway.
    * **Per-API or per-resource** — for CSP (the CSP of an HTML-serving API differs from a JSON-only API), `Cache-Control: no-store` on token endpoints, `Clear-Site-Data` on logout endpoints.

    The standard pattern is a synapse `class` mediator (or a sequence) in the OutSequence that appends the headers to the outgoing response. For per-API control, attach the same mediator to the specific API's OutSequence rather than the global one.

    New APIs published on the gateway should include a security-headers policy attachment by default. Document deviations.

## WSO2 rollout notes

The general header semantics are in MDN; what follows is the WSO2-specific operational guidance.

### HSTS

Roll out incrementally: `max-age=300` → `max-age=86400` (one week) → `max-age=31536000; includeSubDomains` → add `preload` and submit to the [HSTS preload list](https://hstspreload.org/). **Preload submission is hard to reverse** — confirm HTTPS coverage on every subdomain, including ones not yet built, before submitting. Once a browser caches HSTS, it refuses HTTP for the `max-age` duration.

### CSP

Adopt **`Content-Security-Policy-Report-Only`** first, fix violations for a sprint, then switch to enforcing `Content-Security-Policy`. Nonces are per-request, generated server-side, and inserted into every `<script>` / `<style>` tag served by the same response. For SPAs, the bundler's runtime nonce configuration (Vite, Webpack `__webpack_nonce__`, Next.js CSP) is the supported way to thread the nonce into client bundles — see [React Secure Coding Guide]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/general-recommendations-for-react-secure-coding/).

### Cache-Control on sensitive responses

Set `Cache-Control: no-store` (and `Pragma: no-cache` for HTTP/1.0 caches still in the wild) on:

* OAuth token endpoint responses
* Endpoints returning user PII
* Authenticated API responses where intermediary caches (CDN, browser, corporate proxy) are not under WSO2 control

`no-cache` is not the same as `no-store`: `no-cache` allows storage with revalidation; `no-store` forbids storage entirely.

## Verification

After any header change, verify the response shape end-to-end.

### `curl` check

```sh
curl -sI https://example.wso2.com/ \
  | grep -iE '^(strict-transport-security|content-security-policy|x-content-type-options|referrer-policy|permissions-policy|cross-origin-opener-policy|cross-origin-embedder-policy|cross-origin-resource-policy|x-frame-options|cache-control|clear-site-data|server):'
```

Each expected header should appear exactly once. `X-XSS-Protection` (or, if present, only with value `0`), `Public-Key-Pins`, `Feature-Policy`, `Expect-CT` must not appear. The `Server` header must not disclose product/version.

### Automated scanners

* [Mozilla Observatory](https://observatory.mozilla.org/) — aim for grade A or A+.
* [securityheaders.com](https://securityheaders.com/) — quick external scan.
* OWASP ZAP passive scan — runs as part of the dynamic-analysis pipeline; see [Dynamic Analysis with OWASP ZAP]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/dynamic-analysis-with-owasp-zap/). Tune the ZAP policy to expect the modern header set, not legacy ones — by default ZAP still flags missing `X-XSS-Protection`, which is no longer the right signal.

### CI gate

The PR builder includes a header smoke-test against a running instance:

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

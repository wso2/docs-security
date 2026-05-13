---
title: HTTP Security Headers — Configuration Reference
category: security-guidelines
version: 3.0
---

# HTTP Security Headers — Configuration Reference

<p class="doc-info">Version: 3.0</p>
___

This document is the practical "how to apply" companion to the [Secure Coding Guide — Security Misconfiguration]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#security-misconfiguration) section. That section is the canonical statement of **which** headers to set and why; this document covers **how** to apply them across the deployment surfaces WSO2 ships — Carbon / Tomcat, Go services, the WSO2 API Gateway, reverse proxies, and Kubernetes ingresses.

Read the Secure Coding Guide first for the per-header rationale. The reference table below is a recap.

## Headers to set

| Header | Value (default) | Set on |
|---|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` (add `preload` only after the hostname tree is fully HTTPS) | Every TLS-terminating response |
| `Content-Security-Policy` | Nonce-based `script-src 'self' 'nonce-{n}'`; no `'unsafe-inline'`, no `'unsafe-eval'`; `frame-ancestors 'none'`; `object-src 'none'`; `base-uri 'none'` | Every HTML response |
| `X-Content-Type-Options` | `nosniff` | Every response |
| `Referrer-Policy` | `strict-origin-when-cross-origin` (or stricter for admin / token-bearing surfaces) | Every response |
| `Permissions-Policy` | Deny features the app doesn't use, e.g. `geolocation=(), microphone=(), camera=(), payment=(), interest-cohort=()` | Every response |
| `Cross-Origin-Opener-Policy` | `same-origin` | Every HTML response; mandatory on auth UIs |
| `Cross-Origin-Embedder-Policy` | `require-corp` | Every HTML response |
| `Cross-Origin-Resource-Policy` | `same-site` | Every response |
| `Cache-Control` | `no-store` | Responses carrying tokens, session identifiers, or PII |
| `Clear-Site-Data` | `"cache", "cookies", "storage"` | Logout response only |
| `X-Frame-Options` | `DENY` (legacy fallback to `frame-ancestors`) | Every HTML response while CSP rollout is in progress |

### Cookies that carry authentication or session state

`HttpOnly; Secure; SameSite=Strict; Path=<narrow>`. Set `Domain` only when cross-subdomain sharing is required and document why.

### Headers you must not set

These are deprecated and either ignored by browsers or actively unhelpful. If a deployment has them today, remove them:

| Header | Status |
|---|---|
| `X-XSS-Protection` | Chrome removed the XSS Auditor in v78 (October 2019); Firefox never implemented it. The header is **deprecated**. Where any code still sets it, change the value to `0` (explicitly disable). Do not set `1; mode=block` — the heuristics it enabled were themselves a source of XSS in some cases. |
| `Public-Key-Pins` (HPKP) | **Removed from browsers** — Chrome dropped HPKP in v72 (January 2019), Firefox in v72 (January 2020). The header does nothing. Operational misuse can also lock customers out of an upgraded TLS chain in legacy browsers that still parse it. |
| `Feature-Policy` | Replaced by `Permissions-Policy`. Same intent, different syntax. |
| `Expect-CT` | Deprecated by the IETF in 2024; certificate-transparency enforcement is now expected unconditionally by modern browsers. |

## Where to set the headers

Headers can be set at any layer between the client and the origin. The rule is **set once, as close to the edge as practical**, and document which layer owns each header.

A typical WSO2 deployment has these layers, in order from edge to origin:

1. **Edge / CDN** (Cloudflare, CloudFront) — best for static, site-wide headers (HSTS, CORP).
2. **Reverse proxy or Kubernetes ingress** (nginx, Envoy, ingress-nginx) — owns the bulk of headers in cloud deployments.
3. **WSO2 API Gateway** — for headers that must be set per-API or per-resource.
4. **App server** — Carbon / Tomcat for the established Java stack; Go HTTP middleware for the Go stack.

Headers set at a later layer can override headers set earlier, depending on the proxy configuration. To avoid surprises, **pick one layer per header and verify the response after each release**. Don't double-set; if the edge sets HSTS, the app server doesn't.

For a deployment where the customer runs WSO2 behind their own proxy, the WSO2 product is responsible for setting headers at the app-server level so the security posture is correct out of the box. Customers may then move enforcement to their proxy.

## Configuration by deployment surface

=== "Carbon / Tomcat"

    Carbon products run on an embedded Tomcat (9 or 10 in current releases). Tomcat ships `org.apache.catalina.filters.HttpHeaderSecurityFilter`, which covers HSTS, `X-Frame-Options`, and `X-Content-Type-Options`. The newer headers — CSP, COOP, COEP, CORP, Permissions-Policy, Cache-Control, Clear-Site-Data — are not covered by that filter and need either a Tomcat `expires` / response-header filter or a small custom filter.

    **Production `web.xml` — Tomcat's built-in filter for the headers it does cover:**

    ```xml
    <filter>
        <filter-name>HttpHeaderSecurityFilter</filter-name>
        <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
        <init-param>
            <param-name>hstsEnabled</param-name>
            <param-value>true</param-value>
        </init-param>
        <init-param>
            <param-name>hstsMaxAgeSeconds</param-name>
            <param-value>31536000</param-value>
        </init-param>
        <init-param>
            <param-name>hstsIncludeSubDomains</param-name>
            <param-value>true</param-value>
        </init-param>
        <init-param>
            <param-name>antiClickJackingEnabled</param-name>
            <param-value>true</param-value>
        </init-param>
        <init-param>
            <param-name>antiClickJackingOption</param-name>
            <param-value>DENY</param-value>
        </init-param>
        <init-param>
            <param-name>blockContentTypeSniffingEnabled</param-name>
            <param-value>true</param-value>
        </init-param>
        <!-- xssProtectionEnabled is omitted on purpose. The X-XSS-Protection
             header is deprecated; do not enable it. -->
    </filter>
    <filter-mapping>
        <filter-name>HttpHeaderSecurityFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
    ```

    **Development `web.xml`** — same as production but with `hstsEnabled` set to `false` (so non-HTTPS local development is not pinned to HTTPS in the browser).

    **For the headers Tomcat's built-in filter does not cover** — CSP, COOP, COEP, CORP, Permissions-Policy, Cache-Control on sensitive responses, Clear-Site-Data on logout — use a `org.apache.catalina.filters.ResponseHeaderFilter` chain or a custom servlet filter. Sketch of a custom filter:

    ```java
    public class ModernSecurityHeadersFilter implements Filter {
        @Override
        public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
                throws IOException, ServletException {
            HttpServletResponse r = (HttpServletResponse) res;
            String nonce = generatePerRequestNonce(); // 16 bytes, base64
            req.setAttribute("cspNonce", nonce);      // for JSP to read

            r.setHeader("Content-Security-Policy",
                "default-src 'self'; "
                + "script-src 'self' 'nonce-" + nonce + "'; "
                + "style-src 'self' 'nonce-" + nonce + "'; "
                + "object-src 'none'; "
                + "frame-ancestors 'none'; "
                + "base-uri 'none'; "
                + "form-action 'self'");
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

    Wire it into `web.xml` with a `<url-pattern>/*</url-pattern>` mapping placed **after** `HttpHeaderSecurityFilter` so HSTS and `X-Frame-Options` from the built-in filter are preserved alongside the additions.

    **Per-URL overrides.** Where a particular path needs a looser policy (legacy admin console under `/carbon/*` that has not yet been migrated off `unsafe-inline`, for example), define a second filter instance and map it only to that URL pattern. Document the deviation as a tracked hardening item.

    **Note on Jaggery.** Jaggery is deprecated and the historical Jaggery configuration examples for `HttpHeaderSecurityFilter` are no longer maintained here. New WSO2 features should not ship Jaggery applications; existing Jaggery surfaces should be migrated.

=== "Go service middleware"

    Set the full header set in a single piece of middleware that wraps every `http.Handler`. Apply once at the router root; per-route overrides (looser CSP for embedded widgets, etc.) live in the handler itself.

    ```go
    package web

    import (
        "crypto/rand"
        "encoding/base64"
        "fmt"
        "net/http"
    )

    // SecurityHeaders wraps the handler and applies the canonical header set.
    func SecurityHeaders(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            nonce := generateNonce()
            h := w.Header()
            h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
            h.Set("Content-Security-Policy", fmt.Sprintf(
                "default-src 'self'; "+
                    "script-src 'self' 'nonce-%s'; "+
                    "style-src 'self' 'nonce-%s'; "+
                    "object-src 'none'; "+
                    "frame-ancestors 'none'; "+
                    "base-uri 'none'; "+
                    "form-action 'self'",
                nonce, nonce))
            h.Set("X-Content-Type-Options", "nosniff")
            h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
            h.Set("Permissions-Policy",
                "geolocation=(), microphone=(), camera=(), payment=(), interest-cohort=()")
            h.Set("Cross-Origin-Opener-Policy", "same-origin")
            h.Set("Cross-Origin-Embedder-Policy", "require-corp")
            h.Set("Cross-Origin-Resource-Policy", "same-site")
            h.Set("X-Frame-Options", "DENY") // legacy fallback for CSP frame-ancestors
            // X-XSS-Protection is deliberately not set. If the framework adds it,
            // override with the value 0 to disable any residual heuristic.

            // Per-request: hand the nonce to the template via context.
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

    For responses that carry tokens or PII, add `Cache-Control: no-store` at the handler:

    ```go
    func writeTokenResponse(w http.ResponseWriter, body any) {
        w.Header().Set("Cache-Control", "no-store")
        w.Header().Set("Pragma", "no-cache") // HTTP/1.0 fallback
        w.Header().Set("Content-Type", "application/json")
        _ = json.NewEncoder(w).Encode(body)
    }
    ```

    On the logout response, add `Clear-Site-Data`:

    ```go
    func logoutHandler(w http.ResponseWriter, r *http.Request) {
        // ... server-side session invalidation + revocation_endpoint call ...
        w.Header().Set("Clear-Site-Data", `"cache", "cookies", "storage"`)
        http.Redirect(w, r, "/login", http.StatusSeeOther)
    }
    ```

=== "nginx reverse proxy"

    `add_header` in the `server { }` block applies to every response from that server.

    ```nginx
    server {
        listen 443 ssl http2;
        server_name example.wso2.com;

        # Header set
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), interest-cohort=()" always;
        add_header Cross-Origin-Opener-Policy "same-origin" always;
        add_header Cross-Origin-Embedder-Policy "require-corp" always;
        add_header Cross-Origin-Resource-Policy "same-site" always;
        add_header X-Frame-Options "DENY" always;

        # CSP - if the upstream cannot generate per-request nonces, fall back to
        # a strict 'self'-only policy. Adopt nonce-based CSP at the upstream as
        # soon as the application supports it.
        add_header Content-Security-Policy "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'" always;

        # ... proxy_pass etc ...
    }
    ```

    The `always` parameter is important: without it, nginx omits `add_header` directives from error responses (4xx/5xx), which is exactly when the headers matter most.

    `nginx` directives **do not inherit** across nested `location` blocks once a `location` block has its own `add_header`. If any `location` adds a header, it must re-state the full set. The cleanest pattern is to declare the headers at the `server` level and avoid `add_header` inside `location` blocks.

=== "Kubernetes ingress"

    For `ingress-nginx`, the canonical pattern is the `configuration-snippet` or (in newer versions) `server-snippet` annotation, which injects directives into the generated nginx config:

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
    spec:
      # ...
    ```

    For Envoy-based ingresses (Istio, Contour, Gloo), set the headers via the gateway resource's `response_headers_to_add`:

    ```yaml
    routeAction:
      hostRewriteLiteral: backend.svc.cluster.local
    requestHeadersToAdd: []
    responseHeadersToAdd:
      - header:
          key: Strict-Transport-Security
          value: "max-age=31536000; includeSubDomains; preload"
      - header:
          key: X-Content-Type-Options
          value: "nosniff"
      # ... rest of the set
    ```

    Note: cluster-wide enforcement via a `NetworkPolicy`, `OPA Gatekeeper`, or `Kyverno` policy is the recommended way to make these headers mandatory across all ingresses in a namespace. A linting policy that fails the apply when an `Ingress` is missing the security-snippet annotation prevents drift.

=== "WSO2 API Gateway"

    The API Gateway sits in front of every published API. Headers can be set at two levels:

    * **Globally** — applied to every response served through the gateway. Configure in the gateway's transport handler (the response is augmented before it is sent to the client). This is the right level for HSTS, `X-Content-Type-Options`, `Referrer-Policy`, COOP, COEP, CORP, and `Permissions-Policy`.
    * **Per-API or per-resource** — applied only for specific APIs. The right level for CSP (because the CSP of an HTML-serving API differs from a JSON-only API), `Cache-Control: no-store` on token endpoints, and `Clear-Site-Data` on logout endpoints.

    The standard pattern is a synapse `class` mediator (or a sequence) that runs in the OutSequence and appends the headers to the outgoing response. For per-API control, attach the same mediator to the specific API's OutSequence rather than the global sequence.

    For new APIs published on the gateway, the API definition should include a security-headers policy attachment by default. Document deviations.

## Specific header guidance

Beyond the table at the top, some headers need configuration nuance.

### Strict-Transport-Security (HSTS)

Roll out incrementally to avoid bricking the site:

1. Start at `max-age=300` (5 minutes). Verify nothing breaks. Quick to revert.
2. Increase to `max-age=86400` (1 day) for a week. Continue verifying.
3. Increase to `max-age=31536000; includeSubDomains` (1 year with subdomains pinned).
4. Add `preload`, then submit to the [HSTS preload list](https://hstspreload.org/). Preload submission is hard to reverse; verify HTTPS coverage on every subdomain (including ones that haven't been built yet but may be added).

Never set HSTS on a hostname that the customer cannot fully control over HTTPS. Once a browser caches HSTS, it refuses HTTP for the `max-age` duration.

### Content-Security-Policy

Adopt **report-only** first, fix the violations, then enforce:

```
Content-Security-Policy-Report-Only:
  default-src 'self';
  script-src 'self' 'nonce-{n}';
  ...
  report-to csp-endpoint;
```

Configure a `Report-To` group and a reporting endpoint that ingests CSP violation reports. Once the report-only run is clean for a sprint, switch to the enforcing `Content-Security-Policy` header.

Nonces are per-request, generated server-side, and inserted into every `<script>` and `<style>` tag served by the same response. A bundler's runtime configuration (Vite, Webpack `__webpack_nonce__`, Next.js [CSP nonce support](https://nextjs.org/docs/app/building-your-application/configuring/content-security-policy)) is the supported way to thread the nonce into client-side bundles.

### SameSite cookies

* `SameSite=Strict` for authentication and session cookies. The cookie is not sent on cross-site navigations — even GET — which prevents CSRF without a token.
* `SameSite=Lax` for general site cookies. The cookie is sent on top-level GET navigations from external sites; the default in modern browsers.
* `SameSite=None` only with `Secure`, only when the cookie genuinely must be sent cross-site (e.g., a federated authentication flow). The default `Lax` is rarely the wrong answer; reviewers should require justification before `None`.

### Cache-Control on sensitive responses

`Cache-Control: no-store` on:

* OAuth token endpoint responses
* Endpoints returning user PII
* Authenticated API responses if intermediary caches (CDN, browser, corporate proxy) are not under WSO2 control

Add `Pragma: no-cache` alongside for HTTP/1.0 caches still in the wild. `no-cache` is **not** the same as `no-store`: `no-cache` allows storage with revalidation; `no-store` forbids storage entirely.

### Clear-Site-Data on logout

```
Clear-Site-Data: "cache", "cookies", "storage"
```

Sent on the response to the logout endpoint, this instructs the browser to wipe cached HTML, cookies, and `localStorage`/`sessionStorage`/IndexedDB for the origin. Pair with server-side session invalidation and OAuth `revocation_endpoint` (RFC 7009) — `Clear-Site-Data` only handles the client side.

## Verification

After any header configuration change, verify the response shape end-to-end.

### Per-header `curl` check

```sh
curl -sI https://example.wso2.com/ \
  | grep -iE '^(strict-transport-security|content-security-policy|x-content-type-options|referrer-policy|permissions-policy|cross-origin-opener-policy|cross-origin-embedder-policy|cross-origin-resource-policy|x-frame-options|cache-control|clear-site-data|server):'
```

The output should include each expected header exactly once and should not include `X-XSS-Protection` (or, if present, only with the value `0`), `Public-Key-Pins`, `Feature-Policy`, or `Expect-CT`. The `Server` header should not disclose a product/version.

### Automated scanners

* **[Mozilla Observatory](https://observatory.mozilla.org/)** — scores the response, lists missing or weak headers, and gives concrete remediations. Aim for grade A or A+.
* **[securityheaders.com](https://securityheaders.com/)** — quick external scan with the same intent.
* **OWASP ZAP** passive scan — runs as part of the dynamic-analysis pipeline; see [Dynamic Analysis with OWASP ZAP]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/dynamic-analysis-with-owasp-zap/). The "Application Error Disclosure" and "Web Browser XSS Protection Not Enabled" rules in ZAP's default policy are the relevant ones; tune the policy to expect the modern header set rather than legacy ones.

### CI gate

The PR builder should include a header smoke-test against a running instance:

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

## References

* [MDN — Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)
* [MDN — Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
* [MDN — X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options)
* [MDN — Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy)
* [MDN — Permissions-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy)
* [MDN — Cross-Origin-Opener-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy)
* [MDN — Cross-Origin-Embedder-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy)
* [MDN — Cross-Origin-Resource-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy)
* [MDN — Clear-Site-Data](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Clear-Site-Data)
* [MDN — Cookies: SameSite](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)
* [OWASP HTTP Security Response Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
* [HSTS Preload List](https://hstspreload.org/)
* [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/) — TLS configuration, complements the header set.
* [Tomcat `HttpHeaderSecurityFilter` documentation](https://tomcat.apache.org/tomcat-10.1-doc/config/filter.html#HTTP_Header_Security_Filter) (current Tomcat 10.1 version).

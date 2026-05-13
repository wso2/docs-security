---
title: HTTP Security Headers — Configuration Reference
category: security-guidelines
version: 3.2
---

# HTTP Security Headers — Configuration Reference

<p class="doc-info">Version: 3.2</p>
___

This page documents the HTTP security header configuration that current WSO2 products ship and the WSO2 product docs that go with each. Use the per-product production-deployment guide for the authoritative configuration — those guides are kept current per product version.

* [Security Guidelines for Production Deployment]({{#base_path#}}/security-guidelines/security-guidelines-for-production-deployment/) — index of per-product / per-version guides (APIM, IS, MI, EI).

The companion section in the Secure Coding Guide is [Security Misconfiguration]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#security-misconfiguration).

## What WSO2 products ship today

Current Carbon-based products use the standard Tomcat security header filter, [`org.apache.catalina.filters.HttpHeaderSecurityFilter`](https://tomcat.apache.org/tomcat-10.1-doc/config/filter.html#HTTP_Header_Security_Filter), which covers:

* `Strict-Transport-Security` (HSTS) — opt-in per webapp.
* `X-Frame-Options` — clickjacking defence.
* `X-Content-Type-Options: nosniff` — MIME-sniffing defence.

HSTS is **disabled by default** so that development environments are not pinned to HTTPS by self-signed certificates. Production deployments enable it per webapp.

For Content-Security-Policy, current WSO2 APIM guidance is to **set a minimal framing CSP at the Load Balancer**:

```
Content-Security-Policy: frame-src 'self'; frame-ancestors 'self';
```

For preventing browser caching of dynamic pages with sensitive content, WSO2 ships:

* `URLBasedCachePreventionFilter`
* `ContentTypeBasedCachePreventionFilter`

in `org.wso2.carbon.ui.filters.cache`, applied via the webapp's `web.xml`.

For modern headers beyond this set — nonce-based CSP, Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, Cross-Origin-Resource-Policy, Permissions-Policy, Clear-Site-Data on logout — WSO2 products do not currently ship default configuration. Adopting them is a deployment-level concern (LB / reverse proxy / ingress), and the per-product docs above are the right source if and when that changes.

## Configuration on Carbon / Tomcat

### HSTS via `deployment.toml` (applies to every Tomcat webapp)

The pattern WSO2 APIM documents for enabling HSTS across every Tomcat-deployed webapp (Management Console, Publisher, DevPortal, Admin):

```toml
[[tomcat.filter]]
name = "httpHeaderSecurity"
class = "org.apache.catalina.filters.HttpHeaderSecurityFilter"
async_supported = true

[tomcat.filter.init_params]
hstsEnabled = true
hstsMaxAgeSeconds = 31536000
hstsIncludeSubDomains = true

[[tomcat.filter_mapping]]
name = "httpHeaderSecurity"
url_pattern = "/*"
dispatchers = "REQUEST"
```

Source: [APIM — Security Guidelines for Production Deployment, "Enable HSTS Headers"](https://apim.docs.wso2.com/en/latest/install-and-setup/setup/deployment-best-practices/security-guidelines-for-production-deployment/#enable-http-strict-transport-security-hsts-headers).

### HSTS via per-webapp `web.xml`

To enable HSTS only for a specific webapp, edit the `web.xml` file at `<PRODUCT_HOME>/repository/deployment/server/webapps/<WEBAPP>/WEB-INF/web.xml`:

```xml
<filter>
    <filter-name>HttpHeaderSecurityFilter</filter-name>
    <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
    <init-param>
        <param-name>hstsMaxAgeSeconds</param-name>
        <param-value>15768000</param-value>
    </init-param>
</filter>
<filter-mapping>
    <filter-name>HttpHeaderSecurityFilter</filter-name>
    <url-pattern>*</url-pattern>
</filter-mapping>
```

Source: [IS — Enable HSTS Headers](https://is.docs.wso2.com/en/latest/deploy/security/enable-hsts/).

The same `HttpHeaderSecurityFilter` covers `X-Frame-Options` (`antiClickJackingEnabled`, `antiClickJackingOption`) and `X-Content-Type-Options: nosniff` (`blockContentTypeSniffingEnabled`). Refer to the [Tomcat filter reference](https://tomcat.apache.org/tomcat-10.1-doc/config/filter.html#HTTP_Header_Security_Filter) for the full init-param list.

### Preventing browser caching for sensitive pages

For dynamic pages with sensitive content, WSO2 IS documents adding either `URLBasedCachePreventionFilter` or `ContentTypeBasedCachePreventionFilter` to the webapp's `web.xml`. The applications shipped with the product include cache prevention by default; new applications must opt in.

```
Expires: 0
Pragma: no-cache
Cache-Control: no-store, no-cache, must-revalidate
```

Source: [IS — Prevent Browser Caching](https://is.docs.wso2.com/en/latest/deploy/security/prevent-browser-caching/).

### Server header

By default, Carbon products return `Server: WSO2 Carbon Server`, which discloses the product family. Override via the `[transport.https.properties]` section of `deployment.toml`. See [IS — Configure Transport-Level Security](https://is.docs.wso2.com/en/latest/deploy/security/configure-transport-level-security/) for the per-version syntax.

## CSP for clickjacking / framing defence

WSO2 APIM documents setting the following at the Load Balancer:

```
Content-Security-Policy: frame-src 'self'; frame-ancestors 'self';
```

* `frame-src 'self'` — restricts framing inside the application to same-origin content.
* `frame-ancestors 'self'` — prevents the application being embedded by external origins (clickjacking mitigation).

This is narrower than a full content CSP (no `script-src` / `style-src` / `default-src` nonces) and is the only CSP guidance the current production-deployment docs prescribe.

Source: [APIM — Configure Content Security Policy (CSP) headers](https://apim.docs.wso2.com/en/latest/install-and-setup/setup/deployment-best-practices/security-guidelines-for-production-deployment/).

## CSRF on browser-rendered admin UIs

CSRF defence on the Carbon admin UIs is handled by OWASP CSRFGuard (session cookie plus a token). See [OWASP CSRFGuard]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/owasp-csrf-guard/).

## Cookies that carry authentication or session state

`HttpOnly`, `Secure`, and `SameSite` apply at the cookie level rather than the header level. Carbon products set `HttpOnly` and `Secure` on `JSESSIONID` and authentication cookies by default. Where the deployment is fronted by a reverse proxy that strips or rewrites cookies, verify the rewritten cookie still carries these attributes.

## Verification

After any header configuration change, verify the response headers end-to-end.

### `curl` check

```sh
curl -sI https://example.wso2.com/carbon/ \
  | grep -iE '^(strict-transport-security|content-security-policy|x-content-type-options|x-frame-options|cache-control|server):'
```

The `Server` header should be overridden (not `WSO2 Carbon Server`). HSTS should be present on every TLS-terminating response. `X-Frame-Options` and `X-Content-Type-Options` should be present on every response served through `HttpHeaderSecurityFilter`.

### Automated scanners

* [Mozilla Observatory](https://observatory.mozilla.org/).
* [securityheaders.com](https://securityheaders.com/).
* OWASP ZAP passive scan — see [Dynamic Analysis with OWASP ZAP]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/dynamic-analysis-with-owasp-zap/).

## External references

Per-header semantics, browser support, and edge cases:

* MDN: [Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security) · [Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) · [X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options) · [X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options) · [Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy) · [SameSite cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite).
* [OWASP HTTP Security Response Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html).
* [HSTS Preload List](https://hstspreload.org/) — submission for `preload` HSTS.
* [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/) — TLS configuration; complements the header set.
* [Tomcat 10.1 `HttpHeaderSecurityFilter` documentation](https://tomcat.apache.org/tomcat-10.1-doc/config/filter.html#HTTP_Header_Security_Filter).

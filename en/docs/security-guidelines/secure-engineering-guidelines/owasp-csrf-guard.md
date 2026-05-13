---
title: CSRF Defence — Carbon / CSRFGuard Configuration
category: security-guidelines
version: 3.0
---

# CSRF Defence — Carbon / CSRFGuard Configuration

<p class="doc-info">Version: 3.0</p>
___

This document covers Cross-Site Request Forgery defence for the **Carbon-based Java products**. The general CSRF rule (when CSRF tokens are required, when `SameSite` cookies suffice, what state-changing endpoints look like) is in [Secure Coding Guide — Cross-Site Request Forgery (CSRF)]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#cross-site-request-forgery-csrf). This page is the operational configuration reference for the Carbon stack.

## Threat model in 2026

A CSRF attack tricks an authenticated user's browser into issuing a state-changing request to a target site the user is logged into. The browser attaches the user's session cookie automatically; the target site cannot tell the request was not initiated by the user.

The browser landscape has changed materially since the original WSO2 CSRFGuard integration was written:

* Modern browsers default cookies to `SameSite=Lax` if no `SameSite` attribute is set. `Lax` is sufficient against most cross-site form POSTs and AJAX. `Strict` is sufficient against all of them.
* Bearer-token APIs (`Authorization: Bearer …`) are not vulnerable to CSRF because the token is not sent automatically by the browser — only by explicit code. State-changing REST APIs that authenticate exclusively with bearer tokens do not need CSRF tokens.

Where CSRF tokens still earn their keep:

* Browser-rendered admin consoles and management UIs that rely on session cookies — Carbon Management Console, the IS My Account / Console UIs, APIM Publisher / DevPortal UIs.
* Multipart upload endpoints reached from a browser form.
* AJAX endpoints reached from a browser-served SPA that uses session cookies (rather than the BFF pattern).

For these surfaces in the Carbon stack, the defence is **`SameSite=Strict` on the session cookie *plus* CSRFGuard tokens**. Either alone is acceptable in some configurations; both together is defence in depth and matches the existing Carbon deployment shape.

## Recommended approach for WSO2 products

1. **State-changing actions use POST**, with PUT and DELETE acceptable on REST endpoints. GET never has side effects. CSRFGuard does not validate GET (the `UnprotectedMethods=GET` setting).
2. **Session cookies are `HttpOnly; Secure; SameSite=Strict`**. See [HTTP Security Headers — Configuration Reference]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/security-related-http-headers/) for the cookie-flag baseline.
3. **CSRFGuard tokens are injected into POST forms** via the JavaScript injection mechanism (hidden input field). Token in URL is forbidden — it would leak via referer headers, browser history, and access logs.
4. **AJAX POST requests carry the CSRF token in a header**, set automatically by the CSRFGuard JavaScript. Manual injection with the JSP taglib is only acceptable in the narrow cases listed in the checklist below, with explicit Security and Compliance Team approval.
5. **Per-product CSRF exclusion URLs** are appended to `repository/conf/security/Owasp.CsrfGuard.Carbon.properties` during the distribution build. Exclusions are reviewable — every entry has a reason.
6. **Bearer-token-only REST APIs** (no session cookie) skip CSRFGuard. Document this in the API specification.

## CSRFGuard version

WSO2 carbon products historically pinned CSRFGuard 3.x. Current CSRFGuard upstream is 4.x (released 2021, with 4.4.0 in 2024). 4.x added improved per-page tokens, removed legacy behaviours, and changed several configuration keys. Before adopting 4.x in a Carbon product, verify the configuration keys against the [current CSRFGuard documentation](https://owasp.org/www-project-csrfguard/) and run the existing integration test suite. The configuration shown below is for the version Carbon ships with; consult the [CSRFGuard release notes](https://github.com/OWASP/www-project-csrfguard) for upgrades.

## Servlet wiring

`web.xml` additions to enable CSRFGuard on a Carbon web application:

```xml
<!-- CSRFGuard context listener — reads configuration -->
<listener>
    <listener-class>org.owasp.csrfguard.CsrfGuardServletContextListener</listener-class>
</listener>

<!-- CSRFGuard session listener — generates a per-session token -->
<listener>
    <listener-class>org.owasp.csrfguard.CsrfGuardHttpSessionListener</listener-class>
</listener>

<!-- Per-application configuration file location -->
<context-param>
    <param-name>Owasp.CsrfGuard.Config</param-name>
    <param-value>repository/conf/security/Owasp.CsrfGuard.Carbon.properties</param-value>
</context-param>

<!-- CSRFGuard validation filter -->
<filter>
    <filter-name>CSRFGuard</filter-name>
    <filter-class>org.owasp.csrfguard.CsrfGuardFilter</filter-class>
</filter>

<filter-mapping>
    <filter-name>CSRFGuard</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>

<!-- Serves the per-session token-injection JavaScript -->
<servlet>
    <servlet-name>JavaScriptServlet</servlet-name>
    <servlet-class>org.owasp.csrfguard.servlet.JavaScriptServlet</servlet-class>
</servlet>

<servlet-mapping>
    <servlet-name>JavaScriptServlet</servlet-name>
    <url-pattern>/csrf.js</url-pattern>
</servlet-mapping>
```

Include the JavaScriptServlet as the **first** script in the `<head>` of every protected page so it runs before any application script that may construct forms or issue AJAX:

```html
<head>
    <script type="text/javascript" src="/csrf.js"></script>
    <!-- Other application scripts follow -->
    <script type="text/javascript" src="/main.js"></script>
</head>
```

## Configuration

`Owasp.CsrfGuard.Carbon.properties` — the property overrides WSO2 applies on top of the upstream default. Each line below documents the reason for the choice; reviewers should not change these without a documented rationale.

```properties
# State-changing operations are not performed via HTTP GET, so disable
# CSRF validation for GET to avoid unnecessary work.
org.owasp.csrfguard.UnprotectedMethods=GET

# Per-page tokens have a runtime overhead and the upstream library's pre-4.x
# behaviour after blocking a CSRF attempt was problematic for our flows.
# Re-evaluate when adopting CSRFGuard 4.x.
org.owasp.csrfguard.TokenPerPage=false

# Disable token rotation after blocking a CSRF attempt — rotation breaks
# back-navigation immediately after a block, which surfaces as a confusing
# user-facing error.
#org.owasp.csrfguard.action.Rotate=org.owasp.csrfguard.action.Rotate

# Do not redirect to an error page after blocking. We use the Error action
# below to return a 403.
#org.owasp.csrfguard.action.Redirect=org.owasp.csrfguard.action.Redirect

# Return HTTP 403 on a blocked CSRF attempt. Product teams can map 403 to a
# product-specific error page if desired.
org.owasp.csrfguard.action.Error=org.owasp.csrfguard.action.Error
org.owasp.csrfguard.action.Error.Code=403
org.owasp.csrfguard.action.Error.Message=Security violation.

# Non-standard header name carries the X- prefix.
org.owasp.csrfguard.TokenName=X-CSRF-Token

# Don't print the resolved configuration to logs at start-up.
org.owasp.csrfguard.Config.Print=false

# The JavaScript must not inject token values into GET-form actions, since
# that would put the token in a URL — leaks via referer, history, and logs.
org.owasp.csrfguard.JavascriptServlet.injectGetForms=false

# Don't inject into form action URLs (same reason — token in URL).
org.owasp.csrfguard.JavascriptServlet.injectFormAttributes=false

# Don't inject into `src` and `href` (same reason).
org.owasp.csrfguard.JavascriptServlet.injectIntoAttributes=false

# Replace the default "OWASP CSRFGuard Project" identifier on the
# XMLHttpRequest with a non-disclosing string.
org.owasp.csrfguard.JavascriptServlet.xRequestedWith=WSO2 CSRF Protection

# PRNG provider — set per the JVM. SUN on OpenJDK / Oracle JDK, IBMJCE on
# the IBM JDK. Verify the value matches the JVM the product ships with.
org.owasp.csrfguard.PRNG.Provider=SUN

# Allow unauthenticated requests (no valid session) to pass the filter.
# Authentication is enforced separately; CSRFGuard's role is to validate
# the token only when a session exists.
org.owasp.csrfguard.ValidateWhenNoSessionExists=false
```

### Excluding URLs from CSRF validation

A protected web application can exclude specific URLs from CSRF validation via property keys with the `org.owasp.csrfguard.unprotected.` prefix:

```properties
org.owasp.csrfguard.unprotected.Default=%servletContext%/exampleAction
org.owasp.csrfguard.unprotected.Default_1=%servletContext%/exampleAction
org.owasp.csrfguard.unprotected.Example=%servletContext%/exampleAction/*
org.owasp.csrfguard.unprotected.ExampleRegEx=^%servletContext%/.*Public\.do$
```

Two rules:

* **Each exclusion has a reason.** Add a comment immediately above each entry naming the endpoint and the reason it is exempt. Reviewers should reject blanket exclusions and exclusions for state-changing endpoints.
* **The alias suffix after `org.owasp.csrfguard.unprotected.` must not contain additional `.` (period) characters.** The CSRFGuard property loader splits on `.`, so an alias like `org.owasp.csrfguard.unprotected.auth.example` is parsed wrong:

    ```properties
    # WRONG — period in alias suffix
    org.owasp.csrfguard.unprotected.auth.example=%servletContext%/auth

    # RIGHT
    org.owasp.csrfguard.unprotected.authExample=%servletContext%/auth
    ```

## Optional hardening

Settings worth enabling on high-risk applications, weighed against the performance / user-experience cost:

* **`org.owasp.csrfguard.TokenLength=32`** — token length in characters. Default of 32 (≈ 192 bits) is sufficient for any session-bound CSRF token; increase only if a specific threat model justifies it.
* **`org.owasp.csrfguard.PRNG=SHA1PRNG`** — the secure-random algorithm used for token generation. The default is appropriate for most deployments; override only when the JVM doesn't ship `SHA1PRNG`.
* **`org.owasp.csrfguard.action.Invalidate=org.owasp.csrfguard.action.Invalidate`** — invalidates the session entirely when a CSRF attempt is blocked. Forces the user to re-authenticate. Strong defence; tune the UX so this doesn't appear after a benign error such as an expired token mid-session.

## WSO2 product integration checklist

Steps that apply when integrating a WSO2 product with CSRFGuard. Items are listed roughly in the order a new integration would tackle them.

### 1. State-changing operations use POST / PUT / DELETE only

Audit the product's request mapping. State-changing actions reached over HTTP GET must be migrated to POST. Note that some HTML form `submit` defaults use GET — confirm the explicit method attribute on every form.

### 2. Allow unauthenticated requests through the filter

Set `org.owasp.csrfguard.ValidateWhenNoSessionExists=false`. Authentication is enforced separately; CSRFGuard's role is to validate the token only when a session exists. Apply with the distribution-build POM:

```xml
<replace
    file="target/wso2carbon-core-${carbon.kernel.version}/repository/conf/security/Owasp.CsrfGuard.Carbon.properties"
    token="org.owasp.csrfguard.ValidateWhenNoSessionExists = true"
    value="org.owasp.csrfguard.ValidateWhenNoSessionExists = false"/>
```

### 3. Append product-specific CSRF exclusions

Add the product's known-safe URLs to `Owasp.CsrfGuard.Carbon.properties` during the distribution build (each with a reason). See [Excluding URLs from CSRF validation](#excluding-urls-from-csrf-validation).

### 4. Wire CSRFGuard into product web applications

For any Java web application the product ships beyond the Carbon Management Console, follow [Servlet wiring](#servlet-wiring) above. Duplicate `Owasp.CsrfGuard.Carbon.properties` for the application, customise as needed, and point the `Owasp.CsrfGuard.Config` context-param at the new file.

### 5. Include the CSRFGuard JavaScript first on every protected page

The JavaScriptServlet must run before any application JavaScript that creates forms or issues AJAX. Add the `<script src="/csrf.js">` tag as the **first** entry in `<head>` for every page that submits to a CSRF-protected endpoint — including pages whose body is rendered by a sub-component (e.g., the TryIt console) but which submit to the Carbon root context.

### 6. Manually inject tokens into dynamically created forms

If product JavaScript constructs forms via `document.createElement('form')` and submits to a CSRF-protected URL, the CSRFGuard injection does not run on the dynamically created form. Inject the token manually with the JSP taglib:

```jsp
<%@ taglib uri="http://www.owasp.org/index.php/Category:OWASP_CSRFGuard_Project/Owasp.CsrfGuard.tld" prefix="csrf" %>
```

```javascript
const input = document.createElement('input');
input.setAttribute('type', 'hidden');
input.setAttribute('name', '<csrf:tokenname/>');
input.setAttribute('value', '<csrf:tokenvalue/>');
form.appendChild(input);
```

(The original integration documentation set both `name` attributes — a typo. The second call should set `value`. Verify before copying.)

### 7. AJAX requests to relative URLs containing `:`

If an AJAX POST request is sent to a CSRF-protected **relative** path (no `http://` or `https://` prefix) that contains a colon, CSRFGuard fails to add the `X-CSRF-Token` header automatically. Workaround: set the header manually.

```javascript
jQuery.ajax({
    type: 'POST',
    url: '../eventreceiver/get_adapter_properties.jsp?name=example:1.0.0',
    contentType: 'application/json; charset=utf-8',
    beforeSend: function (xhr) {
        xhr.setRequestHeader('<csrf:tokenname/>', '<csrf:tokenvalue/>');
    },
    success: function (response) { /* ... */ }
});
```

### 8. Integration tests submit to CSRF-protected URLs

Integration tests that POST to CSRF-protected endpoints must first fetch a token, then attach it to the submission:

```sh
# Fetch the token for the current session
curl 'https://localhost:9443/carbon/admin/js/csrfPrevention.js' \
    -X POST \
    -H 'FETCH-CSRF-TOKEN: 1' \
    -H 'Cookie: JSESSIONID=<session>' \
    --insecure
# Response includes: X-CSRF-Token: <token>
```

Attach the token as a request header (or as a form parameter where the endpoint accepts that) on the subsequent POST.

### 9. Multipart file uploads

For multipart file uploads (`/fileupload` and similar), inject the CSRF token into the form `action` URL as a query parameter (because the CSRFGuard hidden-input injection runs before form serialisation, and multipart boundaries make it hard to inject a hidden field reliably):

```jsp
<%@ taglib uri="http://www.owasp.org/index.php/Category:OWASP_CSRFGuard_Project/Owasp.CsrfGuard.tld" prefix="csrf" %>
<form method="POST" enctype="multipart/form-data"
      action="../../fileupload/webapp?<csrf:tokenname/>=<csrf:tokenvalue/>">
    <!-- ... -->
</form>
```

Multipart upload endpoints must additionally enforce file size limits and content-type validation at the handler. See [Secure Coding Guide — Unrestricted File Upload]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#unrestricted-file-upload).

### 10. Bearer-token REST APIs do not need CSRFGuard

REST APIs that authenticate exclusively via `Authorization: Bearer <token>` (no session cookie) are not vulnerable to classic CSRF and do not need CSRFGuard tokens. The browser does not attach `Authorization` headers automatically on cross-site requests; only explicit application code can do so. Document this in the API specification rather than excluding the path via `org.owasp.csrfguard.unprotected.*` (which suggests the path is a known exception, not a different security model).

## What this document does not cover

* **REST API authentication and authorisation.** See [Secure Coding Guide — Authentication Failures]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#authentication-failures).
* **CSRF for the Go stack.** Go services typically rely on `SameSite=Strict` cookies plus an explicit anti-CSRF middleware (e.g., a double-submit cookie pattern). See [Secure Coding Guide — Cross-Site Request Forgery (CSRF)]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#cross-site-request-forgery-csrf).
* **Jaggery applications.** Jaggery is deprecated; new WSO2 features should not ship Jaggery surfaces. Existing Jaggery applications follow the same CSRFGuard configuration shape as Java servlets — replace `web.xml` with the equivalent `jaggery.conf` entries — but new integration work should plan migration off Jaggery.

## References

* [OWASP CSRFGuard project](https://owasp.org/www-project-csrfguard/).
* [OWASP CSRFGuard GitHub repository](https://github.com/OWASP/www-project-csrfguard) — current releases and release notes.
* [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) — the general principles this document operationalises.
* [MDN — Cookies: SameSite](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite) — the modern primary defence that CSRFGuard layers on top of.
* [Secure Coding Guide — Cross-Site Request Forgery (CSRF)]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#cross-site-request-forgery-csrf).

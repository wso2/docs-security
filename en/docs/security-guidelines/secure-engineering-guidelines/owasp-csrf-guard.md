---
title: CSRF Defence — Carbon / CSRFGuard Configuration
category: security-guidelines
version: 3.1
---

# CSRF Defence — Carbon / CSRFGuard Configuration

<p class="doc-info">Version: 3.1</p>
___

This document is the operational configuration reference for CSRFGuard on the **Carbon-based Java products**. The CSRF threat model, when CSRF tokens are required vs. when `SameSite` cookies suffice, and bearer-token-API exemptions are covered by the external references below — and at a WSO2 framing in [Secure Coding Guide — Cross-Site Request Forgery (CSRF)]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#cross-site-request-forgery-csrf).

**External references:**

* [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) — general principles.
* [MDN — SameSite cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite) — the primary modern defence.
* [OWASP CSRFGuard project](https://owasp.org/www-project-csrfguard/) · [GitHub](https://github.com/OWASP/www-project-csrfguard) — current releases, release notes, and upstream configuration reference.

## WSO2 approach

For browser-rendered Carbon surfaces that authenticate via session cookies — Carbon Management Console, IS My Account / Console, APIM Publisher / DevPortal — the WSO2 defence is **`SameSite=Strict` on the session cookie *plus* CSRFGuard tokens** (defence in depth). Either alone is acceptable in some configurations; both together matches the existing Carbon deployment shape.

Operational rules:

1. **State-changing actions use POST / PUT / DELETE only.** CSRFGuard does not validate GET (`UnprotectedMethods=GET`); GET must not have side effects.
2. **Session cookies are `HttpOnly; Secure; SameSite=Strict`** — see [HTTP Security Headers]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/security-related-http-headers/).
3. **Tokens injected into POST forms via the JavaScript injection mechanism** (hidden input). Token in URL is forbidden — leaks via referer, browser history, and access logs.
4. **AJAX POSTs carry the token in a header**, set automatically by the CSRFGuard JavaScript. Manual injection with the JSP taglib only in the narrow cases listed below, with explicit security-review approval.
5. **Per-product exclusions are appended to `Owasp.CsrfGuard.Carbon.properties`** during the distribution build; every exclusion has a reason.
6. **Bearer-token-only REST APIs skip CSRFGuard.** Document this in the API specification rather than via the exclusion mechanism.

### CSRFGuard version

WSO2 Carbon historically pinned CSRFGuard 3.x. Current upstream is 4.x. Before adopting 4.x in a Carbon product, verify the configuration keys against the [current CSRFGuard documentation](https://owasp.org/www-project-csrfguard/) and run the existing integration test suite. The configuration shown below is for the version Carbon ships with; consult upstream release notes when upgrading.

## Servlet wiring

`web.xml` additions to enable CSRFGuard on a Carbon web application:

```xml
<listener>
    <listener-class>org.owasp.csrfguard.CsrfGuardServletContextListener</listener-class>
</listener>
<listener>
    <listener-class>org.owasp.csrfguard.CsrfGuardHttpSessionListener</listener-class>
</listener>

<context-param>
    <param-name>Owasp.CsrfGuard.Config</param-name>
    <param-value>repository/conf/security/Owasp.CsrfGuard.Carbon.properties</param-value>
</context-param>

<filter>
    <filter-name>CSRFGuard</filter-name>
    <filter-class>org.owasp.csrfguard.CsrfGuardFilter</filter-class>
</filter>
<filter-mapping>
    <filter-name>CSRFGuard</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>

<servlet>
    <servlet-name>JavaScriptServlet</servlet-name>
    <servlet-class>org.owasp.csrfguard.servlet.JavaScriptServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>JavaScriptServlet</servlet-name>
    <url-pattern>/csrf.js</url-pattern>
</servlet-mapping>
```

Include the JavaScriptServlet as the **first** script in `<head>` of every protected page so it runs before any application script that constructs forms or issues AJAX:

```html
<head>
    <script type="text/javascript" src="/csrf.js"></script>
    <script type="text/javascript" src="/main.js"></script>
</head>
```

## WSO2 configuration overrides

`Owasp.CsrfGuard.Carbon.properties` — the property overrides WSO2 applies on top of the upstream default. Each entry below documents the WSO2-specific reason; reviewers should not change these without a documented rationale.

```properties
# State-changing operations don't go through GET, so skip GET validation.
org.owasp.csrfguard.UnprotectedMethods=GET

# Per-page tokens have a runtime overhead and the upstream pre-4.x behaviour
# after blocking a CSRF attempt was problematic for our flows.
# Re-evaluate when adopting CSRFGuard 4.x.
org.owasp.csrfguard.TokenPerPage=false

# Token rotation after a block breaks back-navigation; the user sees a
# confusing error. Disabled.
#org.owasp.csrfguard.action.Rotate=org.owasp.csrfguard.action.Rotate

# We return 403 via the Error action rather than redirecting.
#org.owasp.csrfguard.action.Redirect=org.owasp.csrfguard.action.Redirect

org.owasp.csrfguard.action.Error=org.owasp.csrfguard.action.Error
org.owasp.csrfguard.action.Error.Code=403
org.owasp.csrfguard.action.Error.Message=Security violation.

# Non-standard header name carries the X- prefix.
org.owasp.csrfguard.TokenName=X-CSRF-Token

# Don't dump resolved config to logs at start-up.
org.owasp.csrfguard.Config.Print=false

# JS must not inject token values into GET-form actions (token in URL leaks
# via referer, history, and logs).
org.owasp.csrfguard.JavascriptServlet.injectGetForms=false
org.owasp.csrfguard.JavascriptServlet.injectFormAttributes=false
org.owasp.csrfguard.JavascriptServlet.injectIntoAttributes=false

# Replace the default "OWASP CSRFGuard Project" XHR identifier.
org.owasp.csrfguard.JavascriptServlet.xRequestedWith=WSO2 CSRF Protection

# PRNG provider — set per the JVM. SUN on OpenJDK / Oracle, IBMJCE on IBM JDK.
# Verify the value matches the JVM the product ships with.
org.owasp.csrfguard.PRNG.Provider=SUN

# Authentication is enforced separately; CSRFGuard only validates the token
# when a session exists.
org.owasp.csrfguard.ValidateWhenNoSessionExists=false
```

### Excluding URLs

Property keys with the `org.owasp.csrfguard.unprotected.` prefix mark URLs that bypass CSRF validation:

```properties
org.owasp.csrfguard.unprotected.Default=%servletContext%/exampleAction
org.owasp.csrfguard.unprotected.Example=%servletContext%/exampleAction/*
org.owasp.csrfguard.unprotected.ExampleRegEx=^%servletContext%/.*Public\.do$
```

WSO2 rules for exclusions:

* **Every exclusion has a comment immediately above it** naming the endpoint and the reason. Reviewers reject blanket exclusions and exclusions for state-changing endpoints.
* **No additional `.` characters in the alias suffix.** CSRFGuard's property loader splits on `.`:

    ```properties
    # WRONG — period in alias suffix
    org.owasp.csrfguard.unprotected.auth.example=%servletContext%/auth
    # RIGHT
    org.owasp.csrfguard.unprotected.authExample=%servletContext%/auth
    ```

### Optional hardening

* `org.owasp.csrfguard.action.Invalidate=...` — invalidates the session entirely on a blocked CSRF attempt; forces re-authentication. Strong defence; tune UX so this doesn't appear after a benign expired-token mid-session.
* `org.owasp.csrfguard.TokenLength=32` and `org.owasp.csrfguard.PRNG=SHA1PRNG` defaults are appropriate for most deployments; only override when there's a specific threat-model or platform reason.

## Product integration checklist

Steps that apply when integrating a Carbon product with CSRFGuard. Roughly in order:

### 1. State-changing operations use POST / PUT / DELETE only

Audit the product's request mapping. State-changing actions reachable over HTTP GET must be migrated. Some HTML form `submit` defaults are GET — confirm the explicit method attribute on every form.

### 2. Allow unauthenticated requests through the filter

Set `ValidateWhenNoSessionExists=false`. Apply via the distribution-build POM:

```xml
<replace
    file="target/wso2carbon-core-${carbon.kernel.version}/repository/conf/security/Owasp.CsrfGuard.Carbon.properties"
    token="org.owasp.csrfguard.ValidateWhenNoSessionExists = true"
    value="org.owasp.csrfguard.ValidateWhenNoSessionExists = false"/>
```

### 3. Append product-specific exclusions

Add the product's known-safe URLs to `Owasp.CsrfGuard.Carbon.properties` during the distribution build (each with a reason).

### 4. Wire CSRFGuard into product web applications beyond Carbon Console

Follow [Servlet wiring](#servlet-wiring). Duplicate `Owasp.CsrfGuard.Carbon.properties` for the application, customise as needed, and point the `Owasp.CsrfGuard.Config` context-param at the new file.

### 5. Include the CSRFGuard JavaScript first on every protected page

Including pages whose body is rendered by a sub-component (e.g., the TryIt console) but which submit to the Carbon root context.

### 6. Manually inject tokens into dynamically created forms

If product JavaScript constructs forms via `document.createElement('form')` and submits to a CSRF-protected URL, the CSRFGuard injection doesn't run on the dynamic form. Inject manually with the JSP taglib:

```jsp
<%@ taglib uri="http://www.owasp.org/index.php/Category:OWASP_CSRFGuard_Project/Owasp.CsrfGuard.tld" prefix="csrf" %>
```

```javascript
const input = document.createElement('input');
input.setAttribute('type', 'hidden');
input.setAttribute('name',  '<csrf:tokenname/>');
input.setAttribute('value', '<csrf:tokenvalue/>');
form.appendChild(input);
```

(The original integration documentation had a typo here — both calls set `name`. The second sets `value`. Verify before copying.)

### 7. AJAX requests to relative URLs containing `:`

CSRFGuard fails to attach the `X-CSRF-Token` header automatically on AJAX POSTs sent to relative paths that contain `:`. Set the header manually:

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

Tests must first fetch a token, then attach it on the submission:

```sh
curl 'https://localhost:9443/carbon/admin/js/csrfPrevention.js' \
    -X POST \
    -H 'FETCH-CSRF-TOKEN: 1' \
    -H 'Cookie: JSESSIONID=<session>' \
    --insecure
# Response: X-CSRF-Token: <token>
```

Attach the token as a request header (or as a form parameter where the endpoint accepts that) on the subsequent POST.

### 9. Multipart file uploads

For multipart uploads (`/fileupload` and similar), inject the token into the form `action` as a query parameter — multipart boundaries make hidden-field injection unreliable:

```jsp
<%@ taglib uri="http://www.owasp.org/index.php/Category:OWASP_CSRFGuard_Project/Owasp.CsrfGuard.tld" prefix="csrf" %>
<form method="POST" enctype="multipart/form-data"
      action="../../fileupload/webapp?<csrf:tokenname/>=<csrf:tokenvalue/>">
    <!-- ... -->
</form>
```

Multipart upload endpoints must additionally enforce file size limits and content-type validation at the handler — see [Secure Coding Guide — Unrestricted File Upload]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#unrestricted-file-upload).

### 10. Bearer-token REST APIs do not need CSRFGuard

Document the bearer-token model in the API specification rather than excluding the path via `org.owasp.csrfguard.unprotected.*` (which suggests the path is a known exception, not a different security model).

## Out of scope

* **REST API authentication / authorisation.** See [Secure Coding Guide — Authentication Failures]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#authentication-failures).
* **Go stack CSRF.** Use `SameSite=Strict` plus a double-submit cookie middleware (e.g., `gorilla/csrf`). See [Secure Coding Guide — Cross-Site Request Forgery (CSRF)]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#cross-site-request-forgery-csrf).
* **Jaggery applications.** Jaggery is deprecated. New WSO2 features should not ship Jaggery surfaces; existing applications follow the same CSRFGuard shape (replace `web.xml` with equivalent `jaggery.conf` entries) but should plan migration.

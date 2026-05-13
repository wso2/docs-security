---
title: React Secure Coding Guide
category: security-guidelines
version: 3.0
---

# React Secure Coding Guide

<p class="doc-info">Version: 3.0</p>
___

## Introduction

This document covers the security considerations that apply specifically to **React** (and SPA-style) frontends shipped by WSO2 products and applications. It is a companion to the [Secure Coding Guide]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/) — the cross-cutting rules (authentication, supply chain, logging, exception handling) live there. This document only adds the things that are React- or browser-specific.

**Scope.** New code: React 18+ with function components and hooks. Examples follow the [react.dev](https://react.dev/) conventions. Class components are mentioned only where legacy code is the pattern under discussion.

**External references every frontend engineer should know.**

* [react.dev — Security topics](https://react.dev/) and the API reference for `dangerouslySetInnerHTML`, refs, and SSR.
* [OWASP Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html), [DOM-based XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html), [HTML5 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html), [Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html).
* [MDN — Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP), [Trusted Types](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API), [Subresource Integrity (SRI)](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity), [Cookies: SameSite](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite).
* [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/rfc9700) — defines what a browser app may and may not do with tokens.
* [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636).

---

## Cross-Site Scripting (XSS)

XSS is the dominant risk in a React frontend. React's default JSX rendering is the primary defence; the named hazards below are the places that bypass it.

### Default JSX escaping is the default — keep it that way

React escapes string children in JSX expressions before inserting them into the DOM. Untrusted user input rendered as a text child is safe.

```jsx
// Safe — text content is escaped by React
function Greeting({ name }) {
  const input = 'hello <img src=x onerror=alert(0)>';
  return <div>{input}</div>; // renders the literal characters, no execution
}
```

The protection applies only when the value is a text child. It does **not** apply when:

* the value is used in `dangerouslySetInnerHTML`,
* the value is interpolated into an attribute that interprets URLs (`href`, `src`, `formaction`, `action`, `xlink:href`),
* the value reaches the DOM via a ref / `findDOMNode` / `innerHTML` assignment,
* the value is rendered through a Markdown / HTML library.

### Attribute injection on URL attributes

`javascript:` URLs in `href` or `src` execute the URL as code. Validate every URL value used as an attribute against a small allow-list of schemes (`http:`, `https:`, and only the schemes you specifically allow such as `mailto:`).

```jsx
// Anti-pattern
<a href="javascript:alert(1)">Click me</a>

// Pattern: parse and validate before use
function safeUrl(input) {
  let url;
  try {
    url = new URL(input, window.location.origin);
  } catch {
    return null; // invalid URL
  }
  const allowed = new Set(['http:', 'https:', 'mailto:']);
  return allowed.has(url.protocol) ? url.toString() : null;
}

function ExternalLink({ href, children }) {
  const safe = safeUrl(href);
  if (!safe) return <span>{children}</span>;
  return (
    <a href={safe} target="_blank" rel="noopener noreferrer">
      {children}
    </a>
  );
}
```

`target="_blank"` always pairs with `rel="noopener noreferrer"` to prevent the opened page from accessing `window.opener`.

For `<iframe>`, `<embed>`, `<object>`, and similar, the same allow-list rule applies — and consider whether the embed needs to exist at all. If it must, sandbox the iframe (`sandbox="allow-scripts"` only if the embedded content is trusted; otherwise omit `allow-scripts`).

### `dangerouslySetInnerHTML` — only with a sanitiser

`dangerouslySetInnerHTML` writes the value into the DOM as HTML. The attribute is named the way it is to discourage casual use. If you must render user-supplied or third-party HTML, sanitise it first with [DOMPurify](https://github.com/cure53/DOMPurify) (or an equivalent allow-list-based sanitiser).

```jsx
import DOMPurify from 'dompurify';

function RenderedHtml({ html }) {
  return (
    <div
      dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}
    />
  );
}
```

Note: the prop key is `__html` (two underscores), and the surrounding object literal is required.

If you find yourself calling `dangerouslySetInnerHTML` for content the application itself produced (e.g., to render formatted text), reach for a structured representation (a Markdown or rich-text component) instead.

### Direct DOM access via refs

`useRef`/`createRef`/`findDOMNode` give you a handle to the underlying DOM node. Writing to `node.innerHTML` from there is equivalent to `dangerouslySetInnerHTML` and has the same rule: sanitise first.

```jsx
import { useRef } from 'react';
import DOMPurify from 'dompurify';

function HtmlPanel({ html }) {
  const ref = useRef(null);
  // Anti-pattern: ref.current.innerHTML = html;
  if (ref.current) {
    ref.current.innerHTML = DOMPurify.sanitize(html);
  }
  return <div ref={ref} />;
}
```

`findDOMNode` is legacy (removed in StrictMode and deprecated for new code); refs are the modern API.

### Markdown rendering

[`react-markdown`](https://www.npmjs.com/package/react-markdown) is the recommended Markdown renderer because it does not interpret raw HTML by default. Keep `skipHtml` enabled (it is the default for new code). If you must allow some HTML, do not turn `skipHtml` off — instead pass a [`rehype-sanitize`](https://github.com/rehypejs/rehype-sanitize) plugin with an explicit schema describing what is allowed.

```jsx
import ReactMarkdown from 'react-markdown';
import rehypeSanitize from 'rehype-sanitize';

function Article({ source }) {
  return (
    <ReactMarkdown rehypePlugins={[rehypeSanitize]}>
      {source}
    </ReactMarkdown>
  );
}
```

The `remarkPlugins` and `rehypePlugins` options do **not** add sanitisation themselves; any plugin that processes HTML must be paired with sanitisation. Custom renderers that bypass sanitisation must be reviewed by the security team.

### Don't use `eval`, `Function`, or runtime template compilation

`eval(userInput)`, `new Function(userInput)`, and runtime-compiled templates (e.g., a templating library passed user-supplied source) execute strings as code. They have no place in a React frontend that handles untrusted input. The Content Security Policy below removes `unsafe-eval` and makes these calls fail at runtime — a useful defence-in-depth.

---

## Content Security Policy (CSP) — the defence-in-depth layer

CSP is set by the server that delivers the HTML; the React app doesn't set it, but the React app must be compatible with it. Target shape for a SPA:

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-{n}';
  style-src 'self' 'nonce-{n}';
  img-src 'self' data: https:;
  connect-src 'self' https://api.example.com;
  font-src 'self';
  object-src 'none';
  frame-ancestors 'none';
  base-uri 'none';
  form-action 'self';
  upgrade-insecure-requests;
```

Constraints for the React build:

* **No `'unsafe-inline'`, no `'unsafe-eval'`.** Configure the bundler so inline `<script>` and inline event handlers are not generated. The fresh nonce `{n}` is injected per response at the HTML-serving layer.
* **No inline style attributes** unless they pass the nonce. Tailwind, CSS Modules, and CSS-in-JS configurations should output to a stylesheet, not inline.
* **No CDN script sources without [Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity).** Every `<script src="https://cdn…">` carries an `integrity="sha384-…"` attribute and `crossorigin="anonymous"`. If the resource cannot be SRI-pinned (its content changes), host it from a domain the team controls.
* **`Trusted Types`** is the next layer up: a browser-enforced policy that requires DOM sinks (`innerHTML`, `script.src`, etc.) to receive a Trusted Type rather than a raw string. Set `Content-Security-Policy: require-trusted-types-for 'script'; trusted-types default;` and define a default policy that runs DOMPurify. See [MDN — Trusted Types API](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API).

The companion HTTP response headers (HSTS, X-Content-Type-Options, COOP/COEP/CORP, Permissions-Policy, etc.) are set by the same server. See [Secure Coding Guide — Security Misconfiguration]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#security-misconfiguration).

---

## Authentication, tokens, and storage

The full authentication discipline is in [Secure Coding Guide — Authentication Failures]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#authentication-failures). The React-specific rules:

* **Never store refresh tokens or long-lived access tokens in `localStorage` or `sessionStorage`.** Anything reachable from `document` is reachable from any script — including a future XSS. Use `HttpOnly`, `Secure`, `SameSite=Strict` cookies, or the **backend-for-frontend (BFF)** pattern where the SPA never holds the long-lived credential.
* **OAuth 2.0 / OIDC for SPAs** uses the **authorisation code flow with PKCE** (RFC 7636). The Implicit grant is deprecated by RFC 9700 and must not be used. `code_challenge_method` is `S256` only — never `plain`.
* **Validate every JWT before trusting it**, even for ID tokens. Check `iss`, `aud`, `exp`, `nbf`, signature against the IdP's JWKS. Do not extract claims from a token without verification just to display the user's name; ask the API for a typed user profile.
* **Logout** calls the server's revocation/end-session endpoint, then clears any client-side state. Don't just delete the cookie locally — the server-side session must end. See `Clear-Site-Data` in the security headers section of the Secure Coding Guide.
* **Service workers are a security boundary.** A service worker can intercept every request the SPA makes. Limit its scope (`scope: '/'` is too broad in most cases), keep its source under the same supply-chain discipline as the SPA, and verify the registration only happens over HTTPS.

---

## Routing and open redirects

Client-side routing libraries (React Router, TanStack Router) commonly accept a `redirect` or `next` URL after authentication. The same exact-match rule that applies to OAuth `redirect_uri` applies here:

```jsx
import { Navigate } from 'react-router-dom';

const ALLOWED_RETURN_PATHS = new Set(['/', '/dashboard', '/settings']);

function PostLogin({ returnTo }) {
  const target = ALLOWED_RETURN_PATHS.has(returnTo) ? returnTo : '/';
  return <Navigate to={target} replace />;
}
```

Never `<Navigate to={searchParams.get('next')} />` without validation — that becomes an open redirect that an attacker can append to phishing emails. Reject absolute URLs, schemeful URLs, and protocol-relative URLs (`//evil.example/`) up front.

---

## `postMessage` and iframe communication

If the SPA hosts or is hosted by another origin (embedded widgets, OAuth popup callbacks), the `postMessage` channel is an attack surface:

* On the **sender** side, always pass an explicit `targetOrigin` — never `'*'`. The receiving origin is part of the security contract.
* On the **receiver** side, check `event.origin` against an allow-list before reading `event.data`. Schema-validate the payload (typed shape, length, allowed values). Treat the payload as untrusted input.

```jsx
useEffect(() => {
  function onMessage(event) {
    if (event.origin !== 'https://idp.example.com') return;
    if (typeof event.data !== 'object' || event.data === null) return;
    if (event.data.type !== 'auth.complete') return;
    // ... handle
  }
  window.addEventListener('message', onMessage);
  return () => window.removeEventListener('message', onMessage);
}, []);
```

---

## Server-side rendering and initial state hydration

For Next.js, Remix, or any setup that renders React on the server and ships HTML + JSON state to the browser, serialising state into a `<script>` tag is risky — `</script>` or other HTML metacharacters inside the JSON can break out of the context.

```jsx
// Anti-pattern — string concatenation of JSON into HTML
<script>
  window.__PRELOADED_STATE__ = ${JSON.stringify(state)}
</script>
```

`JSON.stringify` does **not** escape `<`, `>`, `&`, ` `, ` ` for HTML context — a value containing `</script>` will close the script tag. Use [`serialize-javascript`](https://www.npmjs.com/package/serialize-javascript) with `{ isJSON: true }`, or escape manually:

```jsx
import serialize from 'serialize-javascript';

<script
  // serialize-javascript handles HTML-unsafe characters in JSON-safe mode
  dangerouslySetInnerHTML={{
    __html: `window.__PRELOADED_STATE__ = ${serialize(state, { isJSON: true })};`,
  }}
/>
```

For Next.js, the framework's `getServerSideProps` / `getStaticProps` serialisation handles this for you; avoid hand-rolling state injection scripts.

Never include secrets in the preloaded state. A value visible in the rendered HTML is visible to anyone who can fetch the page.

---

## Supply chain and build hygiene

The full supply-chain discipline is in [Secure Coding Guide — Software Supply Chain Failures]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#software-supply-chain-failures). The React-specific points:

* **Pin every npm/pnpm dependency to an exact version**; no `^` or `~` ranges in `package.json` for production builds. Commit `package-lock.json` or `pnpm-lock.yaml`. CI uses `npm ci` / `pnpm install --frozen-lockfile`.
* **Audit on every PR**: `npm audit --audit-level=high` (or `pnpm audit`) with an explicit allow-list in `.audit-ignore.json` for accepted findings with rationale. Treat unapproved high/critical findings as build failures.
* **Verify packages before adoption.** A new dependency that handles HTML, scripts, or templating must be reviewed against the [`react-markdown`-style](https://www.npmjs.com/package/react-markdown#security) "security" section in its README. If it defaults to unsafe handling, either reject it or wrap it with sanitisation.
* **Beware dependency confusion and typosquatting.** Recent WSO2 [incident clarifications]({{#base_path#}}/security-announcements/incident-clarifications/) (npm package compromise, Shai-Hulud, axios) document what happens when production deployments deviate from the pinned baseline. WSO2's defensive posture relied on exact pinning and committed lock files — keep that.
* **Subresource Integrity** for any third-party JS/CSS loaded by URL from a CDN (see the CSP section above).

### Build / deployment

* **Disable source maps in production builds** (`GENERATE_SOURCEMAP=false` for Create React App; `productionBrowserSourceMaps: false` for Next.js) or restrict access to source-map files behind authentication. Source maps leak the full source tree to anyone who fetches the bundle.
* **Environment variables exposed to the browser** (anything prefixed `REACT_APP_`, `VITE_`, `NEXT_PUBLIC_`) are public. Never put secrets, tokens, internal URLs, or any value that should not be world-readable behind these prefixes. The build inlines them into the bundle.
* **Strip development-only code** from production bundles. `if (process.env.NODE_ENV !== 'production') { console.log(...) }` is fine; relying on a runtime "debug mode" flag in production is not — the flag becomes a control surface.
* **Disable React DevTools and Redux DevTools hooks in production** where possible. The default React production build does this; double-check for any custom wiring.

---

## Logging, errors, and telemetry from the browser

* **Don't log tokens, PII, or full request bodies to the browser console.** Anyone using the browser's DevTools sees them. The full never-log list is in [Secure Coding Guide — Logging and Alerting Failures]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#logging-and-alerting-failures).
* **Error boundaries** catch render-time exceptions and prevent them from leaking stack traces and component-state details to the user. Display a generic error message; send the detail to the server-side logger via a sanitised error-report endpoint.
* **Telemetry (analytics, RUM, error reporters) shipped to third-party domains** carries whatever the SDK collects by default — often URL paths, query parameters, and form field values. Configure the SDK to redact paths that may contain identifiers (tokens in URLs, session IDs in fragments) and to drop the `Referer` for sensitive pages.

---

## Cookies on the browser side

Cookies set by the server are out of the SPA's control, but the SPA must be compatible with the right defaults:

* `HttpOnly` — the SPA cannot read the cookie, which is exactly what we want for auth cookies.
* `Secure` — only sent over HTTPS.
* `SameSite=Strict` for auth/session cookies; `Lax` is acceptable for general site cookies; `None` requires `Secure` and is only used cross-site where genuinely needed.
* `Path` set to the narrowest scope that works; `Domain` is set only when cross-subdomain sharing is required.

If the SPA *does* set its own cookies via JavaScript (`document.cookie`), the same flags apply except `HttpOnly` — `document.cookie` cannot set it. That's a reason to prefer server-set cookies wherever possible.

---

## Quick checklist for a new React surface

When adding a new React-rendered page or component to a WSO2 product, confirm:

- [ ] No `dangerouslySetInnerHTML` without DOMPurify (or equivalent allow-list sanitiser).
- [ ] No `eval`, `new Function`, or runtime template compilation on user input.
- [ ] All `href`/`src` from variable input passes through a scheme allow-list.
- [ ] All `<a target="_blank">` carries `rel="noopener noreferrer"`.
- [ ] Markdown rendering uses `react-markdown` with `skipHtml` (default) or `rehype-sanitize`.
- [ ] No tokens or PII in `localStorage` / `sessionStorage`; OAuth uses authorisation code + PKCE; logout calls the revocation endpoint.
- [ ] Routing's "redirect after action" parameter is validated against an allow-list (no open redirect).
- [ ] `postMessage` handlers check `event.origin` against an allow-list and validate `event.data` shape.
- [ ] SSR initial-state injection uses `serialize-javascript` (or framework-provided escaping), not raw `JSON.stringify` into a `<script>` tag.
- [ ] CSP is configured by the serving layer; the React build is compatible with `nonce`-based `script-src` and `style-src`; no inline event handlers; SRI on every CDN-loaded resource.
- [ ] Source maps are disabled (or behind auth) for the production build.
- [ ] No secrets in `REACT_APP_*` / `VITE_*` / `NEXT_PUBLIC_*` environment variables — they ship to the browser.
- [ ] Dependencies pinned exactly; lock file committed; `npm audit` clean on PR.
- [ ] Error boundary returns a generic message; the full exception is reported server-side, not displayed to the user.

---
title: React Secure Coding Guide
category: security-guidelines
version: 3.1
---

# React Secure Coding Guide

<p class="doc-info">Version: 3.1</p>
___

When you build a React 18+ frontend for a WSO2 product, this is the engineering guide for what your code should and shouldn't do. The general "what XSS is", "what `dangerouslySetInnerHTML` does", or "how CSP works" is covered by the community references below, linked rather than restated. Cross-cutting rules (authentication, supply chain, logging, exception handling, cookie defaults) are in the [Secure Coding Guide]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/) and not restated here.

## External references

* **React.** [react.dev reference for `dangerouslySetInnerHTML`, refs, and SSR](https://react.dev/).
* **XSS and DOM.** [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) · [OWASP DOM-based XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html) · [OWASP HTML5 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html).
* **Browser security.** [MDN CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) · [MDN Trusted Types](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API) · [MDN SRI](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity) · [MDN SameSite cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite).
* **OAuth for browsers.** [RFC 9700, OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/rfc9700) · [RFC 7636, PKCE](https://datatracker.ietf.org/doc/html/rfc7636).
* **Library guidance.** [`react-markdown` security](https://github.com/remarkjs/react-markdown#security) · [DOMPurify](https://github.com/cure53/DOMPurify) · [`rehype-sanitize`](https://github.com/rehypejs/rehype-sanitize).

## React-specific risks

These are the points where React's defaults either protect you or quietly stop protecting you. Know which is which before you write the component.

### JSX auto-escaping, and where it does not protect

React escapes any value you interpolate as a child with `{value}`, so `<div>{userInput}</div>` is safe against HTML and script injection. That guarantee is narrow. It does **not** apply when the value reaches the DOM through any other path:

* **Attributes built from variables** still execute as their attribute, even though the string itself is escaped. `<iframe src={userInput}>` or `<a href={userInput}>` will happily run a `javascript:` or `data:` URL. Validate the value, do not rely on escaping. See [URL, `href`, and `src` handling](#url-href-and-src-handling) below.
* **Raw HTML** through `dangerouslySetInnerHTML` bypasses escaping entirely, by design.
* **Direct DOM writes** through refs or `findDOMNode` bypass React's render path, so escaping never runs.

Treat `{value}` as safe only for text content. For everything else, the protection is yours to add. Read the [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) for the context rules.

### `dangerouslySetInnerHTML`

Setting `dangerouslySetInnerHTML` renders a raw HTML string without escaping. Use it only when you genuinely need to render HTML you do not control, and only after sanitizing with [DOMPurify](https://github.com/cure53/DOMPurify). Never pass raw user input, API responses, or any externally-sourced HTML straight to it.

!!! danger "Anti-pattern"
    ```jsx
    // Raw input rendered as HTML: the onerror handler fires.
    function Comment({ body }) {
      return <div dangerouslySetInnerHTML={{ __html: body }} />;
    }
    ```

!!! tip hint important "Do this instead"
    ```jsx
    import DOMPurify from 'dompurify';

    function Comment({ body }) {
      const clean = DOMPurify.sanitize(body);
      return <div dangerouslySetInnerHTML={{ __html: clean }} />;
    }
    ```

Sanitize on render, not on store, so the value is clean against the policy in effect at display time. Keep one sanitizer across the codebase (see [Sanitizer standardization](#sanitizer-standardization)).

### URL, `href`, and `src` handling

A URL is an injection sink. `javascript:alert(1)` in an `href`, or `data:text/html,...` in an `iframe src`, runs as script. Escaping does not stop this because the string is valid; the *scheme* is the problem. Validate every variable URL with an allow-list of schemes before it reaches an attribute.

!!! danger "Anti-pattern"
    ```jsx
    // Classic XSS through an anchor href.
    <a href={userSuppliedUrl}>Open</a>
    ```

!!! tip hint important "Do this instead"
    ```jsx
    const ALLOWED_SCHEMES = new Set(['http:', 'https:', 'mailto:']);

    function safeUrl(input) {
      try {
        const url = new URL(input, window.location.origin);
        return ALLOWED_SCHEMES.has(url.protocol) ? url.href : null;
      } catch {
        return null; // not a parseable URL
      }
    }
    ```

Reject `javascript:`, `data:`, `vbscript:`, and any scheme not on the list. Allow-list, never deny-list: new dangerous schemes appear over time, so default to rejecting anything unrecognized. Pair `target="_blank"` with `rel="noopener noreferrer"`.

### Direct DOM access, refs, and `findDOMNode`

Reaching past React into the DOM, through a ref's `.innerHTML`, `document.getElementById(...).innerHTML`, or the deprecated `ReactDOM.findDOMNode(...)`, skips the render path and therefore skips escaping. Anything written this way is unescaped HTML.

!!! danger "Anti-pattern"
    ```jsx
    function render(input) {
      // innerHTML on a raw DOM node: the markup executes.
      nodeRef.current.innerHTML = input;
    }
    ```

Prefer rendering through state and JSX so React handles escaping. If you must write to the DOM directly, sanitize with DOMPurify first, exactly as for `dangerouslySetInnerHTML`. `findDOMNode` is deprecated; use a `ref` instead, and the sanitize-then-write rule still applies.

### Rendering Markdown

Markdown can carry embedded HTML and `javascript:` links, so it is an XSS vector unless the output is sanitized. Render it with [`react-markdown`](https://github.com/remarkjs/react-markdown#security), which does not render raw HTML by default. Keep that default: do not enable raw HTML pass-through unless you also sanitize.

!!! tip hint important "Do this instead"
    ```jsx
    import Markdown from 'react-markdown';
    import rehypeSanitize from 'rehype-sanitize';

    // Safe even if raw HTML is enabled, because rehype-sanitize filters the output.
    <Markdown rehypePlugins={[rehypeSanitize]}>{markdownText}</Markdown>
    ```

`remark` and `rehype` plugins do not sanitize on their own, and some emit raw HTML. If you add plugins, also run [`rehype-sanitize`](https://github.com/rehypejs/rehype-sanitize) (or DOMPurify) over the result, with an explicit allow-list schema of permitted tags and attributes.

## Rules for React in WSO2 products

These are the points that are not obvious from the external references, that recur across WSO2 product UIs, or that have a WSO2-specific reason.

### Sanitizer standardization

When a WSO2 React surface needs to render rich text or third-party HTML, use **DOMPurify** as the sanitizer (via `dangerouslySetInnerHTML`, ref-based `innerHTML`, or `rehype-sanitize` for Markdown). Consistency matters more than the library: the security team reviews against this baseline. If you need a different sanitizer, raise it with the security team before adoption.

### URL attribute validation

WSO2 portals routinely render externally-sourced URLs (publisher metadata, IdP endpoints, callback URLs displayed back to the user). For every variable `href` / `src`, parse with `new URL(input, window.location.origin)` and restrict the resulting `url.protocol` to `http:` / `https:` (plus `mailto:` only where deliberately allowed). Reject `javascript:`, `data:`, `vbscript:`, and unknown schemes. Pair `target="_blank"` with `rel="noopener noreferrer"`.

### Token storage with BFF or HttpOnly cookies

WSO2 admin UIs (Carbon Console, APIM Publisher/DevPortal, IS Console) are session-cookie-based; new React SPAs must follow the same pattern. **Never store refresh tokens or long-lived access tokens in `localStorage` / `sessionStorage`.** Two acceptable shapes:

* **Cookie session** with `HttpOnly; Secure; SameSite=Strict`, set by the WSO2 IdP / API Gateway.
* **Backend-for-frontend (BFF)** where a small server-side component holds the long-lived credential and the SPA only talks to it via the same-origin cookie.

OAuth for the SPA itself uses **authorization code with PKCE** (`code_challenge_method=S256`); the Implicit grant is deprecated by RFC 9700 and must not be used.

### Open-redirect parameter validation

WSO2 login flows accept a post-authentication redirect parameter (`returnTo`, `next`, `redirect_uri`). The same exact-match rule that WSO2 enforces for OAuth `redirect_uri` applies here:

```jsx
const ALLOWED_RETURN_PATHS = new Set(['/', '/dashboard', '/settings']);

function PostLogin({ returnTo }) {
  const target = ALLOWED_RETURN_PATHS.has(returnTo) ? returnTo : '/';
  return <Navigate to={target} replace />;
}
```

Reject absolute URLs, schemeful URLs, and protocol-relative URLs (`//evil.example/`) up front. The same logic belongs in any WSO2 IdP-issued template that uses a `commonauth`-style return path.

### CSP target for WSO2-served admin UIs

CSP is set by the serving component, not by React, but the React build must be compatible with the WSO2 target shape:

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

Build-side constraints to make this work: bundler configured so no inline `<script>` or inline event handlers are generated; Tailwind / CSS Modules / CSS-in-JS output to a stylesheet, not inline styles; every CDN-loaded `<script>` and `<link>` carries `integrity="sha384-…"` and `crossorigin="anonymous"`. The next step up is `Trusted Types` (`require-trusted-types-for 'script'`) with a default policy that runs DOMPurify; adopt it where the deployment surface supports it. The companion response headers are covered in [HTTP Security Headers]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/security-related-http-headers/).

### SSR initial-state injection

For Next.js / Remix / any SSR setup, raw `JSON.stringify(state)` interpolated into a `<script>` tag is unsafe, because a `</script>` inside a string value closes the tag and lets the rest of the value run as markup. Use [`serialize-javascript`](https://www.npmjs.com/package/serialize-javascript) with `{ isJSON: true }`, which escapes `<`, `>`, and `/` in the embedded JSON, or the framework's own props serialization (`getServerSideProps` / `getStaticProps`) which handles it. **Never include secrets in the preloaded state**: anything visible in rendered HTML is visible to the recipient.

!!! danger "Anti-pattern"
    ```jsx
    // </script> in a string value breaks out of the script context.
    <script>
      window.__PRELOADED_STATE__ = ${JSON.stringify(state)}
    </script>
    ```

!!! tip hint important "Do this instead"
    ```jsx
    import serialize from 'serialize-javascript';

    <script>
      window.__PRELOADED_STATE__ = ${serialize(state, { isJSON: true })}
    </script>
    ```

### `postMessage` for embedded WSO2 surfaces

Where a WSO2 React UI hosts or is hosted by another origin (OAuth popup callbacks, embedded widgets in the Developer Portal), the receiver checks `event.origin` against an allow-list of WSO2 / customer origins before reading `event.data`, and schema-validates the payload. Senders pass an explicit `targetOrigin`, never `'*'`.

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

### Dependency hygiene

Pin dependencies exactly, commit the lock file, and keep `npm audit` / `pnpm audit` clean on every PR. Onboard new npm packages through WSO2's dependency process. Full guidance, including how WSO2 incidents map to pinning discipline, is in [Dependency Vulnerability Analysis]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/external-dependency-analysis-analysis-using-owasp-dependency-check/) and [Secure Coding Guide, Software Supply Chain Failures]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#software-supply-chain-failures).

### Build hygiene

* **Production source maps disabled** (`GENERATE_SOURCEMAP=false` for CRA, `productionBrowserSourceMaps: false` for Next.js), or served behind authentication on the deployment surface.
* **Browser-exposed env vars are public.** Never put a token, internal URL, or any value that should not be world-readable behind `REACT_APP_*` / `VITE_*` / `NEXT_PUBLIC_*`: the bundler inlines them into the shipped bundle.
* **Error boundaries** return a generic message; the full exception is reported through your product's sanitized error-report endpoint, never displayed to the user.

### Past incidents

WSO2 [incident clarifications]({{#base_path#}}/security-announcements/incident-clarifications/) (npm package compromise, Shai-Hulud, axios) all document the same pattern: deployments that deviated from the pinned baseline were exposed, while deployments that kept exact pinning and committed lock files were not. Keep that discipline; see [Secure Coding Guide, Software Supply Chain Failures]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#software-supply-chain-failures).

## Review checklist

When adding a new React-rendered page or component to a WSO2 product:

- [ ] No `dangerouslySetInnerHTML` without DOMPurify (or equivalent reviewed sanitizer).
- [ ] No `eval`, `new Function`, or runtime template compilation on user input.
- [ ] All `href`/`src` from variable input passes through a scheme allow-list; `target="_blank"` paired with `rel="noopener noreferrer"`.
- [ ] No direct DOM writes (ref `innerHTML`, `findDOMNode`) of unsanitized input.
- [ ] Markdown rendering uses `react-markdown` with `skipHtml` (default) or `rehype-sanitize`.
- [ ] No tokens or PII in `localStorage` / `sessionStorage`; OAuth uses authorization code + PKCE (`S256`); logout calls the revocation / end-session endpoint.
- [ ] Routing's redirect parameter is validated against an allow-list.
- [ ] `postMessage` handlers check `event.origin` against an allow-list and validate `event.data` shape.
- [ ] SSR initial-state injection uses `serialize-javascript` or framework-provided escaping.
- [ ] Build emits no inline `<script>` / event handlers; CDN-loaded resources carry SRI; CSP-compatible.
- [ ] Production source maps disabled or auth-gated.
- [ ] No secrets in `REACT_APP_*` / `VITE_*` / `NEXT_PUBLIC_*`.
- [ ] Dependencies pinned exactly; lock file committed; `npm audit` / `pnpm audit` clean on PR (see [Dependency Vulnerability Analysis]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/external-dependency-analysis-analysis-using-owasp-dependency-check/)).
- [ ] Error boundary returns a generic message; the full exception is reported server-side.

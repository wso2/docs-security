---
title: Dynamic Analysis with OWASP ZAP
category: security-guidelines
version: 3.0
---

# Dynamic Analysis with OWASP ZAP

<p class="doc-info">Version: 3.0</p>
___

[OWASP ZAP](https://www.zaproxy.org/) (Zed Attack Proxy) runs against a *deployed* WSO2 product and probes its HTTP surface for the vulnerability classes a scanner can detect from outside the application. ZAP complements the static analysis tools in [Static Code Analysis]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/static-code-analysis-using-findsecuritybugs/) and the dependency scanners in [Dependency Vulnerability Analysis]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/external-dependency-analysis-analysis-using-owasp-dependency-check/); the three together form the SAST + DAST + SCA baseline every WSO2 product runs.

This document covers two operating modes:

1. **Automated CI scans** (the default — runs on every release branch and nightly on `main`).
2. **Interactive scans for new features** (for an engineer working on a feature whose security posture is not yet covered by the automated baseline).

The interactive UI workflow is documented because it is still useful for triaging findings; the daily security signal should come from CI, not from a human clicking through the desktop UI.

## Automated CI scans

### Docker images

ZAP ships official Docker images on GitHub Container Registry:

* `ghcr.io/zaproxy/zaproxy:stable` — the full ZAP distribution, with all add-ons.
* `ghcr.io/zaproxy/zaproxy:weekly` — built from the development branch; useful when a fix or new add-on hasn't reached `stable` yet.

The packaged scans live in the same image:

* `zap-baseline.py` — fast, passive scan only. Reports issues observable from the response headers and body without actively probing. Suitable for every PR.
* `zap-full-scan.py` — passive plus active scan (probes the application). Slower; suitable for nightly or release-gate runs.
* `zap-api-scan.py` — scans a REST API described by an OpenAPI / Swagger or SOAP description. Suitable for any WSO2 product that publishes an OpenAPI spec.

### GitHub Action

The official `zaproxy/action-baseline` and `zaproxy/action-full-scan` actions wrap the Docker images for GitHub Actions:

```yaml
name: ZAP Baseline

on:
  pull_request:
  schedule:
    - cron: '30 3 * * *'  # nightly

jobs:
  zap-baseline:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Boot the product under test
        run: docker compose up -d --wait

      - name: ZAP baseline scan
        uses: zaproxy/action-baseline@v0.13.0
        with:
          target: 'https://localhost:9443/'
          rules_file_name: '.zap/baseline-rules.tsv'
          cmd_options: '-a -j -T 5'
          fail_action: true
          allow_issue_writing: false
```

`rules_file_name` is the project's per-rule allow-list (false positives, accepted findings). Each row carries a rule id, the action (`IGNORE`/`WARN`/`FAIL`), and a rationale comment.

`fail_action: true` makes the job fail on any unresolved finding above the configured threshold. The action also uploads the HTML report as a workflow artefact.

For the active scan in a nightly run, swap to `zaproxy/action-full-scan@v0.13.0`. Active scans are longer (typically 30–90 minutes against a Carbon product) and are not appropriate for every PR.

### Scanning REST APIs

WSO2 products publish OpenAPI specs for their REST surfaces. Point `zap-api-scan.py` at the spec:

```sh
docker run --rm -t \
    --network host \
    -v "$PWD:/zap/wrk/:rw" \
    ghcr.io/zaproxy/zaproxy:stable \
    zap-api-scan.py \
        -t https://localhost:9443/api/am/publisher/v4/swagger.yaml \
        -f openapi \
        -r api-scan-report.html \
        -J api-scan-report.json
```

The API scan reads the spec, generates request shapes from it, and probes the endpoints. It does **not** automatically obtain an OAuth token — see [Authenticated scans](#authenticated-scans).

### Authenticated scans

WSO2 products expose almost all interesting state behind authentication. An unauthenticated scan finds the login page and not much else. There are three patterns for giving ZAP the credentials it needs.

**Session-cookie-based UIs (Management Console, Publisher / DevPortal / Console).** Configure a ZAP Authentication script that logs in by submitting the login form and captures the session cookie. The packaged `Form-Based Authentication` method handles this for most Carbon flows. Configure it in the ZAP context (see [Interactive scans — Authentication setup](#authentication-setup)); the same context is reusable in CI by exporting it as a `.context` file and importing in the Docker run with `-z "-config ..."`.

**Bearer-token REST APIs.** Obtain an OAuth token before the scan, then run with the `Authorization` header injected:

```sh
TOKEN=$(curl -sk -u "$CLIENT_ID:$CLIENT_SECRET" \
    -d "grant_type=client_credentials" \
    https://localhost:9443/oauth2/token | jq -r .access_token)

docker run --rm -t --network host -v "$PWD:/zap/wrk/:rw" \
    ghcr.io/zaproxy/zaproxy:stable \
    zap-api-scan.py \
        -t https://localhost:9443/api/am/publisher/v4/swagger.yaml \
        -f openapi \
        -z "-config replacer.full_list(0).description=Authorization \
            -config replacer.full_list(0).enabled=true \
            -config replacer.full_list(0).matchtype=REQ_HEADER \
            -config replacer.full_list(0).matchstr=Authorization \
            -config replacer.full_list(0).regex=false \
            -config replacer.full_list(0).replacement=Bearer\ $TOKEN"
```

Set the token's validity period long enough to cover the scan duration. The OAuth `AccessTokenDefaultValidityPeriod` in `repository/conf/deployment.toml` may need to be increased for the test instance.

**OIDC flows (Single Sign-On).** Use the [Authentication scripts](https://www.zaproxy.org/docs/desktop/start/features/authmethods/) Add-on which supports OAuth 2.0 authorization-code flow. Configure once interactively, export the context for CI reuse.

### Scaling the JVM

The default heap is `Xmx512m`. Active scans against Carbon products typically need 4 GB or more. Set `JAVA_OPTS` on the container:

```sh
docker run --rm -t -e JAVA_OPTS='-Xmx4g' ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py ...
```

Run CI scans on a dedicated runner where possible — active scans are long, and pre-emption mid-scan loses the partial work.

### WSO2 scan policy

Tune the scan policy before the first run. The WSO2 default scan policy enables the rules that matter against Carbon products and disables rules that produce known false positives (such as test rules tuned for PHP applications, irrelevant CMS plugins, etc.).

Maintain the policy file in the product repository under `.zap/policies/`. The file is plain XML and version-controllable. Adjust on each ZAP version bump (rules sometimes get added or split between releases).

### Failing the build

The exit code conventions for the packaged scans:

* `0` — no findings above the configured threshold.
* `1` — findings exceeding the threshold.
* `2` — at least one finding at `WARN` level (configurable to be treated as failure).

CI gates on exit code. The HTML report and JSON report are uploaded as workflow artefacts on every run, regardless of pass / fail.

### Triage and false positives

Two layers of suppression:

1. **Rule-level suppression** in the `.zap/baseline-rules.tsv` (or `full-scan-rules.tsv`) file — applies the same action (`IGNORE`/`WARN`) to every alert of that rule across the scan.

    ```tsv
    # Rule ID    Action    Comment
    10202       IGNORE    Anti-CSRF tokens managed by CSRFGuard; rule does not detect the X-CSRF-Token header.
    10038       WARN      CSP nonces are present but rule expects hashes; manual review confirmed compliant.
    ```

2. **Alert-instance suppression** via the ZAP alert-filter feature, configured in the context. Applies to a specific URL + rule combination, surfaced in the report as an explicit "accepted" mark rather than silently dropped.

Each suppression carries a rationale. Review the suppression list quarterly — rules and the product both change.

## Interactive scans

Useful when developing a new feature whose paths the automated baseline does not yet exercise, or when triaging a finding from a CI run.

### Install

[Download ZAP](https://www.zaproxy.org/download/) for the host platform. ZAP ships its own bundled JVM since 2.14; the older "install a JRE separately" guidance no longer applies.

### Browser proxy configuration

ZAP runs as an HTTP proxy. Configure the browser to send traffic through it, then drive the application and ZAP records everything it sees.

1. In ZAP: **Tools → Options → Network → Local Servers/Proxies** (newer UI) or **Tools → Options → Local Proxies** (older). Pick a port (the default `8080` is fine; some environments use `7777` to avoid conflicting with development servers).
2. In the browser: set the manual HTTP / HTTPS proxy to the ZAP host and port. Remove any `localhost` exception so traffic to the local server is captured. Firefox: **Settings → Network Settings → Manual proxy configuration**. Chrome: use the system proxy or [SwitchyOmega](https://chrome.google.com/webstore/detail/proxy-switchyomega-3-zero/pfnededegaaopdmhkdmcofjmoldfiped) — Chrome's built-in proxy switching is awkward.
3. Trust the ZAP root certificate so HTTPS to the product works without warnings. In ZAP: **Tools → Options → Network → Dynamic SSL Certificate → Save**; import the saved file into the browser's certificate store.
4. Set ZAP's mode to **Protected**. In Protected mode, only sites added to the active **Context** are attacked — important when developer browsers also visit external sites.

### Context setup

A **Context** groups URLs that belong to the same application. Right-click the site in the **Sites** tree → **Include in Context → New Context**. Name it (e.g., `WSO2 Publisher`). Adjust the regex to match the URL prefix.

For a WSO2 product with multiple browser surfaces (Carbon Management Console, APIM Publisher, DevPortal, Console), define one context per surface; configurations are surface-specific.

### Authentication setup

Configure **Session Properties → Authentication** for the context. For Carbon Management Console:

* **Authentication method**: Form-Based Authentication.
* **Login form target URL**: the login servlet URL (varies per product).
* **POST data**: include the ZAP authentication placeholders for the username and password fields. ZAP uses `{` followed by `%username%` and `%password%}` style placeholders that the configuration UI inserts; consult ZAP's authentication documentation for the exact form.
* **Logged In / Logged Out indicators**: regex patterns that distinguish authenticated from unauthenticated responses. Often `\Qhome.jsp\E` for "logged in" and the login form's title for "logged out".
* **Users**: add the test user(s); credentials are stored in the ZAP session file (don't commit it).

For OIDC flows, install the **Authentication Helper** add-on (formerly **Authentication scripts**) and select OAuth 2.0 Authorization Code with PKCE.

### Exclude the logout endpoint

The Spider follows links indiscriminately and will eventually hit the logout endpoint, after which everything else fails because the session is gone. Exclude the logout URL:

* Trigger a logout in the browser so ZAP records the URL.
* Find the URL in the Sites tree, right-click → **Exclude from → Spider** and **Exclude from → Active Scan**.

### Run the AJAX Spider and Spider

ZAP has two crawlers:

* **AJAX Spider** — runs a headless browser, executes JavaScript, follows links generated by client-side code. Required for any SPA-style interface (Publisher, DevPortal). Configure the browser driver in **Tools → Options → Selenium**.
* **Traditional Spider** — fetches HTML and follows static links. Faster; useful as a second pass to catch URLs the AJAX Spider missed.

Set max crawl depth and max duration to `0` on the AJAX Spider to disable the limits (rely on Protected mode to keep it in scope). Set Traditional Spider depth to 5.

For surfaces with substantial client-side state (multi-step wizards, conditional rendering), supplement the spider with Selenium scripts that drive the UI through the flows. Run the scripts with ZAP as the proxy; ZAP records every request.

### Run the Active Scan

After the spider has populated the URL tree, **Attack → Active Scan** on the context (or right-click the site). Select the imported WSO2 scan policy. The active scan probes each URL it discovered with the rules in the policy.

Active scans against a full Carbon product run for hours. Plan accordingly — a dedicated VM or container is preferable to a laptop. Save the session (`File → Save Session`) periodically.

### Manage alerts

After the scan completes, work through the **Alerts** panel. For each:

* If it's a real finding — file the issue against the product team. Severity and recommended remediation are in the alert details.
* If it's a false positive — open the alert, set **Confidence: False Positive**. Better still, add an alert filter in **Session Properties → Alert Filters** so the same alert is auto-suppressed on the next run.

Export the report via **Report → Generate Report**. The HTML report is the customer-facing artefact; the JSON / SARIF formats feed pipelines.

## Scanning Go services

The Go-based WSO2 products serve HTTP surfaces in the same shape as the Carbon products — ZAP doesn't care what language is on the server side. Use the same baseline / full-scan / API-scan flows; point ZAP at the Go service URL or its OpenAPI spec.

Authentication for Go services typically uses bearer tokens (see [Bearer-token REST APIs](#authenticated-scans) above).

## References

* [OWASP ZAP](https://www.zaproxy.org/) — project home.
* [ZAP Docker documentation](https://www.zaproxy.org/docs/docker/) — packaged scans, configuration options.
* [ZAP GitHub Actions](https://github.com/zaproxy/action-baseline) — `zaproxy/action-baseline`, `zaproxy/action-full-scan`, `zaproxy/action-api-scan`.
* [ZAP rule reference](https://www.zaproxy.org/docs/alerts/) — every alert ID and what it means; useful when authoring the rules file.
* [Authentication in ZAP](https://www.zaproxy.org/docs/desktop/start/features/authmethods/) — form, JSON, script, OAuth 2.0.
* [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) — the testing approach ZAP automates.

---
title: Dynamic Analysis with OWASP ZAP
category: security-guidelines
version: 3.1
---

# Dynamic Analysis with OWASP ZAP

<p class="doc-info">Version: 3.1</p>
___

[OWASP ZAP](https://www.zaproxy.org/) runs against a deployed WSO2 product and probes its HTTP surface. ZAP install, proxy setup, UI navigation, and the per-rule reference are in the ZAP documentation — this page covers WSO2-specific scan policy, authentication patterns, and CI integration only.

ZAP forms the DAST leg of the WSO2 SAST + DAST + SCA baseline together with [Static Code Analysis]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/static-code-analysis-using-findsecuritybugs/) and [Dependency Vulnerability Analysis]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/external-dependency-analysis-analysis-using-owasp-dependency-check/).

**External references:**

* [ZAP project home](https://www.zaproxy.org/) · [Docker images](https://www.zaproxy.org/docs/docker/) · [GitHub Actions](https://github.com/zaproxy/action-baseline) · [Authentication methods](https://www.zaproxy.org/docs/desktop/start/features/authmethods/) · [Alert / rule reference](https://www.zaproxy.org/docs/alerts/).
* [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) — the testing approach ZAP automates.

## When ZAP runs in WSO2 CI

* **Baseline scan (passive only)** — every PR. Runs in minutes; reports issues observable from response headers and bodies without actively probing. Image: `ghcr.io/zaproxy/zaproxy:stable`, action: `zaproxy/action-baseline`.
* **Full scan (passive + active)** — nightly on `main` and on release branches. Active probing; typically 30–90 minutes against a Carbon product. Action: `zaproxy/action-full-scan`.
* **API scan** — against products that publish an OpenAPI spec. `zap-api-scan.py` reads the spec, generates request shapes, and probes the endpoints.

The daily security signal comes from CI, not from a human clicking through the desktop UI. The interactive UI is for triaging findings and exploring new surfaces.

## WSO2 scan policy

WSO2 maintains a tuned ZAP policy in each product repository under `.zap/policies/` — plain XML, version-controlled. The policy enables rules that matter against Carbon products and disables rules that produce known false positives (PHP-only tests, CMS plugins, etc.). Adjust on each ZAP version bump (rules sometimes get added or split between releases).

The matching rules file in `.zap/baseline-rules.tsv` (or `full-scan-rules.tsv`) carries one row per allow-listed rule with a rationale:

```tsv
# Rule ID    Action    Comment
10202       IGNORE    Anti-CSRF tokens managed by CSRFGuard; rule does not detect the X-CSRF-Token header.
10038       WARN      CSP nonces are present but rule expects hashes; manual review confirmed compliant.
```

Two layers of suppression — rule-level (above) and alert-instance via the ZAP alert-filter feature configured in the context. Each suppression carries a rationale; review the suppression list quarterly.

## Sample WSO2 CI step

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

The action uploads the HTML and JSON reports as workflow artefacts on every run. CI gates on the action's exit code; `fail_action: true` fails the job on any unresolved finding above the configured threshold.

For nightly active scans, swap to `zaproxy/action-full-scan@v0.13.0`. Active scans need more heap — set `JAVA_OPTS=-Xmx4g` on the ZAP container — and a dedicated runner; pre-emption mid-scan loses the partial work.

## Authentication patterns for WSO2 surfaces

WSO2 products expose almost all interesting state behind authentication. An unauthenticated scan finds the login page and not much else. Three patterns by surface type:

### Session-cookie UIs — Carbon Console, APIM Publisher / DevPortal, IS Console

Configure ZAP's **Form-Based Authentication** in a context that matches the surface, captures the session cookie on login submit, and provides a logged-in indicator (often `\Qhome.jsp\E`) and logged-out indicator (the login form's title). Export the context as a `.context` file for CI reuse; import in the Docker run with `-z "-config ..."`.

Define one context per surface — Carbon Console, Publisher, DevPortal, Console — because the login flow and indicators differ.

### Bearer-token REST APIs

Obtain an OAuth token before the scan, then inject it as the `Authorization` header:

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

**Set the token validity to cover the scan duration.** The OAuth `AccessTokenDefaultValidityPeriod` in `repository/conf/deployment.toml` may need to be increased for the test instance.

### OIDC flows (SSO into IS)

Use the **Authentication Helper** add-on (formerly Authentication scripts) and select OAuth 2.0 Authorization Code with PKCE. Configure once interactively in the desktop UI, export the context for CI reuse.

## WSO2 surfaces to scan and exclude

**Scan:** Carbon Management Console, APIM Publisher, APIM DevPortal, APIM Console, IS Console, IS My Account, all REST APIs that publish an OpenAPI spec.

**Exclude from Spider and Active Scan:** the **logout endpoint** for every surface. The Spider follows links indiscriminately and will eventually log out, after which the rest of the scan fails because the session is gone. Right-click the logout URL in the Sites tree → **Exclude from → Spider** and **Exclude from → Active Scan**.

For Go services, ZAP doesn't care about the server language — use the same baseline / full-scan / API-scan flows pointed at the Go service URL or its OpenAPI spec. Authentication is typically bearer-token as above.

## Triage

Active scans produce alerts faster than they can be filed individually. For each alert:

* **Real finding** — file against the product team; severity and remediation are in the alert details.
* **False positive** — open the alert, set **Confidence: False Positive**, then add an alert filter in **Session Properties → Alert Filters** so the same alert is auto-suppressed on the next run. Backport the filter to the repository's `.zap/` files if it should apply in CI.

Per-WSO2 expectations on the policy: tune ZAP to **expect the modern header set** ([HTTP Security Headers]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/security-related-http-headers/)), not legacy ones. By default ZAP still flags missing `X-XSS-Protection` — that's no longer the right signal; set the rule to `IGNORE` with a rationale row referencing the deprecation.

## Interactive scans

The ZAP desktop UI is the right place for triaging a CI finding or exploring a new feature whose paths the baseline doesn't yet exercise. ZAP install, browser proxy configuration, certificate trust, Spider / AJAX Spider, and the Active Scan workflow are covered in the ZAP documentation — start with the [ZAP Getting Started](https://www.zaproxy.org/getting-started/) guide.

WSO2-specific notes for interactive runs:

* Set ZAP's mode to **Protected** so only URLs added to the active context are attacked.
* For SPA-style WSO2 surfaces (Publisher, DevPortal, Console), use the AJAX Spider (executes JavaScript) followed by the Traditional Spider as a second pass.
* For multi-step workflows (the API creation wizard, MFA enrollment), supplement the spider with Selenium scripts that drive the UI; run them with ZAP as the proxy.
* Save the ZAP session (`File → Save Session`) periodically — active scans against a full Carbon product can run for hours and pre-emption loses the work.

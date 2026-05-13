---
title: Dependency Vulnerability Analysis
category: security-guidelines
version: 3.1
---

# Dependency Vulnerability Analysis

<p class="doc-info">Version: 3.1</p>
___

This document covers WSO2's policy for finding and triaging **known-vulnerable third-party dependencies**. Tool-by-tool tutorials are in the tools' own documentation — linked below. The supply-chain framing (version pinning, lock files, manifest guards, release signing) is in [Secure Coding Guide — Software Supply Chain Failures]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#software-supply-chain-failures).

## The WSO2 rule

**A known-vulnerable component never ships in a release.** Either the vulnerable code path is not reachable from product code (documented and approved by the WSO2 Security and Compliance Team) or the component is upgraded / replaced / removed. A finding that is neither fixed nor formally accepted **blocks the release**. Defer is not an option.

## When dependency scans run

* **Every pull request** — fast subset; build fails on any new high-severity finding.
* **Daily on `main`** — full database refresh; surfaces findings discovered overnight.
* **Before every release** — full scan with the latest vulnerability database; report attached to the release artefact.

The CI pipeline owns the scan; manual runs are for local debugging only.

## Tooling by stack

* **Java (Maven, Ivy, Gradle)** — [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/) ([Maven plugin reference](https://jeremylong.github.io/DependencyCheck/dependency-check-maven/), [releases](https://github.com/jeremylong/DependencyCheck/releases)).
* **Go** — [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) reading the [Go vulnerability database](https://pkg.go.dev/vuln/). Call-path analysis means findings reflect what is actually reachable from product code, not every vulnerable function in the dependency graph.
* **JavaScript / npm** — [`npm audit`](https://docs.npmjs.com/cli/v10/commands/npm-audit) or [`pnpm audit`](https://pnpm.io/cli/audit) for React portals and admin UIs shipped with WSO2 products.

Output format: **SARIF** wherever the tool supports it — uploads cleanly to the GitHub Security tab and integrates with the SAST dashboard. See the [SARIF specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) and [GitHub's SARIF support](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning).

## WSO2 CI configuration

### Java (Dependency Check Maven plugin)

Pin the plugin version in the parent POM. WSO2 settings:

```xml
<plugin>
    <groupId>org.owasp</groupId>
    <artifactId>dependency-check-maven</artifactId>
    <version>10.0.4</version>
    <configuration>
        <failBuildOnCVSS>7</failBuildOnCVSS>
        <suppressionFiles>
            <suppressionFile>dependency-check-suppressions.xml</suppressionFile>
        </suppressionFiles>
        <formats>
            <format>HTML</format>
            <format>SARIF</format>
        </formats>
        <nvdApiKey>${env.NVD_API_KEY}</nvdApiKey>
    </configuration>
    <executions>
        <execution><goals><goal>check</goal></goals></execution>
    </executions>
</plugin>
```

* `failBuildOnCVSS=7` — fails on High and Critical. WSO2 builds should aim for zero unsuppressed findings at this threshold.
* `nvdApiKey` is required for non-throttled runs. Obtain a [free NVD API key](https://nvd.nist.gov/developers/request-an-api-key) and store as the `NVD_API_KEY` CI secret.
* Never use Maven version ranges (`[1.0,)`), `LATEST`, or `RELEASE` in product POMs. Dependency Check can only assess what Maven resolves at build time; a moving version target makes findings unreproducible.

### Go (`govulncheck`)

```yaml
- name: govulncheck
  run: |
    go install golang.org/x/vuln/cmd/govulncheck@latest
    govulncheck -format sarif ./... > govulncheck.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: govulncheck.sarif
```

`govulncheck` does not support a suppression file. Track accepted findings in the project's `SECURITY.md` using the same rationale-and-review pattern as Java. The Go security team's recommendation is to fix or upgrade rather than suppress.

For release-validation against a built binary: `govulncheck -mode binary ./bin/your-binary`.

### JavaScript (`npm audit` / `pnpm audit`)

```sh
npm audit --audit-level=high
pnpm audit --audit-level high
```

CI fails on any unsuppressed high or critical advisory. The audit allow-list lives in `.audit-ignore.json` with one entry per accepted advisory:

```json
{
  "frontend": {
    "GHSA-XXXX-XXXX-XXXX": {
      "reason": "Transitive of eslint; dev-only, not shipped to production bundle.",
      "accepted_by": "security-team@wso2.com",
      "review_date": "2026-04-01"
    }
  }
}
```

The PR-builder workflow reads the allow-list and exits non-zero on any high/critical advisory not present in it.

Lock files must be committed (`package-lock.json`, `pnpm-lock.yaml`). CI installs with `npm ci` / `pnpm install --frozen-lockfile`. Never use semver ranges (`^`, `~`) in production `package.json`; pin exactly, lock the transitives.

## Triage workflow

When a new finding lands above the severity threshold:

1. **Severity ≥ High blocks the merge** until either fixed or formally accepted.
2. **Fix path**: upgrade the dependency; or pin a known-good earlier version if upstream has no fixed release yet; or remove the dependency if the project no longer needs it.
3. **Accept path**: the WSO2 Security and Compliance Team reviews, confirms the vulnerable code path is not reachable from product code (or that impact is otherwise mitigated), records the rationale in the suppression file / allow-list, and links to the review record. **Every acceptance carries an expiry date** — re-review at expiry.
4. **Defer is not an option.** A finding without an explicit accept is not "deferred", it is "blocking".

### Suppression rules

* Each suppression names a specific CVE / GHSA, a specific GAV (or package), and a rationale that points at a review record.
* Wildcard suppressions on entire packages are not acceptable.
* Every accepted finding has a named accept-er from the WSO2 Security and Compliance Team and an expiry date.

Example WSO2 Dependency Check suppression:

```xml
<suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd">
    <suppress>
        <notes>
            CVE-2024-XXXXX applies only to the FTP server functionality of
            commons-net, which WSO2 does not use. Confirmed by Security and
            Compliance Team review YYYY-MM-DD.
        </notes>
        <gav regex="true">^commons-net:commons-net:.*$</gav>
        <cve>CVE-2024-XXXXX</cve>
    </suppress>
</suppressions>
```

## PR-builder steps recap

* **Java** — `mvn dependency-check:check` (fails on CVSS ≥ 7).
* **Go** — `govulncheck ./...` (fails on any reachable vulnerability).
* **JS** — `npm audit --audit-level=high` (with `.audit-ignore.json` filter).

Each step uploads its SARIF output for the GitHub Security tab and attaches the human-readable report as a build artefact.

---
title: Dependency Vulnerability Analysis
category: security-guidelines
version: 3.0
---

# Dependency Vulnerability Analysis

<p class="doc-info">Version: 3.0</p>
___

This document covers tooling for finding **known-vulnerable third-party dependencies** in WSO2 product source. It is the operational companion to the supply-chain rules in [Secure Coding Guide — Software Supply Chain Failures]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/#software-supply-chain-failures), which covers the broader picture (version pinning, lock files, manifest guards, release signing).

The rule is the same in every stack: **a known-vulnerable component never ships in a release**. Either the vulnerable code path is not reachable from product code (documented and approved by the WSO2 Security and Compliance Team) or the component is upgraded / replaced / removed. A finding that is neither fixed nor formally accepted blocks the release.

## When and where

* **On every pull request** — fast subset, fail the build on any new high-severity finding.
* **Daily on `main`** — full database refresh, longer running, surface new findings discovered overnight.
* **Before every release** — full scan with the latest vulnerability database, attached to the release artefact.

The CI pipeline owns the dependency scan; it is not run manually only.

## Tooling by stack

=== "Java stack — OWASP Dependency Check"

    [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/) identifies known vulnerabilities in Java (Maven, Ivy, Gradle) and several other ecosystems. It maps each dependency to its CPE in the [NVD](https://nvd.nist.gov/) and reports any matching CVEs.

    **Maven plugin (canonical for WSO2 builds):**

    ```xml
    <build>
        <plugins>
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
                    <execution>
                        <goals>
                            <goal>check</goal>
                        </goals>
                    </execution>
                </executions>
            </plugin>
        </plugins>
    </build>
    ```

    Pin the plugin version; check the [Maven Central page](https://central.sonatype.com/artifact/org.owasp/dependency-check-maven) for the current release.

    Notes on configuration:

    * `failBuildOnCVSS` of 7.0 fails on High and Critical CVEs. New WSO2 builds should aim for 0 unsuppressed findings at this threshold.
    * `nvdApiKey` — obtain a free API key from the [NVD](https://nvd.nist.gov/developers/request-an-api-key). Without a key the NVD download is severely rate-limited and CI runs slowly. Store the key as a CI secret (`NVD_API_KEY`).
    * `formats` includes SARIF so findings can be uploaded to the GitHub Security tab.

    **Suppression file** — narrow, with rationale:

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
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

    Wildcard suppressions on full packages are not acceptable. Each suppression names a specific CVE, a specific GAV, and a rationale that points at a review record.

    **CLI** for local runs against a directory of JARs:

    ```sh
    dependency-check.sh --project "WSO2 Component" \
        --scan ./target/lib \
        --failOnCVSS 7 \
        --nvdApiKey "$NVD_API_KEY" \
        --format HTML --format SARIF \
        --out ./dependency-check-report
    ```

    Download the CLI from the [Dependency Check releases page](https://github.com/jeremylong/DependencyCheck/releases).

    **Avoid** Maven version ranges (`[1.0,)`), `LATEST`, and `RELEASE` in product POMs. Dependency Check can only assess what Maven resolves at build time; a moving version target makes findings unreproducible.

=== "Go stack — `govulncheck`"

    [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) is the official Go vulnerability scanner. Unlike database-only scanners, it does **call-path analysis** — it reports only vulnerabilities the code actually *reaches*, not every vulnerable function that happens to be in a dependency. False positives are dramatically lower.

    ```sh
    go install golang.org/x/vuln/cmd/govulncheck@latest
    govulncheck ./...
    ```

    In CI:

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

    `govulncheck` covers both the Go standard library and third-party modules. The Go vulnerability database it consults is curated by the Go security team — quality is high.

    **Suppression** — `govulncheck` itself doesn't support a suppression file; track accepted findings in the project's `SECURITY.md` (or equivalent) with the same rationale-and-review pattern as Java. The Go security team's recommendation is to fix or upgrade rather than suppress.

    **Module-only mode** (no source-level reachability, faster) for early-CI runs:

    ```sh
    govulncheck -mode binary ./bin/your-binary
    ```

    Use this against built binaries in release-validation steps.

=== "JavaScript / npm — `npm audit` / `pnpm audit`"

    For frontend modules shipped alongside WSO2 products (React portals, admin UIs, sample apps), `npm audit` and `pnpm audit` are the canonical scanners.

    ```sh
    # npm projects
    npm audit --audit-level=high

    # pnpm projects
    pnpm audit --audit-level high
    ```

    In CI, fail the build on any unsuppressed high or critical finding. The audit allow-list lives in a granular `.audit-ignore.json` (custom per repo) listing accepted GHSA / CVE IDs and a rationale per entry:

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

    **Lock files must be committed** (`package-lock.json`, `pnpm-lock.yaml`). CI installs with `npm ci` / `pnpm install --frozen-lockfile`. Never use semver ranges (`^`, `~`) in production `package.json`; pin to exact versions, and let the lock file pin transitives.

## Reporting and triage

Every scanner produces some form of structured output. Standardise on **SARIF** where possible — it uploads cleanly to GitHub's Security tab, integrates with most SAST dashboards, and lives next to the build artefact for the release record.

Triage workflow for a new finding:

1. **Severity ≥ High** — block the merge until either fixed or formally accepted.
2. **Fix path**: upgrade the dependency; or, if the upstream has no fixed release yet, pin a known-good earlier version; or, if the project no longer needs the dependency, remove it.
3. **Accept path**: the WSO2 Security and Compliance Team reviews the finding, confirms the vulnerable code path is not reachable from product code (or the impact is otherwise mitigated), records the rationale in the suppression file / allow-list, and links to the review record. The acceptance carries an expiry date — re-review at expiry.
4. **Defer is not an option.** A finding without an explicit accept is not "deferred", it is "blocking".

## CI gates

Recommended PR-builder steps for each stack:

* **Java** — `mvn dependency-check:check` (fails on CVSS ≥ 7 by default; pin the version in the parent POM).
* **Go** — `govulncheck ./...` (fails on any reachable vulnerability).
* **JS** — `npm audit --audit-level=high` (with `.audit-ignore.json` filter).

Each step uploads its SARIF output for the GitHub Security tab and attaches the human-readable HTML report as a build artefact.

## References

* [OWASP Dependency Check project](https://owasp.org/www-project-dependency-check/) — Java + Maven + several other ecosystems.
* [Dependency Check Maven plugin reference](https://jeremylong.github.io/DependencyCheck/dependency-check-maven/).
* [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) — official Go vulnerability scanner.
* [Go vulnerability database](https://pkg.go.dev/vuln/) — what `govulncheck` consults.
* [`npm audit`](https://docs.npmjs.com/cli/v10/commands/npm-audit) — npm vulnerability scanner.
* [`pnpm audit`](https://pnpm.io/cli/audit) — pnpm equivalent.
* [SARIF specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) — standardised output format.
* [GitHub code scanning with SARIF uploads](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning).
* [NVD API key registration](https://nvd.nist.gov/developers/request-an-api-key) — required for non-throttled Dependency Check runs.

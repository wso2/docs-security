---
title: Static Code Analysis
category: security-guidelines
version: 3.0
---

# Static Code Analysis

<p class="doc-info">Version: 3.0</p>
___

This document covers static-analysis tooling for WSO2 product code. Static analysis runs over the source — without executing it — to flag bugs, security defects, and known-bad patterns. It complements [Dynamic Analysis with OWASP ZAP]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/dynamic-analysis-with-owasp-zap/), which runs against the deployed application, and [Dependency Vulnerability Analysis]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/external-dependency-analysis-analysis-using-owasp-dependency-check/), which looks at third-party libraries.

Pick the tools that fit your stack. The full set is the right baseline; nothing here is optional in a production WSO2 product.

!!! note "FindBugs is defunct"
    Earlier versions of this document covered FindBugs and the FindBugs-IDEA IntelliJ plugin. **FindBugs has been unmaintained since 2015** and has been formally archived; the project moved to [SpotBugs](https://spotbugs.github.io/) (a community fork) in 2017. The **Find Security Bugs** plugin still exists and now runs on SpotBugs. Use SpotBugs + Find Security Bugs for new work. If a legacy build still references FindBugs, plan its migration to SpotBugs.

## What to run on every change

* **A SAST tool that covers OWASP-Top-10 patterns** (SpotBugs + Find Security Bugs for Java; `gosec` for Go).
* **A general-purpose static analyzer** for code quality and correctness defects that often have security implications (`spotbugs` core checks for Java; `staticcheck` for Go).
* **A semantic-rules engine** like [Semgrep](https://semgrep.dev/) or [GitHub CodeQL](https://codeql.github.com/) for codebase-specific rules. These catch the patterns that generic tools miss — usage of internal helpers, secrets in source, anti-patterns specific to WSO2 codebases.
* **A vulnerable-dependency scanner** — covered in the [Dependency Vulnerability Analysis]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/external-dependency-analysis-analysis-using-owasp-dependency-check/) doc, not here.

Findings above the agreed severity threshold fail the PR build. Suppressions go in an audited allow-list with a documented rationale; reviewers reject blanket suppressions.

## Tooling by stack

=== "Java stack"

    **SpotBugs + Find Security Bugs.** SpotBugs is the maintained successor to FindBugs; the Find Security Bugs plugin layers ~120 security-focused rules on top of SpotBugs's bytecode analysis. Both run on the compiled classes (not source), so they catch defects across method boundaries and library usage that pure-source analyzers miss.

    **Maven plugin (canonical for CI):**

    ```xml
    <build>
        <plugins>
            <plugin>
                <groupId>com.github.spotbugs</groupId>
                <artifactId>spotbugs-maven-plugin</artifactId>
                <version>4.8.6.6</version>
                <configuration>
                    <effort>Max</effort>
                    <threshold>Low</threshold>
                    <failOnError>true</failOnError>
                    <plugins>
                        <plugin>
                            <groupId>com.h3xstream.findsecbugs</groupId>
                            <artifactId>findsecbugs-plugin</artifactId>
                            <version>1.13.0</version>
                        </plugin>
                    </plugins>
                </configuration>
                <executions>
                    <execution>
                        <id>spotbugs</id>
                        <phase>verify</phase>
                        <goals>
                            <goal>check</goal>
                        </goals>
                    </execution>
                </executions>
            </plugin>
        </plugins>
    </build>
    ```

    Pin both versions; check the [SpotBugs](https://spotbugs.github.io/) and [Find Security Bugs](https://find-sec-bugs.github.io/) sites for current releases before pinning. The `<effort>Max</effort>` and `<threshold>Low</threshold>` settings are intentionally aggressive — for new code, the build should be quiet at this setting.

    **Suppressing a specific finding** — only with a rationale, only with a narrow filter file:

    ```xml
    <!-- spotbugs-exclude.xml -->
    <FindBugsFilter>
        <Match>
            <Bug pattern="EI_EXPOSE_REP"/>
            <Class name="org.wso2.example.legacy.LegacyDTO"/>
            <!-- Reason: public mutable internal array is the existing contract;
                 rewrite tracked in WSO2-XXXX. -->
        </Match>
    </FindBugsFilter>
    ```

    Annotation-based suppression (`@SuppressFBWarnings`) is acceptable on a single method or field; both forms must include a rationale comment.

    **IDE integration.** The current SpotBugs IntelliJ plugin is `SpotBugs-IDEA`, available from JetBrains Marketplace. The legacy `FindBugs-IDEA` plugin is unmaintained — uninstall and replace.

    **Beyond SpotBugs.** Consider [Semgrep](https://semgrep.dev/) for codebase-specific patterns (forbid direct `Cipher.getInstance("RSA")` calls, require `CryptoUtil` usage, ban `Runtime.exec(String)` in product code). Semgrep rules are short YAML files and run on source — they catch patterns SpotBugs cannot express. [GitHub CodeQL](https://codeql.github.com/) is the heavier alternative; it runs in Actions and produces findings in the GitHub Security tab.

    **WSO2-specific anti-patterns to author rules for** — the [Secure Coding Guide]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/) names many. The high-value ones to encode in a Semgrep ruleset:

    * `Cipher.getInstance("RSA")` or `"AES"` without explicit mode and padding
    * `MessageDigest.getInstance("MD5")` and `"SHA-1"` for security purposes
    * `NoopHostnameVerifier.INSTANCE` or `AllowAllHostnameVerifier`
    * `ObjectInputStream` construction without `ObjectInputFilter`
    * `Runtime.getRuntime().exec(<single String arg>)` outside test code
    * Missing `PrivilegedCarbonContext.endTenantFlow()` after `startTenantFlow()`

=== "Go stack"

    **`gosec`** — Go-specific SAST that covers the OWASP-Top-10 patterns the Go ecosystem cares about (hardcoded credentials, `crypto/md5`/`sha1` for security purposes, `crypto/rand` substitutes with `math/rand`, `os/exec` with shell, SQL injection via string concat, TLS misconfiguration including `InsecureSkipVerify`).

    ```sh
    go install github.com/securego/gosec/v2/cmd/gosec@latest
    gosec -severity high -confidence medium ./...
    ```

    In CI, fail the build on any high-severity finding:

    ```yaml
    - name: gosec
      run: |
        go install github.com/securego/gosec/v2/cmd/gosec@latest
        gosec -severity high -confidence medium -exclude-dir=vendor ./...
    ```

    **`staticcheck`** — code quality and correctness defects from the [Staticcheck](https://staticcheck.dev/) suite. Run alongside `gosec`; the two have minimal overlap. `staticcheck` catches deadlocks, ineffective error handling, mis-spelled identifiers, and other defects that often have security implications.

    ```sh
    go install honnef.co/go/tools/cmd/staticcheck@latest
    staticcheck ./...
    ```

    **`govulncheck`** — though primarily a dependency vulnerability tool, it also reports usage of vulnerable code paths in the standard library. Covered in [Dependency Vulnerability Analysis]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/external-dependency-analysis-analysis-using-owasp-dependency-check/).

    **`go vet`** is enabled by default in `go build` and `go test` in current Go releases — surface warnings as build errors with `-vet=all`.

    **Semgrep** for codebase-specific patterns is as useful here as in Java. Examples of WSO2 Go anti-patterns worth encoding as Semgrep rules:

    * `tls.Config{InsecureSkipVerify: true}` outside `_test.go`
    * `aes.NewCipher` called from anywhere outside the project's central crypto helper package
    * `==` comparison of MAC/HMAC byte slices (must be `hmac.Equal`)
    * `text/template` used to render HTML
    * `panic(` calls in handlers/services (panic is reserved for init failures)
    * `json.Unmarshal` without `DisallowUnknownFields` on inbound request bodies
    * `os/exec` invocations of `sh -c` with interpolated input

## CI integration

Run static analysis on every pull request, fail on findings above the agreed threshold, allow suppressions only with rationale. The PR-builder workflow already runs build and test; SAST is a parallel step.

For GitHub Actions, [`reviewdog`](https://github.com/reviewdog/reviewdog) is the standard way to surface SAST findings as inline PR comments rather than a single build-failed message — much better signal for reviewers.

## Reports

* SpotBugs + Find Security Bugs produces an XML report (`target/spotbugsXml.xml` by default). The HTML view is generated by `mvn spotbugs:gui` locally; for CI, attach the XML as a build artefact and use a reviewdog adapter to surface findings inline.
* `gosec` produces JSON/SARIF; SARIF is the format to feed into GitHub's Security tab.
* `staticcheck` produces line-by-line text and JSON.
* Semgrep / CodeQL produce SARIF natively.

Track findings over time. A SAST tool that produces 1000 findings on first run with no follow-up is doing nothing. Either fix or formally accept each — never silently ignore.

## References

* [SpotBugs](https://spotbugs.github.io/) — successor to FindBugs.
* [Find Security Bugs](https://find-sec-bugs.github.io/) — security plugin for SpotBugs.
* [SpotBugs Maven plugin](https://spotbugs.github.io/spotbugs-maven-plugin/).
* [Staticcheck](https://staticcheck.dev/) — Go static analysis.
* [gosec](https://github.com/securego/gosec) — Go security analyzer.
* [Semgrep](https://semgrep.dev/) — semantic rules engine, Java and Go and others.
* [GitHub CodeQL](https://codeql.github.com/) — query-based code analysis.
* [reviewdog](https://github.com/reviewdog/reviewdog) — CI integration for surfacing SAST findings as PR comments.

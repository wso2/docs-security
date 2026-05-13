---
title: Static Code Analysis
category: security-guidelines
version: 3.1
---

# Static Code Analysis

<p class="doc-info">Version: 3.1</p>
___

This document covers the WSO2-specific guidance for static-analysis tooling. Tool-by-tool tutorials, install steps, and configuration references are in the tools' own documentation — linked below.

Static analysis complements [Dynamic Analysis with OWASP ZAP]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/dynamic-analysis-with-owasp-zap/) and [Dependency Vulnerability Analysis]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/external-dependency-analysis-analysis-using-owasp-dependency-check/).

!!! note "FindBugs is defunct"
    Earlier versions of this document referenced FindBugs and `FindBugs-IDEA`. **FindBugs has been unmaintained since 2015** and is formally archived; the project moved to [SpotBugs](https://spotbugs.github.io/) in 2017, and Find Security Bugs now runs on SpotBugs. Use SpotBugs + Find Security Bugs for new work; migrate any legacy build that still references FindBugs.

## What WSO2 builds run

Every WSO2 product build runs all four:

* **OWASP-Top-10-focused SAST** — SpotBugs + Find Security Bugs (Java); `gosec` (Go).
* **General-purpose static analyzer** — SpotBugs core (Java); `staticcheck` (Go).
* **Semantic-rules engine** for codebase-specific patterns — [Semgrep](https://semgrep.dev/) or [GitHub CodeQL](https://codeql.github.com/). These catch what generic tools cannot — usage of internal WSO2 helpers, secrets in source, anti-patterns from past audits.
* **Vulnerable-dependency scanner** — covered in [Dependency Vulnerability Analysis]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/external-dependency-analysis-analysis-using-owasp-dependency-check/).

Findings above the agreed severity threshold fail the PR build. Suppressions go in an audited allow-list with a documented rationale; blanket suppressions are rejected at review.

## Tool references

* **SpotBugs**: [project site](https://spotbugs.github.io/) · [Maven plugin](https://spotbugs.github.io/spotbugs-maven-plugin/) · [SpotBugs-IDEA IntelliJ plugin](https://plugins.jetbrains.com/plugin/14014-spotbugs) (the legacy `FindBugs-IDEA` is unmaintained; uninstall and replace).
* **Find Security Bugs** (SpotBugs plugin, ~120 security rules): [project site](https://find-sec-bugs.github.io/).
* **`gosec`**: [github.com/securego/gosec](https://github.com/securego/gosec).
* **`staticcheck`**: [staticcheck.dev](https://staticcheck.dev/).
* **Semgrep**: [semgrep.dev](https://semgrep.dev/).
* **CodeQL**: [codeql.github.com](https://codeql.github.com/).
* **`reviewdog`** (surface SAST findings as inline PR comments): [github.com/reviewdog/reviewdog](https://github.com/reviewdog/reviewdog).

## WSO2 thresholds and CI integration

* Maven SpotBugs plugin pinned in the parent POM with `<effort>Max</effort>` and `<threshold>Low</threshold>`; `<failOnError>true</failOnError>`. New code should be quiet at this setting. Pin both the SpotBugs and Find Security Bugs plugin versions; check their sites for current releases.
* `gosec` in CI: `gosec -severity high -confidence medium -exclude-dir=vendor ./...` — fails on any high-severity finding.
* SARIF output from each tool uploaded to the GitHub Security tab. Semgrep and CodeQL produce SARIF natively; `gosec` supports it directly; SpotBugs XML can be converted via a reviewdog adapter or `spotbugs-sarif`.
* SAST runs as a parallel step alongside build/test in the PR builder. `reviewdog` surfaces findings as inline PR comments rather than a single "build failed" line.
* Track findings over time. A SAST tool producing 1000 findings on first run with no follow-up is doing nothing. Either fix or formally accept each.

### Suppressions

Narrow, with rationale, in the tool-native suppression format:

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

## WSO2-specific Semgrep rules to author

These are anti-patterns from the WSO2 [Secure Coding Guide]({{#base_path#}}/security-guidelines/secure-engineering-guidelines/secure-coding-guidlines/secure-coding-guide/) that generic SAST tools do not catch. They are high-value to encode as Semgrep (or CodeQL) rules in a shared WSO2 ruleset:

**Java:**

* `Cipher.getInstance("RSA")` or `"AES"` without explicit mode and padding.
* `MessageDigest.getInstance("MD5")` and `"SHA-1"` for security purposes.
* `NoopHostnameVerifier.INSTANCE` or `AllowAllHostnameVerifier`.
* `ObjectInputStream` construction without `ObjectInputFilter`.
* `Runtime.getRuntime().exec(<single String arg>)` outside test code.
* Missing `PrivilegedCarbonContext.endTenantFlow()` after `startTenantFlow()`.
* Direct `Cipher.getInstance` calls outside the central `CryptoUtil` facade.

**Go:**

* `tls.Config{InsecureSkipVerify: true}` outside `_test.go`.
* `aes.NewCipher` called from anywhere outside the project's central crypto helper package.
* `==` comparison of MAC / HMAC byte slices (must be `hmac.Equal`).
* `text/template` used to render HTML (must be `html/template`).
* `panic(` in handlers / services (panic is reserved for init failures).
* `json.Unmarshal` without `DisallowUnknownFields` on inbound request bodies.
* `os/exec` invocations of `sh -c` with interpolated input.

Each rule lives in the shared WSO2 Semgrep ruleset with a short description, the canonical example, and a link to the Secure Coding Guide entry that motivated it.

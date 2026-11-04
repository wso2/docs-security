#!/usr/bin/env python3
#
# Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
#
# WSO2 LLC. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

"""Check that links to a CVE record point to the CVE Program's record page.

A CVE record is linked as:

    https://www.cve.org/CVERecord?id=CVE-2026-5430

Reported, wherever they appear in a Markdown file (link targets, link text,
bare URLs and HTML attributes):

    NVD                https://nvd.nist.gov/vuln/detail/CVE-2026-5430
    CVE Details        https://www.cvedetails.com/cve/CVE-2026-5430/
    MITRE (old site)   https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-5430
    other directories  cvefeed.io, opencve.io, vulners.com, cve.circl.lu
    cve.org            any other form, such as http://, no "www.", or a lowercase ID

Links to vendor or researcher advisories, to WSO2 pages, and to tools such
as CVSS calculators are not CVE record links and are not reported.

Code blocks and inline code are skipped, as is any line that contains
<!-- cve-link-check: allow -->. Use it only when the text cites something
that only the other site shows, such as NVD's own CVSS score.

Usage:

    python3 .github/scripts/check_cve_links.py [--fix] [PATH ...]

PATH defaults to en/docs and .announcement-templates. With --fix, the links
are rewritten in place.

Requires Python 3.8 or later and no third-party packages.
"""

import argparse
import bisect
import os
import re
import sys

CANONICAL = "https://www.cve.org/CVERecord?id={}"
EXAMPLE = CANONICAL.format("CVE-2026-5430")
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_PATHS = ("en/docs", ".announcement-templates")
SCRIPT = ".github/scripts/check_cve_links.py"
ALLOW = "<!-- cve-link-check: allow -->"

CVE_RECORD_URL = re.compile(
    r"https?://(?:www\.|app\.)?(?:"
    r"nvd\.nist\.gov/vuln/detail/"
    r"|cvedetails\.com/cve/"
    r"|cve\.mitre\.org/cgi-bin/cvename\.cgi\?name="
    r"|cvefeed\.io/vuln/detail/"
    r"|opencve\.io/cve/"
    r"|vulners\.com/cve/"
    r"|cve\.circl\.lu/(?:vuln|cve)/"
    r"|cve\.org/CVERecord/?\?id="
    r")(?P<id>CVE-\d{4}-\d{4,})(?![\w-])/?",
    re.IGNORECASE,
)
FENCE = re.compile(r"^[ \t]*(```|~~~)")
INLINE_CODE = re.compile(r"(`+)(?:(?!\1).)+?\1")


class Finding(object):
    def __init__(self, start, found, replacement):
        self.start = start
        self.found = found
        self.replacement = replacement
        self.message = "link to the CVE record as {} (found {})".format(replacement, found)


def find_links(text):
    """Return the CVE record links that are not in the canonical form."""
    findings = []
    offset = 0
    in_fence = None
    for line in text.splitlines(True):
        fence = FENCE.match(line)
        if fence:
            if in_fence is None:
                in_fence = fence.group(1)
            elif fence.group(1) == in_fence:
                in_fence = None
        elif in_fence is None and ALLOW not in line:
            code = [m.span() for m in INLINE_CODE.finditer(line)]
            for match in CVE_RECORD_URL.finditer(line):
                if any(start <= match.start() < end for start, end in code):
                    continue
                replacement = CANONICAL.format(match.group("id").upper())
                if match.group(0) != replacement:
                    findings.append(Finding(offset + match.start(), match.group(0), replacement))
        offset += len(line)
    return findings


def apply_fixes(text, findings):
    parts = []
    last = 0
    for finding in findings:
        parts.append(text[last:finding.start])
        parts.append(finding.replacement)
        last = finding.start + len(finding.found)
    parts.append(text[last:])
    return "".join(parts)


def markdown_files(paths):
    for path in paths:
        if os.path.isfile(path):
            yield path
            continue
        for root, dirs, files in os.walk(path):
            dirs[:] = sorted(d for d in dirs if not d.startswith("."))
            for name in sorted(files):
                if name.endswith(".md"):
                    yield os.path.join(root, name)


def escape_annotation(value):
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def report(path, text, findings, github):
    line_starts = [0] + [m.end() for m in re.finditer(r"\n", text)]
    for finding in findings:
        line = bisect.bisect_right(line_starts, finding.start)
        column = finding.start - line_starts[line - 1] + 1
        print("{}:{}:{}: {}".format(path, line, column, finding.message))
        if github:
            print("::error file={},line={},col={},endColumn={},title=CVE link::{}".format(
                path, line, column, column + len(finding.found),
                escape_annotation(finding.message)))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check that CVE record links use {}.".format(EXAMPLE))
    parser.add_argument("paths", nargs="*", metavar="PATH",
                        help="Markdown files or folders (default: {})".format(
                            ", ".join(DEFAULT_PATHS)))
    parser.add_argument("--fix", action="store_true", help="rewrite the links in place")
    args = parser.parse_args(argv)

    paths = args.paths or [os.path.relpath(os.path.join(REPO_ROOT, p)) for p in DEFAULT_PATHS]
    missing = [p for p in paths if not os.path.exists(p)]
    if missing:
        parser.error("path not found: {}".format(", ".join(missing)))

    github = os.environ.get("GITHUB_ACTIONS") == "true"
    checked = fixed = fixed_files = remaining = remaining_files = 0
    for path in markdown_files(paths):
        with open(path, encoding="utf-8", newline="") as handle:
            text = handle.read()
        checked += 1
        findings = find_links(text)
        if args.fix and findings:
            with open(path, "w", encoding="utf-8", newline="") as handle:
                handle.write(apply_fixes(text, findings))
            fixed += len(findings)
            fixed_files += 1
            continue
        if findings:
            report(path, text, findings, github)
            remaining += len(findings)
            remaining_files += 1

    if args.fix:
        print("Fixed {} link(s) in {} file(s).".format(fixed, fixed_files))
    if not remaining:
        print("Checked {} file(s). All CVE record links use {}.".format(
            checked, CANONICAL.format("<CVE ID>")))
        return 0
    print("\nFound {} CVE record link(s) in {} file(s) that do not use {}.".format(
        remaining, remaining_files, CANONICAL.format("<CVE ID>")))
    print('Run "python3 {} --fix" to rewrite them.'.format(SCRIPT))
    return 1


if __name__ == "__main__":
    sys.exit(main())

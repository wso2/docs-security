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

With --published, the script checks instead that every CVE ID a page links
has a published CVE record, so a page never links a reserved CVE ID before
its record is public. It looks up each ID in the CVE Program's API
(https://cveawg.mitre.org/api/cve/<CVE ID>). The IDs are those of the CVE
record links above, in any form, and those in the front matter title, which
the build links on the page. A rejected record counts as published. When the
API cannot be reached, the check fails rather than passing unchecked. With
--since REF, only the CVE IDs that a file did not link at the git revision
REF are checked, so a pull request is checked for the IDs it adds.

Usage:

    python3 .github/scripts/check_cve_links.py [--fix | --published [--since REF]] [PATH ...]

PATH defaults to en/docs and .announcement-templates. With --fix, the links
are rewritten in place.

Requires Python 3.8 or later and no third-party packages.
"""

import argparse
import bisect
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

CANONICAL = "https://www.cve.org/CVERecord?id={}"
EXAMPLE = CANONICAL.format("CVE-2026-5430")
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_PATHS = ("en/docs", ".announcement-templates")
SCRIPT = ".github/scripts/check_cve_links.py"
ALLOW = "<!-- cve-link-check: allow -->"
CVE_API = "https://cveawg.mitre.org/api/cve/{}"
ATTEMPTS = 3

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
CVE_ID = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
TITLE = re.compile(r"\A---[ \t]*\r?\n(?:.*\r?\n)*?(title:.*)$", re.M)
FENCE = re.compile(r"^[ \t]*(```|~~~)")
INLINE_CODE = re.compile(r"(`+)(?:(?!\1).)+?\1")


class Finding(object):
    def __init__(self, start, found, replacement):
        self.start = start
        self.found = found
        self.replacement = replacement
        self.message = "link to the CVE record as {} (found {})".format(replacement, found)


class Unpublished(object):
    def __init__(self, start, cve_id):
        self.start = start
        self.found = cve_id
        self.message = ("{} has no published CVE record. Link it once its record is published on "
                        "cve.org, or remove the link".format(cve_id))


def record_links(text):
    """Yield (offset, match) for each CVE record link outside code and allowed lines."""
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
                if not any(start <= match.start() < end for start, end in code):
                    yield offset + match.start(), match
        offset += len(line)


def find_links(text):
    """Return the CVE record links that are not in the canonical form."""
    findings = []
    for start, match in record_links(text):
        replacement = CANONICAL.format(match.group("id").upper())
        if match.group(0) != replacement:
            findings.append(Finding(start, match.group(0), replacement))
    return findings


def linked_cves(text):
    """Return (offset, CVE ID) for each CVE ID the page links: its record links and its title's IDs."""
    linked = [(start, match.group("id").upper()) for start, match in record_links(text)]
    title = TITLE.match(text)
    if title:
        linked += [(title.start(1) + m.start(), m.group(0).upper()) for m in CVE_ID.finditer(title.group(1))]
    return sorted(linked)


def record_state(cve_id):
    """The state of a CVE record (PUBLISHED or REJECTED), or None when it has no record.

    Raises OSError when the CVE Program's API cannot be reached after a few attempts.
    """
    request = urllib.request.Request(CVE_API.format(cve_id), headers={
        "Accept": "application/json", "User-Agent": "wso2-docs-security-cve-link-check"})
    for attempt in range(1, ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return json.load(response).get("cveMetadata", {}).get("state")
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None  # CVE_RECORD_DNE: reserved, or never assigned
            failure = error
        except (urllib.error.URLError, OSError, ValueError) as error:
            failure = error
        if attempt < ATTEMPTS:
            time.sleep(2 * attempt)
    raise OSError("could not look up {} at {}: {}".format(cve_id, CVE_API.format(cve_id), failure))


def linked_at(revision, path):
    """The CVE IDs a file linked at a git revision; none when the file did not exist there."""
    relative = os.path.relpath(os.path.abspath(path), REPO_ROOT).replace(os.sep, "/")
    result = subprocess.run(["git", "-C", REPO_ROOT, "show", "{}:{}".format(revision, relative)],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if result.returncode != 0:
        return set()
    return {cve_id for _, cve_id in linked_cves(result.stdout.decode("utf-8", "replace"))}


def find_unpublished(text, states, known=frozenset()):
    """Return the CVE IDs the page links that have no published record, leaving out the known ones.

    states caches the lookups.
    """
    findings = []
    for start, cve_id in linked_cves(text):
        if cve_id in known:
            continue
        if cve_id not in states:
            states[cve_id] = record_state(cve_id)
        if states[cve_id] is None:
            findings.append(Unpublished(start, cve_id))
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
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--fix", action="store_true", help="rewrite the links in place")
    mode.add_argument("--published", action="store_true",
                      help="check instead that each linked CVE ID has a published record (needs network access)")
    parser.add_argument("--since", metavar="REF",
                        help="with --published, check only the CVE IDs a file did not link at this git revision")
    args = parser.parse_args(argv)
    if args.since and not args.published:
        parser.error("--since needs --published")

    paths = args.paths or [os.path.relpath(os.path.join(REPO_ROOT, p)) for p in DEFAULT_PATHS]
    missing = [p for p in paths if not os.path.exists(p)]
    if missing:
        parser.error("path not found: {}".format(", ".join(missing)))

    github = os.environ.get("GITHUB_ACTIONS") == "true"
    if args.published:
        return check_published(paths, github, args.since)
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


def check_published(paths, github, since=None):
    states = {}
    checked = remaining = remaining_files = 0
    for path in markdown_files(paths):
        with open(path, encoding="utf-8", newline="") as handle:
            text = handle.read()
        checked += 1
        known = linked_at(since, path) if since else frozenset()
        try:
            findings = find_unpublished(text, states, known)
        except OSError as error:
            print("{}: {}".format(path, error))
            if github:
                print("::error file={},title=CVE record::{}".format(path, escape_annotation(str(error))))
            print("\nThe CVE Program's API could not be reached, so the CVE records were not checked. "
                  "Run the check again.")
            return 1
        if findings:
            report(path, text, findings, github)
            remaining += len(findings)
            remaining_files += 1
    if not remaining:
        print("Checked {} file(s) and looked up {} CVE ID(s). Each has a published record.".format(
            checked, len(states)))
        return 0
    print("\nFound {} link(s) in {} file(s) to CVE IDs that have no published record.".format(
        remaining, remaining_files))
    return 1


if __name__ == "__main__":
    sys.exit(main())

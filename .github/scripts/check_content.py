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

"""Check the documentation for consistency problems that have caused errors before.

Every page:

    placeholder      a template placeholder such as {{cvss}} was left in the page
    stray-front-matter  a second front matter block in the page body, which readers see
                     as plain text
    legacy-link      a link to the retired docs.wso2.com/display/ pages
    trailing-slash   a {{#base_path#}} link to a page does not end with "/"   (--fix)
    empty-link       a link with no text or no target
    image-alt        an image has no alt text, or only its file name
    file-name        a file name contains characters other than letters, digits, ".", "-", "_"

Security advisories (security-advisories/<year>/WSO2-*.md):

    advisory-id      the title or heading does not name the advisory in the file name
    repeated-info    the page repeats its heading or Published, Updated, Version,
                     Severity, CVSS, or CVE IDs lines; the build renders them from
                     front matter. --fix removes them when they match front matter,
                     and first copies any value front matter lacks         (--fix)
    field-format     a front matter field is missing or not in its standard form:
                     published, version (1.0.0), severity (Critical, High, Medium,
                     Low, Informative, Not Applicable), cvss ("9.8 (CVSS:3.1/...)" or
                     Not Applicable)                                      (--fix for
                     N/A, lowercase severity, 1.0 versions, and stray spaces)
    cvss-score       the cvss score differs from the base score of its CVSS 3.0 or 3.1
                     vector (CVSS 4.0 vectors are not checked)
    severity-score   the severity differs from the rating of the cvss score: Low 0.1
                     to 3.9, Medium 4.0 to 6.9, High 7.0 to 8.9, Critical 9.0 to 10.0
    year-folder      the published year differs from the year folder
    duplicate-id     the advisory ID exists in more than one year folder
    listing          the advisory is missing from its yearly list or from the nav
    listing-label    the yearly list entry does not read "WSO2-... (CVE-...)" with
                     the advisory's CVE IDs                                (--fix)

CVE justifications (cve-justifications/<year>/*.md):

    listing          the page is missing from its yearly list or from the nav
    field-format     no published date, or "date" instead of "published"  (--fix)

Problems recorded in .github/scripts/content_check_baseline.txt are not
reported. Each line there is "<path> <rule>". Remove a line once the problem
is fixed; the check says which lines are no longer needed.

Usage:

    python3 .github/scripts/check_content.py [--fix] [PATH ...]

PATH defaults to en/docs. Cross-page rules (listing, duplicate-id) look at the
whole docs folder but report only on the files checked.

Requires Python 3.8 or later and no third-party packages.
"""

import argparse
import bisect
import collections
import math
import os
import posixpath
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DOCS = os.path.join(REPO_ROOT, "en", "docs")
MKDOCS = os.path.join(REPO_ROOT, "en", "mkdocs.yml")
BASELINE = os.path.join(REPO_ROOT, ".github", "scripts", "content_check_baseline.txt")
SCRIPT = ".github/scripts/check_content.py"

ADVISORY_PATH = re.compile(r"security-announcements/security-advisories/(\d{4})/(WSO2-\d{4}-\d{4})\.md$")
ADVISORY_LIST_PATH = re.compile(r"security-announcements/security-advisories/(\d{4})/\d{4}-advisories\.md$")
JUSTIFICATION_PATH = re.compile(r"security-announcements/cve-justifications/(\d{4})/(?!index\.md$)([^/]+)\.md$")
CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
DATE = re.compile(r"^(January|February|March|April|May|June|July|August|September|October|"
                  r"November|December) [1-9]\d?, \d{4}$")
SEVERITIES = ("Critical", "High", "Medium", "Low", "Informative", "Not Applicable")
CVSS = re.compile(r"^\d{1,2}(\.\d)? \(CVSS:\d\.\d/[A-Za-z:/]+\)$")
INFO_BLOCK = re.compile(r'#[ \t]+[^\n]*\n(?:[ \t]*\n)*(?:<p class="doc-info">[^\n]*\n)+(?:[ \t]*\n)*(?:---[ \t]*\n)?(?:[ \t]*\n)*')
INFO_LINE = re.compile(r'^<p class="doc-info">(Published|Updated|Version|Severity|CVSS Score|CVE IDs):.*$', re.M)
HEADING = re.compile(r"\s*^#[ \t]+(.+?)[ \t]*$", re.M)  # only the first line of the body
PLACEHOLDER = re.compile(r"\{\{(?!#)[^{}#]*\}\}")
MD_LINK = re.compile(r"(!?)\[([^\]]*)\]\(([^)\s]*)(?:\s+\"[^\"]*\")?\)")
HTML_LINK = re.compile(r"<a\b[^>]*?href=\"([^\"]*)\"[^>]*>(.*?)</a>", re.S)
HTML_IMG = re.compile(r"<img\b[^>]*>")
FENCE = re.compile(r"^[ \t]*(```|~~~)")
INLINE_CODE = re.compile(r"(`+)(?:(?!\1).)+?\1")
FILE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


class Finding(object):
    def __init__(self, rule, start, message, fixable=False):
        self.rule = rule
        self.start = start
        self.message = message
        self.fixable = fixable


class Page(object):
    def __init__(self, path):
        self.path = path
        self.rel = os.path.relpath(path, DOCS).replace(os.sep, "/")
        with open(path, encoding="utf-8", newline="") as handle:
            self.text = handle.read()
        match = re.match(r"\A\s*---[ \t]*\n(.*?\n)---[ \t]*\n", self.text, re.S)
        self.meta_end = match.end() if match else 0
        self.meta = collections.OrderedDict()
        self.meta_lines = {}
        if match:
            offset = match.start(1)
            for line in match.group(1).splitlines(True):
                field = re.match(r"([A-Za-z][\w -]*?):[ \t]*(.*?)[ \t]*$", line.rstrip("\n"))
                if field:
                    value = field.group(2)
                    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                        value = value[1:-1]
                    self.meta[field.group(1)] = value
                    self.meta_lines[field.group(1)] = offset
                offset += len(line)
        self.body = self.text[self.meta_end:]

    def prose_spans(self):
        """Spans of the body outside fenced code and inline code."""
        spans = []
        offset = self.meta_end
        fence = None
        for line in self.body.splitlines(True):
            marker = FENCE.match(line)
            if marker:
                fence = marker.group(1) if fence is None else (None if marker.group(1) == fence else fence)
            elif fence is None:
                last = 0
                for code in INLINE_CODE.finditer(line):
                    spans.append((offset + last, offset + code.start(), line[last:code.start()]))
                    last = code.end()
                spans.append((offset + last, offset + len(line), line[last:]))
            offset += len(line)
        return spans


class Site(object):
    """Facts that span pages: nav entries, yearly lists, and advisory locations."""

    def __init__(self):
        with open(MKDOCS, encoding="utf-8") as handle:
            self.nav = set(re.findall(r"'([^']+\.md)'\s*$", handle.read(), re.M))
        self.advisory_folders = collections.defaultdict(list)
        self.lists = {}
        for root, _, files in os.walk(DOCS):
            for name in files:
                rel = os.path.relpath(os.path.join(root, name), DOCS).replace(os.sep, "/")
                match = ADVISORY_PATH.search(rel)
                if match:
                    self.advisory_folders[match.group(2)].append(match.group(1))
                if ADVISORY_LIST_PATH.search(rel) or re.search(r"cve-justifications/\d{4}/index\.md$", rel):
                    with open(os.path.join(root, name), encoding="utf-8") as handle:
                        self.lists[rel] = handle.read()

    def listed(self, list_rel, target):
        text = self.lists.get(list_rel, "")
        pattern = r"\]\(\{\{#base_path#\}\}/" + "(?: |%20)".join(re.escape(p) for p in target.split(" ")) + r"/?\)"
        return re.search(pattern, text) is not None


def check_page(page, site):
    findings = []
    name = os.path.basename(page.path)
    if not FILE_NAME.match(name):
        findings.append(Finding("file-name", 0, "rename the file without spaces or parentheses, "
                                "and add a redirect from the old URL"))
    stray = re.search(r"^---[ \t]*\n(?:[A-Za-z][\w -]*:.*\n)+---[ \t]*$", page.body, re.M)
    if stray:
        findings.append(Finding("stray-front-matter", page.meta_end + stray.start(),
                                "remove the second front matter block; readers see it as text"))
    for start, _, text in page.prose_spans():
        for match in PLACEHOLDER.finditer(text):
            findings.append(Finding("placeholder", start + match.start(),
                                    "fill in the template placeholder {}".format(match.group(0))))
        for match in MD_LINK.finditer(text):
            image, label, target = match.group(1), match.group(2).strip(), match.group(3)
            at = start + match.start()
            if image:
                stem = os.path.splitext(posixpath.basename(target))[0]
                slug = re.fullmatch(r"[\w.]+(?:[-_][\w.]+)+", label)
                if not label or slug or label.lower().replace(" ", "-") == stem.lower():
                    findings.append(Finding("image-alt", at, "describe the image in its alt text"))
                continue
            check_target(findings, at, label, target)
        for match in HTML_LINK.finditer(text):
            label = re.sub(r"<[^>]+>", "", match.group(2)).strip()
            check_target(findings, start + match.start(), label, match.group(1))
        for match in HTML_IMG.finditer(text):
            alt = re.search(r"\balt=\"([^\"]*)\"", match.group(0))
            if not alt or not alt.group(1).strip():
                findings.append(Finding("image-alt", start + match.start(), "describe the image in its alt text"))

    advisory = ADVISORY_PATH.search(page.rel)
    if advisory:
        findings.extend(check_advisory(page, site, advisory.group(1), advisory.group(2)))
    listing = ADVISORY_LIST_PATH.search(page.rel)
    if listing:
        findings.extend(check_advisory_list(page, site, listing.group(1)))
    justification = JUSTIFICATION_PATH.search(page.rel)
    if justification:
        findings.extend(check_justification(page, site, justification.group(1), justification.group(2)))
    return findings


def check_target(findings, at, label, target):
    if not label or not target or target.endswith("?id="):
        findings.append(Finding("empty-link", at, "give the link both text and a target"))
    elif "docs.wso2.com/display/" in target:
        findings.append(Finding("legacy-link", at, "replace the link to the retired docs.wso2.com/display/ "
                                "page with its current location"))
    elif target.startswith("{{#base_path#}}/"):
        path = "{{#base_path#}}/" + target[len("{{#base_path#}}/"):].split("#", 1)[0]
        if not path.endswith("/") and "." not in posixpath.basename(path):
            findings.append(Finding("trailing-slash", at, "end the link with \"/\" ({}/)".format(path), True))


def advisory_cves(page):
    """The advisory's CVE IDs, found the way the build finds them (hooks/seo.py)."""
    cves = CVE.findall(page.meta.get("title", ""))
    if not cves:
        line = re.search(r"CVE IDs?:(.*)", page.body)
        cves = CVE.findall(line.group(1)) if line else []
    if not cves:
        overview = re.search(r"^#{2,4}[ \t]+OVERVIEW[ \t]*\n(.*?)(?=^#{2,4}[ \t])", page.body, re.M | re.S)
        cves = CVE.findall(overview.group(1)) if overview else []
    return list(collections.OrderedDict.fromkeys(cves))


def check_advisory(page, site, year, advisory_id):
    findings = []
    meta, line = page.meta, page.meta_lines
    title = meta.get("title", "")
    if advisory_id not in title or len(re.findall(r"WSO2-\d{4}-\d{4}", title)) != 1:
        findings.append(Finding("advisory-id", line.get("title", 0),
                                "the title must name {} (found \"{}\")".format(advisory_id, title)))

    shown = INFO_LINE.findall(page.body)
    heading = HEADING.match(page.body)
    if heading and any(found != advisory_id for found in re.findall(r"WSO2-\d{4}-\d{4}", heading.group(1))):
        findings.append(Finding("advisory-id", page.meta_end + heading.start(1),
                                "the heading must name {} (found \"{}\")".format(advisory_id, heading.group(1))))
    if shown or (heading and re.match(r"(?i)security advisory\b", heading.group(1))):
        repeated = (["heading"] if heading else []) + shown
        findings.append(Finding("repeated-info", page.meta_end + (heading.start() if heading else 0),
                                "remove the {} from the page body; the build renders them from front "
                                "matter".format(", ".join(repeated)), safe_to_remove(page)))

    published = meta.get("published", "")
    if not published:
        findings.append(Finding("field-format", 0, "add a published date"))
    elif DATE.match(published) and published[-4:] != year:
        findings.append(Finding("year-folder", line["published"],
                                "published {} is not in the {} folder".format(published, year)))
    version = meta.get("version")
    if version is None:
        findings.append(Finding("field-format", 0, "add a version, such as 1.0.0"))
    elif not re.match(r"^\d+\.\d+\.\d+$", version):
        findings.append(Finding("field-format", line["version"], "write the version as 1.0.0 (found \"{}\")".format(
            version), bool(re.match(r"^\d+\.\d+$", version))))
    severity = meta.get("severity")
    if severity is None:
        findings.append(Finding("field-format", 0, "add a severity"))
    elif severity not in SEVERITIES:
        findings.append(Finding("field-format", line["severity"], "write the severity as one of {} (found \"{}\")".format(
            ", ".join(SEVERITIES), severity), normalize_severity(severity) is not None))
    cvss = meta.get("cvss")
    if cvss is None:
        findings.append(Finding("field-format", 0, "add a cvss value, such as \"9.8 (CVSS:3.1/...)\""))
    elif cvss != "Not Applicable" and not CVSS.match(cvss):
        findings.append(Finding("field-format", line["cvss"], "write cvss as \"9.8 (CVSS:3.1/...)\" or Not "
                                "Applicable (found \"{}\")".format(cvss), normalize_cvss(cvss) is not None))
    elif cvss != "Not Applicable":
        score, vector = float(cvss.split(" ", 1)[0]), cvss.split(" ", 1)[1][1:-1]
        computed = cvss3_base_score(vector)
        if computed is not None and computed != score:
            findings.append(Finding("cvss-score", line["cvss"], "the vector {} gives a score of {}, not {}; correct "
                                    "the score or the vector".format(vector, computed, cvss.split(" ", 1)[0])))
        if severity in SEVERITIES[:4] and severity != cvss_rating(score):
            findings.append(Finding("severity-score", line["severity"], "a CVSS score of {} is {}, but the severity "
                                    "is {}".format(cvss.split(" ", 1)[0], cvss_rating(score), severity)))
    for key in meta:
        if key not in ("title", "category", "published", "updated", "version", "severity", "cvss",
                       "description", "seo_title"):
            findings.append(Finding("field-format", line[key], "remove the unknown front matter field \"{}\"".format(key)))

    if len(site.advisory_folders.get(advisory_id, [])) > 1:
        findings.append(Finding("duplicate-id", 0, "{} also exists in {}".format(advisory_id, ", ".join(
            y for y in sorted(site.advisory_folders[advisory_id]) if y != year))))
    target = "security-announcements/security-advisories/{}/{}".format(year, advisory_id)
    list_rel = "security-announcements/security-advisories/{0}/{0}-advisories.md".format(year)
    if not site.listed(list_rel, target):
        findings.append(Finding("listing", 0, "add {} to {}".format(advisory_id, list_rel)))
    if target + ".md" not in site.nav:
        findings.append(Finding("listing", 0, "add {}.md to the nav in en/mkdocs.yml".format(target)))
    return findings


def check_advisory_list(page, site, year):
    findings = []
    entry = re.compile(r"^\* \[([^\]]+)\]\(\{\{#base_path#\}\}/security-announcements/security-advisories/"
                       r"(\d{4})/(WSO2-\d{4}-\d{4})/?\)", re.M)
    for match in entry.finditer(page.body):
        label, folder, advisory_id = match.groups()
        at = page.meta_end + match.start()
        path = os.path.join(DOCS, "security-announcements", "security-advisories", folder, advisory_id + ".md")
        if not os.path.exists(path):
            findings.append(Finding("listing", at, "{} links to {}/{}, which does not exist".format(
                label, folder, advisory_id)))
            continue
        expected = expected_label(Page(path), advisory_id)
        if label != expected:
            findings.append(Finding("listing-label", at, "write the entry as \"{}\" (found \"{}\")".format(
                expected, label), True))
    return findings


def expected_label(page, advisory_id):
    cves = advisory_cves(page)
    return "{} ({})".format(advisory_id, ", ".join(cves)) if cves else advisory_id


def check_justification(page, site, year, name):
    findings = []
    target = "security-announcements/cve-justifications/{}/{}".format(year, name)
    list_rel = "security-announcements/cve-justifications/{}/index.md".format(year)
    if not site.listed(list_rel, target):
        findings.append(Finding("listing", 0, "add the page to {}".format(list_rel)))
    if target + ".md" not in site.nav:
        findings.append(Finding("listing", 0, "add {}.md to the nav in en/mkdocs.yml".format(target)))
    if "date" in page.meta:
        findings.append(Finding("field-format", page.meta_lines["date"], "rename \"date\" to \"published\", as in "
                                "the CVE justification template", True))
    elif not page.meta.get("published"):
        findings.append(Finding("field-format", 0, "add a published date"))
    return findings


def normalize_severity(value):
    value = value.strip()
    if value in ("N/A", "NA", "n/a"):
        return "Not Applicable"
    if value.capitalize() in SEVERITIES:
        return value.capitalize()
    return None


def normalize_cvss(value):
    value = value.strip()
    if value in ("N/A", "NA", "n/a"):
        return "Not Applicable"
    match = re.match(r"^(\d{1,2}(?:\.\d)?)\s*\(?\s*(CVSS:\d\.\d/[A-Za-z:/]+)\s*\)?$", value)
    return "{} ({})".format(match.group(1), match.group(2)) if match else None


CVSS3_WEIGHTS = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
                 "UI": {"N": 0.85, "R": 0.62}, "C": {"H": 0.56, "L": 0.22, "N": 0.0}}


def cvss3_base_score(vector):
    """The base score of a CVSS 3.0 or 3.1 vector, as the FIRST specification defines it, or None."""
    match = re.match(r"^CVSS:(3\.[01])/((?:[A-Z]+:[A-Z]/?)+)$", vector)
    if not match:
        return None
    metrics = dict(part.split(":") for part in match.group(2).strip("/").split("/"))
    try:
        changed = {"U": False, "C": True}[metrics["S"]]
        privileges = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[metrics["PR"]]
        exploitability = (8.22 * CVSS3_WEIGHTS["AV"][metrics["AV"]] * CVSS3_WEIGHTS["AC"][metrics["AC"]] *
                          privileges * CVSS3_WEIGHTS["UI"][metrics["UI"]])
        c, i, a = (CVSS3_WEIGHTS["C"][metrics[key]] for key in ("C", "I", "A"))
    except KeyError:
        return None
    base = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (base - 0.029) - 3.25 * (base - 0.02) ** 15 if changed else 6.42 * base
    if impact <= 0:
        return 0.0
    score = min(1.08 * (impact + exploitability) if changed else impact + exploitability, 10)
    if match.group(1) == "3.0":
        return math.ceil(score * 10) / 10
    whole = int(round(score * 100000))
    return whole / 100000.0 if whole % 10000 == 0 else (whole // 10000 + 1) / 10.0


def cvss_rating(score):
    if score == 0:
        return "None"
    return "Low" if score < 4 else "Medium" if score < 7 else "High" if score < 9 else "Critical"


def standard(key, value):
    """A field value in its standard form, as --fix writes it."""
    if key == "version" and re.match(r"^\d+\.\d+$", value):
        return value + ".0"
    if key == "severity":
        return normalize_severity(value) or value
    if key == "cvss":
        return normalize_cvss(value) or value
    return value


SHOWN_FIELDS = collections.OrderedDict([("Published", "published"), ("Updated", "updated"), ("Version", "version"),
                                        ("Severity", "severity"), ("CVSS Score", "cvss")])


def shown_values(page):
    """The values the page's info lines show, keyed by front matter field."""
    shown = dict(re.findall(r'^<p class="doc-info">([A-Za-z ]+?):\s*(.*?)\s*</p>\s*$', page.body, re.M))
    return collections.OrderedDict((key, re.sub(r"<a [^>]*>(.*?)</a>", r"\1", shown[label]).strip())
                                   for label, key in SHOWN_FIELDS.items() if label in shown)


def safe_to_remove(page):
    """True when every repeated line shows what front matter holds, or front matter lacks that field."""
    shown = dict(re.findall(r'^<p class="doc-info">([A-Za-z ]+?):\s*(.*?)\s*</p>\s*$', page.body, re.M))
    fields = SHOWN_FIELDS
    for label, value in shown.items():
        if label == "CVE IDs":
            found = list(collections.OrderedDict.fromkeys(CVE.findall(value)))
            if not found or found != advisory_cves(page):
                return False
            continue
        if label not in fields:
            return False
        value = re.sub(r"<a [^>]*>(.*?)</a>", r"\1", value).strip()
        current = page.meta.get(fields[label], "").strip()
        if current and standard(fields[label], value) != standard(fields[label], current):
            return False
    if "Updated" not in shown and page.meta.get("updated", "") not in ("", page.meta.get("published")):
        return False
    if "CVE IDs" not in shown and CVE.search(page.meta.get("title", "")):
        return False
    heading = HEADING.match(page.body)
    block = INFO_BLOCK.match(page.body.lstrip("\n"))
    if not heading or not block or heading.group(1).lower() != page.meta.get("title", "").lower():
        return False
    block_lines = [l for l in block.group(0).splitlines() if l.startswith("<p class=")]
    return all(INFO_LINE.match(l) for l in block_lines) and len(block_lines) == len(INFO_LINE.findall(page.body)) \
        and len(block_lines) == len(re.findall(r'^<p class="doc-info">', page.body, re.M))


def fix(page, findings):
    text = page.text
    rules = {f.rule for f in findings if f.fixable}
    if "trailing-slash" in rules:
        def slash(m):
            path = m.group(2)
            if path.endswith("/") or "." in posixpath.basename(path):
                return m.group(0)
            return m.group(1) + path + "/" + m.group(3)
        text = re.sub(r"(\]\(\{\{#base_path#\}\}/)([^)#\s]+)((?:#[^)\s]*)?\))", slash, text)
    if "repeated-info" in rules:
        head, body = text[:page.meta_end], text[page.meta_end:].lstrip("\n")
        # Keep any value the page shows but front matter lacks.
        missing = ["{}: \"{}\"\n".format(key, value) for key, value in shown_values(page).items()
                   if not page.meta.get(key, "").strip()]
        head = re.sub(r"---[ \t]*\n\Z", "".join(missing) + "---\n", head)
        text = head + "\n" + body[INFO_BLOCK.match(body).end():]
    if "field-format" in rules:
        head, body = text[:page.meta_end], text[page.meta_end:]
        def field(key, valid, normalize):
            def replace(m):
                value = m.group(2)
                if valid(value) or normalize(value) is None:
                    return m.group(0)
                return m.group(1) + '"{}"'.format(normalize(value))
            return re.sub(r"^(" + key + r":[ \t]*)\"?([^\"\n]*?)\"?[ \t]*$", replace, head, flags=re.M)
        head = field("severity", lambda v: v in SEVERITIES, normalize_severity)
        head = field("cvss", lambda v: v == "Not Applicable" or CVSS.match(v), normalize_cvss)
        head = re.sub(r"^date:", "published:", head, flags=re.M) if JUSTIFICATION_PATH.search(page.rel) else head
        head = re.sub(r"^(version:[ \t]*)\"?(\d+\.\d+)\"?[ \t]*$", r'\1"\2.0"', head, flags=re.M)
        text = head + body
    if "listing-label" in rules:
        def relabel(match):
            path = os.path.join(DOCS, "security-announcements", "security-advisories", match.group(3),
                                match.group(4) + ".md")
            if not os.path.exists(path):
                return match.group(0)
            return match.group(1) + expected_label(Page(path), match.group(4)) + match.group(2)
        text = re.sub(r"^(\* \[)[^\]]+(\]\(\{\{#base_path#\}\}/security-announcements/security-advisories/"
                      r"(\d{4})/(WSO2-\d{4}-\d{4})/?\))", relabel, text, flags=re.M)
    return text


def load_baseline():
    entries = set()
    if os.path.exists(BASELINE):
        with open(BASELINE, encoding="utf-8") as handle:
            for line in handle:
                line = line.split("#", 1)[0].strip()
                if line:
                    path, rule = line.rsplit(" ", 1)
                    entries.add((path, rule))
    return entries


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


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check the documentation for consistency problems.")
    parser.add_argument("paths", nargs="*", metavar="PATH", help="Markdown files or folders (default: en/docs)")
    parser.add_argument("--fix", action="store_true", help="fix the problems that can be fixed safely")
    args = parser.parse_args(argv)

    paths = args.paths or [os.path.relpath(DOCS)]
    missing = [p for p in paths if not os.path.exists(p)]
    if missing:
        parser.error("path not found: {}".format(", ".join(missing)))

    github = os.environ.get("GITHUB_ACTIONS") == "true"
    site = Site()
    baseline = load_baseline()
    used = set()
    checked = fixed = 0
    remaining = collections.Counter()
    whole_docs = not args.paths
    for path in markdown_files(paths):
        if not os.path.abspath(path).startswith(DOCS + os.sep):
            continue
        page = Page(path)
        checked += 1
        findings = check_page(page, site)
        if args.fix and any(f.fixable for f in findings):
            new_text = fix(page, findings)
            if new_text != page.text:
                with open(path, "w", encoding="utf-8", newline="") as handle:
                    handle.write(new_text)
                fixed += 1
                site = Site()
                page = Page(path)
                findings = check_page(page, site)
        line_starts = [0] + [m.end() for m in re.finditer(r"\n", page.text)]
        for finding in findings:
            if (page.rel, finding.rule) in baseline:
                used.add((page.rel, finding.rule))
                continue
            line = bisect.bisect_right(line_starts, finding.start)
            column = finding.start - line_starts[line - 1] + 1
            message = "{} [{}]".format(finding.message, finding.rule)
            print("{}:{}:{}: {}".format(path, line, column, message))
            if github:
                print("::error file={},line={},col={},title=Content check::{}".format(
                    path, line, column, escape_annotation(message)))
            remaining[finding.rule] += 1

    if args.fix:
        print("Fixed problems in {} file(s).".format(fixed))
    if whole_docs:
        for path, rule in sorted(baseline - used):
            print("{}: the baseline entry \"{} {}\" is no longer needed; remove it from {}".format(
                os.path.relpath(BASELINE), path, rule, os.path.relpath(BASELINE)))
    if not remaining:
        print("Checked {} file(s). No content problems found.".format(checked))
        return 0
    print("\nFound {} content problem(s): {}.".format(
        sum(remaining.values()), ", ".join("{} {}".format(n, r) for r, n in sorted(remaining.items()))))
    print('Run "python3 {} --fix" to fix the ones marked as fixable, and fix the rest by hand.'.format(SCRIPT))
    return 1


if __name__ == "__main__":
    sys.exit(main())

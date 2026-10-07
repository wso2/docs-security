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

"""The announcement formats: security advisories, CVE justifications, and incident clarifications.

Authors write each value once, in front matter. The build renders a page's heading
from its title and its info lines from its fields; .github/scripts/check_content.py
checks the fields against the same definitions.
"""

import html
import os
import re

from . import text

ADVISORY_RE = re.compile(r"^security-announcements/security-advisories/\d{4}/WSO2-[^/]+\.md$")
JUSTIFICATION_RE = re.compile(r"^security-announcements/cve-justifications/\d{4}/(?!index\.md$)[^/]+\.md$")
INCIDENT_RE = re.compile(r"^security-announcements/incident-clarifications/\d{4}/(?!index\.md$)[^/]+\.md$")
BULLETIN_RE = re.compile(r"^security-announcements/cloud-security-bulletins/[^/]+/\d{4}/(?!index\.md$)[^/]+\.md$")

# The info lines of a CVE justification and of an incident clarification: each is a front
# matter field, shown in this order as "label: value". Older pages wrote the lines by hand,
# under the other labels listed, which .github/scripts/check_content.py --fix moves into
# front matter. Fields: (key, label, older labels, required, allowed values).
YES_NO = r"^(Yes|No)( \(.+\))?$"
JUSTIFICATION_FIELDS = (
    ("published", "Published", (), True, "date"),
    ("updated", "Updated", ("Last Updated",), False, "date"),
    ("wso2_products_impacted", "WSO2 Products impacted", ("WSO2 Products Impacted",), True,
     r"^(Yes|No|Limited)( \(.+\))?$"),
    ("severity", "WSO2 Products severity", ("WSO2 Products Severity",), False, "severity"),
    ("cvss", "WSO2 Products CVSS score", ("WSO2 Products CVSS Score",), False, "cvss"),
    ("customer_action_required", "Customer action required",
     ("Customer actions required", "Customers actions required", "Customers Actions Required"), True, YES_NO),
)
INCIDENT_FIELDS = (
    ("published", "Published", (), True, "date"),
    ("updated", "Updated", ("Last Updated",), False, "date"),
    ("version", "Version", (), False, "version"),
    ("wso2_impacted", "WSO2 impacted", (), True, YES_NO),
    ("evidence_of_compromise", "Evidence of compromise", (), True, YES_NO),
    ("customers_impacted", "Customers impacted", (), False, YES_NO),
    ("customer_action_required", "Customer action required",
     ("Customer actions required", "Customers actions required"), True, YES_NO),
)

# The section that lists a page's products, by format. Each line starts with a product name
# from products.txt.
PRODUCT_SECTIONS = ((ADVISORY_RE, "AFFECTED PRODUCTS"), (JUSTIFICATION_RE, "REPORTED PRODUCTS"))
PRODUCTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "products.txt")


def products():
    """The official product names, and the old spellings check_content.py --fix replaces.

    Read from products.txt, which people edit: one name per line, and "old -> official"
    lines for spellings to correct.
    """
    official, renamed = [], {}
    with open(PRODUCTS_FILE, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "->" in line:
                old, new = (part.strip() for part in line.split("->", 1))
                renamed[old] = new
            else:
                official.append(line)
    return official, renamed


# An advisory's search title uses its OVERVIEW sentence, up to this length, after dropping
# words that add nothing to it.
TITLE_SUMMARY_LIMIT = 100
_FOUND = r"(?:identified|detected|discovered|found|observed)"
_PLACE = r"(?=\s+(?:in|on|at|with|within|through|during|when|via|for|while|after|before|due)\b|$)"
TITLE_FILLER_RES = (
    re.compile(r"^It has been " + _FOUND + r" that\s+", re.I),
    re.compile(r"^(?:A|An)\s+(?=\S)", re.I),
    re.compile(r"\s+(?:has|have) been " + _FOUND + _PLACE, re.I),
    re.compile(r"\s+(?:is|are|was|were) " + _FOUND + _PLACE, re.I),
    re.compile(r"\s+exists?" + _PLACE, re.I),
)


def advisory_cves(title, markdown, sections=None):
    """An advisory's CVE IDs: from its title, else its CVE IDs line, else its OVERVIEW."""
    cves = text.unique(text.CVE_RE.findall(str(title or "")))
    if not cves:
        line = re.search(r"CVE IDs?:(.*)", markdown)
        cves = text.unique(text.CVE_RE.findall(line.group(1))) if line else []
    if not cves:
        sections = text.sections(markdown) if sections is None else sections
        cves = text.unique(text.CVE_RE.findall(sections.get("OVERVIEW", "")))
    return cves


def advisory_overview(markdown):
    """The first paragraph of an advisory's OVERVIEW section."""
    return text.first_paragraph(text.sections(markdown).get("OVERVIEW", ""))


def title_summary(overview, drop_cves=False):
    """The search title wording of an advisory's OVERVIEW, and whether the title can use it.

    The OVERVIEW's first sentence names the vulnerability. The title drops only words that
    add nothing to it ("A potential XSS vulnerability has been identified in X" becomes
    "Potential XSS vulnerability in X"), so it never says anything the page does not.
    Sentences that are still long, or that lean on the page ("the above-listed products"),
    give way to the product names.
    """
    summary = re.split(r"(?<=[.!?])\s+", overview.strip())[0].rstrip(".")
    if drop_cves:
        # The title starts with the CVE IDs, so drop a "(CVE-...)" that repeats them.
        summary = re.sub(r"\s*\((?:CVE-\d{4}-\d{4,}[,\s]*)+\)", "", summary)
    start = summary
    for pattern in TITLE_FILLER_RES:
        summary = pattern.sub("", summary, count=1)
    if summary != start and not summary.startswith(start[:1]):
        summary = summary[:1].upper() + summary[1:]
    usable = (10 <= len(summary) <= TITLE_SUMMARY_LIMIT
              and not re.search(r"(?i)\babove\b", summary) and not re.match(r"(?i)it has been", summary))
    return summary, usable


def render(src, markdown, meta):
    """A page's Markdown with the heading and info lines its format renders from front matter."""
    if ADVISORY_RE.match(src):
        markdown = with_info_block(markdown, meta)
        return heading_with_cves(markdown, meta, advisory_cves(meta.get("title"), markdown))
    if JUSTIFICATION_RE.match(src):
        return with_info_lines(with_heading(markdown, meta), meta, JUSTIFICATION_FIELDS)
    if INCIDENT_RE.match(src):
        return with_info_lines(with_heading(markdown, meta), meta, INCIDENT_FIELDS)
    return markdown


def with_info_block(markdown, meta):
    """Render an advisory's heading and info lines from its front matter.

    Authors fill Published, Updated, Version, Severity, CVSS, and the CVE IDs (in the
    title) once, in front matter. Pages that still write the info lines themselves are
    left as they are.
    """
    if 'class="doc-info"' in markdown:
        return markdown
    lines = []
    published = text.display_date(meta.get("published"))
    updated = text.display_date(meta.get("updated"))
    if published:
        lines.append(info_line("Published", published))
    if updated:
        lines.append(info_line("Updated", updated))
    for label, key in (("Version", "version"), ("Severity", "severity")):
        value = str(meta.get(key) or "").strip()
        if value:
            lines.append(info_line(label, html.escape(value)))
    cvss = str(meta.get("cvss") or "").strip()
    if cvss:
        lines.append(info_line("CVSS Score", cvss_link(cvss)))
    cves = text.unique(text.CVE_RE.findall(str(meta.get("title", ""))))
    if cves:
        links = ['<a href="https://www.cve.org/CVERecord?id={0}">{0}</a>'.format(cve) for cve in cves]
        lines.append(info_line("CVE IDs", ", ".join(links)))
    block = "\n".join(lines) + "\n---\n" if lines else ""

    heading = text.leading_heading(markdown)
    if heading:
        return markdown[:heading.end()] + "\n\n" + block + "\n" + markdown[heading.end():].lstrip("\n")
    title = str(meta.get("title") or "").strip()
    return "# {}\n\n{}\n{}".format(title, block, markdown.lstrip("\n"))


def heading_with_cves(markdown, meta, cves):
    """Show an advisory's CVE IDs in its heading, as in "Security Advisory WSO2-2021-1738/CVE-2022-29464".

    Some advisories list their CVE only in the "CVE IDs:" line. The heading carries
    weight with search engines, so the build adds any CVE ID it is missing.
    """
    match = text.leading_heading(markdown)
    if not cves or not match:
        return markdown
    heading = match.group(1)
    missing = [cve for cve in cves if cve not in heading]
    if not missing:
        return markdown
    updated = heading + (", " if text.CVE_RE.search(heading) else "/") + ", ".join(missing)
    if str(meta.get("title", "")).strip() == heading:
        meta["title"] = updated
    return markdown[:match.start(1)] + updated + markdown[match.end(1):]


def with_heading(markdown, meta):
    """Render a CVE justification's or incident clarification's heading from its title.

    Authors write the title once, in front matter. Pages that still start with their
    own heading are left as they are.
    """
    title = str(meta.get("title") or "").strip()
    if text.leading_heading(markdown) or not title:
        return markdown
    return "# {}\n\n{}".format(title, markdown.lstrip("\n"))


def with_info_lines(markdown, meta, fields):
    """Render a CVE justification's or incident clarification's info lines from front matter.

    Pages that still write the lines themselves are left as they are.
    """
    if 'class="doc-info"' in markdown:
        return markdown
    lines = []
    for key, label, _, _, kind in fields:
        value = meta.get(key)
        if isinstance(value, bool):  # YAML reads an unquoted Yes or No as a boolean
            value = "Yes" if value else "No"
        if kind == "date":
            shown = text.display_date(value)
        elif kind == "cvss":
            shown = cvss_link(str(value or "").strip())
        else:
            shown = html.escape(str(value if value is not None else "").strip())
        if shown:
            lines.append(info_line(label, shown))
    if not lines:
        return markdown
    heading = text.leading_heading(markdown)
    rest = markdown[heading.end():] if heading else markdown
    head = markdown[:heading.end()] + "\n\n" if heading else ""
    rule = "" if re.match(r"\s*---[ \t]*\n", rest) else "---\n"  # the page may draw its own
    return head + "\n".join(lines) + "\n" + rule + "\n" + rest.lstrip("\n")


def info_line(label, value):
    return '<p class="doc-info">{}: {}</p>'.format(label, value)


def cvss_link(cvss):
    """Link a "score (CVSS:x.y/...)" value to the FIRST calculator, as the advisories do."""
    vector = re.search(r"\((CVSS:(\d\.\d)/[^)\s]+)\)", cvss)
    if not vector:
        return html.escape(cvss)
    version = vector.group(2).replace("4.0", "4-0")
    return '<a href="https://www.first.org/cvss/calculator/{}#{}">{}</a>'.format(
        version, vector.group(1), html.escape(cvss))

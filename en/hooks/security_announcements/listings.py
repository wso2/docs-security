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

"""The lists and nav the build writes from the announcement files, so authors add a page in one place.

    Security advisories        the yearly list pages, the year sections of the nav, and the
                               year links on the Security Advisories page
    Incident clarifications    the same, by year of the incident
    CVE justifications         one table on the CVE Justifications page, by CVE ID; they are
                               not in the nav
"""

import os
import posixpath
import re
from datetime import datetime

from . import formats, text

ADVISORY_DIR = "security-announcements/security-advisories"
ADVISORY_FILE_RE = re.compile(r"^WSO2-\d{4}-\d{4}\.md$")
ADVISORY_YEAR_RE = re.compile(r"^security-announcements/security-advisories/(\d{4})/\d{4}-advisories\.md$")
INCIDENT_YEAR_RE = re.compile(r"^security-announcements/incident-clarifications/(\d{4})/index\.md$")
JUSTIFICATION_YEAR_RE = re.compile(r"^security-announcements/cve-justifications/(\d{4})/index\.md$")
BULLETIN_YEAR_RE = re.compile(r"^security-announcements/cloud-security-bulletins/[^/]+/(\d{4})/index\.md$")

# Section pages that list their year pages: the year folder, the year page, and its label.
YEAR_LISTS = {
    "security-announcements/security-advisories/index.md":
        ("security-announcements/security-advisories", "{0}/{0}-advisories.md", "{0} Advisories"),
    "security-announcements/incident-clarifications/index.md":
        ("security-announcements/incident-clarifications", "{0}/index.md", "{0} Incident Clarifications"),
}
# Where a section page lists its year pages. The build replaces this line.
YEAR_LIST_MARKER = "<!-- The build lists the year pages here, newest first. -->"
YEAR_LINK_RE = re.compile(r"^[*-][ \t]+\[[^\]]*\]\(\{\{#base_path#\}\}/security-announcements/"
                          r"(?:security-advisories|cve-justifications|incident-clarifications)/\d{4}/[^)]*\)[ \t]*\n?", re.M)
# Any year page list line the build writes: an advisory, CVE justification, or incident clarification.
ENTRY_LINE_RE = re.compile(r"^[*-][ \t]+\[.*\]\(\{\{#base_path#\}\}/security-announcements/(?:security-advisories|"
                           r"cve-justifications|incident-clarifications)/\d{4}/.+\)[ \t]*\n?", re.M)
# The nav sections the build writes, by their index page, and how each names its year sections.
# CVE justifications are not in the nav: their section page lists them by CVE ID.
NAV_SECTIONS = {
    "security-announcements/security-advisories/index.md": "{} Advisories",
    "security-announcements/incident-clarifications/index.md": "{}",
}
JUSTIFICATIONS_PAGE = "security-announcements/cve-justifications/index.md"
# Where the CVE Justifications page lists every justification by CVE ID. The build replaces this line.
JUSTIFICATION_TABLE_MARKER = "<!-- The build lists the CVE justifications here, by CVE ID. -->"


def fill_nav(items, docs_dir):
    """Write the year sections of the advisories and incident clarifications into the nav.

    Each year folder with a year page gets a section listing its pages, as the year page does.
    """
    for item in items:
        if not isinstance(item, dict):
            continue
        for value in item.values():
            if not isinstance(value, list):
                continue
            landing = nav_index(value)
            if landing not in NAV_SECTIONS:
                fill_nav(value, docs_dir)
                continue
            label = NAV_SECTIONS[landing]
            # Year sections written by hand are dropped; check_content.py reports them.
            value[:] = [entry for entry in value if not (isinstance(entry, dict) and any(
                isinstance(v, list) and nav_index(v).startswith(landing[:-len("index.md")]) for v in entry.values()))]
            for year, year_page, _ in year_pages(docs_dir, landing):
                folder = posixpath.dirname(year_page)
                value.append({label.format(year): [{"": year_page}] + [
                    # The nav names an advisory by its ID; the year page adds its CVE IDs.
                    {name if folder.startswith(ADVISORY_DIR + "/") else name_label: "{}/{}.md".format(folder, name)}
                    for name, name_label in section_entries(docs_dir, folder)]})


def nav_index(entries):
    """The page a nav section names as `'': path`, its index."""
    return next((v for entry in entries if isinstance(entry, dict)
                 for k, v in entry.items() if k == "" and isinstance(v, str)), "")


def generated_source(src, source, docs_dir):
    """A page's source with the lists the build writes, or None when the page has none."""
    folder = posixpath.dirname(src)
    if ADVISORY_YEAR_RE.match(src) or INCIDENT_YEAR_RE.match(src):
        source = ENTRY_LINE_RE.sub("", source)  # check_content.py reports these
        entries = ["* [" + label + "]({{#base_path#}}/" + folder + "/" + name + "/)"
                   for name, label in section_entries(docs_dir, folder)]
        return source.rstrip("\n") + "\n\n" + "\n".join(entries) + "\n"
    if src == JUSTIFICATIONS_PAGE:
        return source.replace(JUSTIFICATION_TABLE_MARKER, justification_table(docs_dir), 1)
    if src not in YEAR_LISTS:
        return None
    links = "\n".join("* [" + label + "]({{#base_path#}}/" + text.page_path(list_page) + ")"
                      for _, list_page, label in year_pages(docs_dir, src))
    source = YEAR_LINK_RE.sub("", source)  # check_content.py reports these
    if YEAR_LIST_MARKER in source:
        return source.replace(YEAR_LIST_MARKER, links, 1)
    return source.rstrip("\n") + "\n\n" + links + "\n"


def section_entries(docs_dir, folder):
    """The pages a year page lists, as (file name without .md, label), in list order.

    Advisories: newest advisory ID first, labeled with their CVE IDs. Incident
    clarifications: newest published first, then the higher CVE ID, then the title,
    labeled with the title.
    """
    if folder.startswith(ADVISORY_DIR + "/"):
        return advisory_list(docs_dir, folder.rsplit("/", 1)[1])
    root = os.path.join(docs_dir, folder)
    entries = []
    for name in os.listdir(root):
        if not name.endswith(".md") or name == "index.md":
            continue
        with open(os.path.join(root, name), encoding="utf-8-sig") as handle:
            fields, _ = text.front_matter(handle.read())
        title = fields.get("title") or name[:-3]
        try:
            published = datetime.strptime(fields.get("published", ""), "%B %d, %Y")
        except ValueError:
            published = datetime.min
        cve = re.search(r"CVE-(\d{4})-(\d+)", title)
        entries.append((published, (int(cve.group(1)), int(cve.group(2))) if cve else (0, 0), title, name[:-3]))
    return [(name, title) for _, _, title, name in sorted(entries, reverse=True)]


def advisory_list(docs_dir, year):
    """The advisories in a year folder as (advisory ID, list label) pairs, newest ID first.

    The label carries the CVE IDs, as in "WSO2-2026-5328 (CVE-2026-5430)".
    """
    folder = os.path.join(docs_dir, ADVISORY_DIR, year)
    ids = [name[:-3] for name in os.listdir(folder) if ADVISORY_FILE_RE.match(name)] if os.path.isdir(folder) else []
    entries = []
    for advisory_id in sorted(ids, key=lambda i: (int(i[5:9]), int(i[10:])), reverse=True):
        with open(os.path.join(folder, advisory_id + ".md"), encoding="utf-8-sig") as handle:
            fields, body = text.front_matter(handle.read())
        cves = formats.advisory_cves(fields.get("title", ""), body)
        entries.append((advisory_id, "{} ({})".format(advisory_id, ", ".join(cves)) if cves else advisory_id))
    return entries


def justification_rows(docs_dir):
    """Every CVE justification, one row per CVE ID, newest CVE first, then the ones without a CVE.

    Each row is (ID, page path, WSO2 products, WSO2 Products impacted, customer action required,
    published), taken from the page's title, front matter, and REPORTED PRODUCTS list.
    """
    section = "security-announcements/cve-justifications"
    rows = []
    years = [name for name in os.listdir(os.path.join(docs_dir, section)) if re.match(r"^\d{4}$", name)]
    for year in years:
        root = os.path.join(docs_dir, section, year)
        for name in os.listdir(root):
            if not name.endswith(".md") or name == "index.md":
                continue
            with open(os.path.join(root, name), encoding="utf-8-sig") as handle:
                fields, body = text.front_matter(handle.read())
            title = fields.get("title") or name[:-3]
            products = ", ".join(text.product_names(text.sections(body).get("REPORTED PRODUCTS", "")))
            ids = text.unique(text.CVE_RE.findall(title)) or text.unique(
                re.findall(r"\b(?:GHSA(?:-[0-9a-z]{4}){3}|ZDI-[A-Z]+-\d+)\b", title)) or [title]
            for vuln_id in ids:
                rows.append((vuln_id, "{}/{}/{}".format(section, year, name[:-3]), products,
                             fields.get("wso2_products_impacted", ""), fields.get("customer_action_required", ""),
                             fields.get("published", "")))

    def order(row):
        cve = re.match(r"CVE-(\d{4})-(\d+)$", row[0])
        return (0, -int(cve.group(1)), -int(cve.group(2)), "") if cve else (1, 0, 0, row[0].lower())
    return sorted(rows, key=order)


def justification_table(docs_dir):
    """The CVE Justifications page's table of every justification, by CVE ID."""
    lines = ["| ID | WSO2 products | WSO2 Products impacted | Customer action required | Published |",
             "| -- | ------------- | ---------------------- | ------------------------ | --------- |"]
    for vuln_id, path, products, impacted, action, published in justification_rows(docs_dir):
        cells = ["[{}]({{{{#base_path#}}}}/{}/)".format(vuln_id, path), products, impacted, action,
                 published.replace(" ", "&nbsp;")]  # a date stays on one line
        lines.append("| " + " | ".join(cell.replace("|", "\\|") for cell in cells) + " |")
    return "\n".join(lines)


def year_pages(docs_dir, landing):
    """The year pages a section page lists, newest year first, as (year, page, label).

    A year is listed once its folder has its year page, so authors add a year in one place.
    """
    folder, page, label = YEAR_LISTS[landing]
    root = os.path.join(docs_dir, folder)
    years = sorted((name for name in os.listdir(root) if re.match(r"^\d{4}$", name)), reverse=True)
    return [(year, "{}/{}".format(folder, page.format(year)), label.format(year)) for year in years
            if os.path.isfile(os.path.join(root, page.format(year)))]

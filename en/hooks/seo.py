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

"""Search engine metadata for every page.

Derives a page-specific meta description, a search-friendly title for
advisories and CVE justifications, publication dates, and schema.org
structured data from the front matter and the standard section headings
the announcement templates use. theme/material/main.html and sitemap.xml
render the values. A `description` set in front matter always wins.

Also lists each year's advisories on its yearly list page and in its nav
section, from the files in the year folder, newest advisory ID first.

Must stay compatible with Python 3.8 (the WSO2 docs builder version).
"""

import html
import json
import os
import posixpath
import re
from datetime import date, datetime, timezone
from email.utils import format_datetime
from urllib.parse import urljoin
from xml.sax.saxutils import escape

ORGANIZATION = {
    "@type": "Organization",
    "name": "WSO2",
    "url": "https://wso2.com/",
}
DESCRIPTION_LIMIT = 300
TITLE_SUMMARY_LIMIT = 100
FEED_FILE = "feed.xml"
FEED_TITLE = "WSO2 Security Announcements"
FEED_LIMIT = 50
SEVERITIES = ("Critical", "High", "Medium", "Low", "Informative")

ADVISORY_RE = re.compile(r"^security-announcements/security-advisories/\d{4}/WSO2-[^/]+\.md$")
JUSTIFICATION_RE = re.compile(r"^security-announcements/cve-justifications/\d{4}/(?!index\.md$)[^/]+\.md$")
ADVISORY_YEAR_RE = re.compile(r"^security-announcements/security-advisories/(\d{4})/\d{4}-advisories\.md$")
ADVISORY_DIR = "security-announcements/security-advisories"
ADVISORY_FILE_RE = re.compile(r"^WSO2-\d{4}-\d{4}\.md$")
# Section pages that list their year pages: the year folder, the year page, and its label.
YEAR_LISTS = {
    "security-announcements/security-advisories/index.md":
        ("security-announcements/security-advisories", "{0}/{0}-advisories.md", "{0} Advisories"),
    "security-announcements/cve-justifications/index.md":
        ("security-announcements/cve-justifications", "{0}/index.md", "{0} CVE Justifications"),
    "security-announcements/incident-clarifications/index.md":
        ("security-announcements/incident-clarifications", "{0}/index.md", "{0} Incident Clarifications"),
}
# Where a section page lists its year pages. The build replaces this line.
YEAR_LIST_MARKER = "<!-- The build lists the year pages here, newest first. -->"
YEAR_LINK_RE = re.compile(r"^[*-][ \t]+\[[^\]]*\]\(\{\{#base_path#\}\}/security-announcements/"
                          r"(?:security-advisories|cve-justifications|incident-clarifications)/\d{4}/[^)]*\)[ \t]*\n?", re.M)
# A yearly list line for one advisory. The build writes these; check_content.py rejects hand-written ones.
ADVISORY_ENTRY_RE = re.compile(r"^[*-][ \t]+\[[^\]]*\]\([^)]*/security-advisories/\d{4}/WSO2-\d{4}-\d{4}/?\)[ \t]*$", re.M)
JUSTIFICATION_YEAR_RE = re.compile(r"^security-announcements/cve-justifications/(\d{4})/index\.md$")
INCIDENT_YEAR_RE = re.compile(r"^security-announcements/incident-clarifications/(\d{4})/index\.md$")
BULLETIN_YEAR_RE = re.compile(r"^security-announcements/cloud-security-bulletins/[^/]+/(\d{4})/index\.md$")
BULLETIN_RE = re.compile(r"^security-announcements/cloud-security-bulletins/[^/]+/\d{4}/(?!index\.md$)[^/]+\.md$")
INCIDENT_RE = re.compile(r"^security-announcements/incident-clarifications/\d{4}/(?!index\.md$)[^/]+\.md$")

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
DATE_RE = re.compile(r"\b(?:January|February|March|April|May|June|July|August|September|October|November|December) \d{1,2}, \d{4}\b")
VULN_ID_RE = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3})\b")
ADVISORY_ID_RE = re.compile(r"\bWSO2-\d{4}-\d{4}\b")
HEADING_RE = re.compile(r"^#{2,4}[ \t]+(.+?)[ \t]*$", re.M)
TABLE_ID_RE = re.compile(r"^\|[ \t]*([A-Z][A-Z0-9]*-\d{4}-[0-9A-Z]+)[ \t]*\|", re.M)
BULLET_RE = re.compile(r"^[*+-][ \t]+(.+)$", re.M)
VERSION_START_RE = re.compile(r"[\s:,(-]+(?:v(?:ersions?)?\.?\s*)?\d")
# Words an advisory title can drop from the OVERVIEW sentence without changing what it says.
_FOUND = r"(?:identified|detected|discovered|found|observed)"
_PLACE = r"(?=\s+(?:in|on|at|with|within|through|during|when|via|for|while|after|before|due)\b|$)"
TITLE_FILLER_RES = (
    re.compile(r"^It has been " + _FOUND + r" that\s+", re.I),
    re.compile(r"^(?:A|An)\s+(?=\S)", re.I),
    re.compile(r"\s+(?:has|have) been " + _FOUND + _PLACE, re.I),
    re.compile(r"\s+(?:is|are|was|were) " + _FOUND + _PLACE, re.I),
    re.compile(r"\s+exists?" + _PLACE, re.I),
)

# Announcement pages for the RSS feed, collected during the build.
_feed_items = []

# Paths of the pages written as `'': path` in `nav`. Such a page is its
# section's index, like an index.md.
_section_index_paths = set()


def on_config(config):
    _section_index_paths.clear()
    del _feed_items[:]
    _fill_advisory_nav(config.get("nav") or [], config["docs_dir"])
    _collect_section_indexes(config.get("nav") or [])
    return config


def _fill_advisory_nav(items, docs_dir):
    """Write the year sections of the advisories' nav section, one per year folder with a yearly list."""
    for item in items:
        if not isinstance(item, dict):
            continue
        for value in item.values():
            if not isinstance(value, list):
                continue
            if _nav_index(value) != ADVISORY_DIR + "/index.md":
                _fill_advisory_nav(value, docs_dir)
                continue
            # Year sections written by hand are dropped; check_content.py reports them.
            value[:] = [entry for entry in value if not (isinstance(entry, dict) and any(
                isinstance(v, list) and ADVISORY_YEAR_RE.match(_nav_index(v)) for v in entry.values()))]
            for year, list_page, label in year_pages(docs_dir, ADVISORY_DIR + "/index.md"):
                value.append({label: [{"": list_page}] + [
                    {advisory_id: "{}/{}/{}.md".format(ADVISORY_DIR, year, advisory_id)}
                    for advisory_id, _ in advisory_list(docs_dir, year)]})


def _nav_index(entries):
    """The page a nav section names as `'': path`, its index."""
    return next((v for entry in entries if isinstance(entry, dict)
                 for k, v in entry.items() if k == "" and isinstance(v, str)), "")


def on_page_read_source(page, config):
    """Write the generated lists: a year's advisories, and a section's year pages."""
    src = page.file.src_uri
    year = ADVISORY_YEAR_RE.match(src)
    if not year and src not in YEAR_LISTS:
        return None
    with open(page.file.abs_src_path, encoding="utf-8-sig") as handle:
        source = handle.read()
    if year:
        source = ADVISORY_ENTRY_RE.sub("", source)  # check_content.py reports these
        entries = [advisory_list_entry(year.group(1), advisory_id, label)
                   for advisory_id, label in advisory_list(config["docs_dir"], year.group(1))]
        return source.rstrip("\n") + "\n\n" + "\n".join(entries) + "\n"
    links = "\n".join("* [" + label + "]({{#base_path#}}/" + _page_path(list_page) + ")"
                      for _, list_page, label in year_pages(config["docs_dir"], src))
    source = YEAR_LINK_RE.sub("", source)  # check_content.py reports these
    if YEAR_LIST_MARKER in source:
        return source.replace(YEAR_LIST_MARKER, links, 1)
    return source.rstrip("\n") + "\n\n" + links + "\n"


def year_pages(docs_dir, landing):
    """The year pages a section page lists, newest year first, as (year, page, label).

    A year is listed once its folder has its year page, so authors add a year in one
    place. .github/scripts/check_content.py uses this too.
    """
    folder, page, label = YEAR_LISTS[landing]
    root = os.path.join(docs_dir, folder)
    years = sorted((name for name in os.listdir(root) if re.match(r"^\d{4}$", name)), reverse=True)
    return [(year, "{}/{}".format(folder, page.format(year)), label.format(year)) for year in years
            if os.path.isfile(os.path.join(root, page.format(year)))]


def _page_path(src):
    """The URL path of a page, as the site links it."""
    return src[:-len("index.md")] if src.endswith("index.md") else src[:-len(".md")] + "/"


def _collect_section_indexes(items):
    for item in items:
        if not isinstance(item, dict):
            continue
        for title, value in item.items():
            if title == "" and isinstance(value, str):
                _section_index_paths.add(value)
            elif isinstance(value, list):
                _collect_section_indexes(value)


def on_page_markdown(markdown, page, config, files):
    src = page.file.src_uri
    meta = page.meta
    sections = _sections(markdown)
    seo = {"type": "TechArticle", "og_type": "article"}

    if ADVISORY_RE.match(src):
        markdown = _with_info_block(markdown, meta)
        title, description, keywords = _advisory(page.file.name, meta, markdown, sections)
        markdown = _heading_with_cves(markdown, meta, [k for k in keywords if CVE_RE.fullmatch(k)])
        seo["feed"] = "Security Advisory"
    elif JUSTIFICATION_RE.match(src):
        markdown = _with_heading(markdown, meta)
        title, description, keywords = _justification(meta, markdown, sections)
        seo["feed"] = "CVE Justification"
    else:
        title, keywords = None, []
        description = _listing_description(src, page)
        if description:
            seo["type"], seo["og_type"] = "CollectionPage", "website"
        else:
            description = _first_paragraph(markdown)
        if BULLETIN_RE.match(src):
            keywords = _unique(TABLE_ID_RE.findall(sections.get("VULNERABILITIES ADDRESSED", "")))
            seo["feed"] = "Cloud Security Bulletin"
        elif INCIDENT_RE.match(src):
            markdown = _with_heading(markdown, meta)
            keywords = _unique(CVE_RE.findall(str(meta.get("title", ""))))
            seo["feed"] = "Incident Clarification"

    if page.is_homepage:
        seo["type"], seo["og_type"] = "WebSite", "website"

    if meta.get("seo_title"):
        title = str(meta["seo_title"])
    if title:
        seo["title"] = title
    if description and not meta.get("description"):
        meta["description"] = _truncate(description, DESCRIPTION_LIMIT)
    seo["keywords"] = keywords

    # The date readers see wins: search engines compare structured data with the page.
    # Some advisories moved their front matter date forward when revised, so that date
    # counts as a revision, as do an "Updated:" line and change log entries.
    front_matter_date = _iso_date(meta.get("published") or meta.get("date"))
    published = _iso_date(_doc_info(markdown, r"published")) or front_matter_date
    revised = [front_matter_date, _iso_date(meta.get("updated")), _iso_date(_doc_info(markdown, r"updated"))]
    revised += [_iso_date(d) for d in DATE_RE.findall(sections.get("CHANGE LOG", ""))]
    modified = max([d for d in revised + [published] if d], default=None)
    if published:
        seo["published"] = published
    if modified:
        seo["modified"] = modified

    meta["seo"] = seo
    return markdown


def on_env(env, config, files):
    """Date each yearly list by its newest entry, since that is when the list changes."""
    newest = {}
    for file in files.documentation_pages():
        seo = file.page.meta.get("seo") if file.page else None
        if seo and seo["type"] != "CollectionPage" and seo.get("published"):
            folder = posixpath.dirname(file.src_uri)
            newest[folder] = max(newest.get(folder, ""), seo["published"])
    for file in files.documentation_pages():
        seo = file.page.meta.get("seo") if file.page else None
        folder = posixpath.dirname(file.src_uri)
        if seo and seo["type"] == "CollectionPage" and not seo.get("modified") and folder in newest:
            seo["modified"] = newest[folder]
    return env


def on_page_context(context, page, config, nav):
    seo = page.meta.get("seo")
    if seo is None:
        return context

    site_url = config.get("site_url") or ""
    logo = urljoin(site_url, config["theme"]["favicon"])
    seo["image"] = logo
    url = page.canonical_url
    if page.is_homepage:
        headline = config["site_name"]
    else:
        headline = seo.get("title") or _page_title(page) or config["site_name"]
    seo["headline"] = headline
    if "noindex" in str(page.meta.get("robots", "")):
        return context
    if seo.get("feed") and seo.get("published"):
        _feed_items.append({
            "title": headline,
            "link": url,
            "description": page.meta.get("description", ""),
            "category": seo["feed"],
            "published": seo["published"],
        })

    graph = []
    if seo["type"] == "WebSite":
        organization = dict(ORGANIZATION)
        organization["logo"] = logo
        organization["sameAs"] = [
            item["link"] for item in config["extra"].get("social", []) if item.get("link")
        ]
        graph.append(organization)
        graph.append({
            "@type": "WebSite",
            "name": config["site_name"],
            "alternateName": "WSO2 Security Documentation",
            "url": site_url,
            "description": page.meta.get("description") or config.get("site_description"),
            "inLanguage": "en",
            "publisher": {"@type": "Organization", "name": ORGANIZATION["name"]},
        })
    else:
        node = {
            "@type": seo["type"],
            "headline": headline,
            "url": url,
            "mainEntityOfPage": url,
            "inLanguage": "en",
            "isPartOf": {"@type": "WebSite", "name": config["site_name"], "url": site_url},
            "author": ORGANIZATION,
            "publisher": dict(ORGANIZATION, logo={"@type": "ImageObject", "url": logo}),
        }
        if page.meta.get("description"):
            node["description"] = page.meta["description"]
        if seo.get("published"):
            node["datePublished"] = seo["published"]
        if seo.get("modified"):
            node["dateModified"] = seo["modified"]
        if seo["keywords"]:
            node["keywords"] = seo["keywords"]
            cves = [k for k in seo["keywords"] if CVE_RE.fullmatch(k)]
            if cves:
                node["about"] = [
                    {"@type": "Thing", "name": cve, "sameAs": "https://www.cve.org/CVERecord?id=" + cve}
                    for cve in cves
                ]
        graph.append(node)
        breadcrumbs = _breadcrumbs(page, site_url, headline)
        if breadcrumbs:
            graph.append(breadcrumbs)

    data = {"@context": "https://schema.org", "@graph": graph}
    # Escape "<" so the JSON cannot close or alter the surrounding <script> element.
    seo["jsonld"] = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("<", "\\u003c")
    return context


def on_post_build(config):
    """Write an RSS feed of the newest announcements next to the sitemap."""
    site_url = config.get("site_url") or ""
    items = sorted(_feed_items, key=lambda item: (item["published"], item["link"]), reverse=True)
    items = items[:FEED_LIMIT]
    entries = []
    for item in items:
        entries.append(
            "<item><title>{}</title><link>{}</link><guid isPermaLink=\"true\">{}</guid>"
            "<pubDate>{}</pubDate><category>{}</category><description>{}</description></item>".format(
                escape(item["title"]), escape(item["link"]), escape(item["link"]),
                _rfc822(item["published"]), escape(item["category"]), escape(item["description"])))
    feed = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom"><channel>'
        "<title>{title}</title><link>{link}</link>"
        '<atom:link href="{self}" rel="self" type="application/rss+xml"/>'
        "<description>{description}</description><language>en</language>"
        "{updated}{entries}</channel></rss>\n"
    ).format(
        title=escape(FEED_TITLE),
        link=escape(site_url),
        self=escape(urljoin(site_url, FEED_FILE)),
        description=escape("Security advisories, CVE justifications, incident clarifications, "
                           "and cloud security bulletins published by WSO2."),
        # The newest entry's date rather than the build time, so rebuilds are reproducible.
        updated="<lastBuildDate>{}</lastBuildDate>".format(_rfc822(items[0]["published"])) if items else "",
        entries="".join(entries),
    )
    with open(os.path.join(config["site_dir"], FEED_FILE), "w", encoding="utf-8") as handle:
        handle.write(feed)


def _advisory(name, meta, markdown, sections):
    # The file name is the advisory ID the URL, nav, and yearly list use.
    advisory_id = name if ADVISORY_ID_RE.fullmatch(name) else _first(ADVISORY_ID_RE, markdown)
    cves = advisory_cves(meta.get("title"), markdown, sections)
    products = _product_names(sections.get("AFFECTED PRODUCTS", ""))
    overview = _first_paragraph(sections.get("OVERVIEW", ""))
    summary, usable = title_summary(overview, drop_cves=bool(cves))

    if cves:
        lead = _join(cves[:3]) + (" and Others" if len(cves) > 3 else "")
    else:
        lead = advisory_id or str(meta.get("title") or "WSO2")
    if usable:
        title = "{}: {}".format(lead, summary)
    else:
        title = "{} Security Advisory for {}".format(lead, _product_phrase(products))
    if cves and advisory_id:
        title += " ({})".format(advisory_id)

    parts = [_sentence(overview)]
    if products:
        parts.append("Affects {}.".format(_product_list(products)))
    severity = _plain(str(meta.get("severity") or "")).capitalize()
    if severity not in SEVERITIES:
        severity = ""
    score = _cvss_score(meta.get("cvss"))
    if severity and score:
        parts.append("Severity: {} (CVSS {}).".format(severity, score))
    elif severity:
        parts.append("Severity: {}.".format(severity))
    description = "{}: {}".format(lead, " ".join(p for p in parts if p))

    keywords = cves + ([advisory_id] if advisory_id else []) + products
    return title, description, keywords


def advisory_cves(title, markdown, sections=None):
    """An advisory's CVE IDs: from its title, else its CVE IDs line, else its OVERVIEW."""
    cves = _unique(CVE_RE.findall(str(title or "")))
    if not cves:
        line = re.search(r"CVE IDs?:(.*)", markdown)
        cves = _unique(CVE_RE.findall(line.group(1))) if line else []
    if not cves:
        sections = _sections(markdown) if sections is None else sections
        cves = _unique(CVE_RE.findall(sections.get("OVERVIEW", "")))
    return cves


def advisory_list(docs_dir, year):
    """The advisories in a year folder as (advisory ID, list label) pairs, newest ID first.

    The build writes the yearly list and the year's nav entries from this, so authors
    add an advisory in one place: its file. The label carries the CVE IDs, as in
    "WSO2-2026-5328 (CVE-2026-5430)".
    """
    folder = os.path.join(docs_dir, ADVISORY_DIR, year)
    ids = [name[:-3] for name in os.listdir(folder) if ADVISORY_FILE_RE.match(name)] if os.path.isdir(folder) else []
    entries = []
    for advisory_id in sorted(ids, key=lambda i: (int(i[5:9]), int(i[10:])), reverse=True):
        with open(os.path.join(folder, advisory_id + ".md"), encoding="utf-8-sig") as handle:
            text = handle.read()
        front = re.match(r"\A---[ \t]*\n(.*?\n)---[ \t]*\n", text, re.S)
        title = re.search(r"^title:[ \t]*(.*)$", front.group(1), re.M) if front else None
        cves = advisory_cves(title.group(1) if title else "", text[front.end():] if front else text)
        entries.append((advisory_id, "{} ({})".format(advisory_id, ", ".join(cves)) if cves else advisory_id))
    return entries


def advisory_list_entry(year, advisory_id, label):
    """A yearly list line, linked the way every page links (markdownextradata fills base_path)."""
    return "* [" + label + "]({{#base_path#}}/" + ADVISORY_DIR + "/" + year + "/" + advisory_id + "/)"


def advisory_overview(markdown):
    """The first paragraph of an advisory's OVERVIEW section."""
    return _first_paragraph(_sections(markdown).get("OVERVIEW", ""))


def title_summary(overview, drop_cves=False):
    """The search title wording of an advisory's OVERVIEW, and whether the title can use it.

    The OVERVIEW's first sentence names the vulnerability. The title drops only words that
    add nothing to it ("A potential XSS vulnerability has been identified in X" becomes
    "Potential XSS vulnerability in X"), so it never says anything the page does not.
    Sentences that are still long, or that lean on the page ("the above-listed products"),
    give way to the product names. .github/scripts/check_content.py uses this function too.
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


def _with_info_block(markdown, meta):
    """Render an advisory's heading and info lines from its front matter.

    Authors fill Published, Updated, Version, Severity, CVSS, and the CVE IDs (in the
    title) once, in front matter. Pages that still write the info lines themselves are
    left as they are.
    """
    if 'class="doc-info"' in markdown:
        return markdown
    lines = []
    published = _display_date(meta.get("published"))
    updated = _display_date(meta.get("updated"))
    if published:
        lines.append(_info_line("Published", published))
    if updated:
        lines.append(_info_line("Updated", updated))
    for label, key in (("Version", "version"), ("Severity", "severity")):
        value = str(meta.get(key) or "").strip()
        if value:
            lines.append(_info_line(label, html.escape(value)))
    cvss = str(meta.get("cvss") or "").strip()
    if cvss:
        lines.append(_info_line("CVSS Score", _cvss_link(cvss)))
    cves = _unique(CVE_RE.findall(str(meta.get("title", ""))))
    if cves:
        links = ['<a href="https://www.cve.org/CVERecord?id={0}">{0}</a>'.format(cve) for cve in cves]
        lines.append(_info_line("CVE IDs", ", ".join(links)))
    block = "\n".join(lines) + "\n---\n" if lines else ""

    heading = _leading_heading(markdown)
    if heading:
        return markdown[:heading.end()] + "\n\n" + block + "\n" + markdown[heading.end():].lstrip("\n")
    title = str(meta.get("title") or "").strip()
    return "# {}\n\n{}\n{}".format(title, block, markdown.lstrip("\n"))


def _with_heading(markdown, meta):
    """Render a CVE justification's or incident clarification's heading from its title.

    Authors write the title once, in front matter. Pages that still start with their
    own heading are left as they are.
    """
    title = str(meta.get("title") or "").strip()
    if _leading_heading(markdown) or not title:
        return markdown
    return "# {}\n\n{}".format(title, markdown.lstrip("\n"))


def _leading_heading(markdown):
    """The page's H1 when it is the first line of the body.

    A "# ..." line further down may be a comment inside a code block, not a heading.
    """
    return re.match(r"\s*^#[ \t]+(.+?)[ \t]*$", markdown, re.M)


def _info_line(label, value):
    return '<p class="doc-info">{}: {}</p>'.format(label, value)


def _cvss_link(cvss):
    """Link a "score (CVSS:x.y/...)" value to the FIRST calculator, as the advisories do."""
    vector = re.search(r"\((CVSS:(\d\.\d)/[^)\s]+)\)", cvss)
    if not vector:
        return html.escape(cvss)
    version = vector.group(2).replace("4.0", "4-0")
    return '<a href="https://www.first.org/cvss/calculator/{}#{}">{}</a>'.format(
        version, vector.group(1), html.escape(cvss))


def _display_date(value):
    if isinstance(value, datetime):
        value = value.date()
    if isinstance(value, date):
        return "{:%B} {}, {}".format(value, value.day, value.year)
    return str(value or "").strip()


def _heading_with_cves(markdown, meta, cves):
    """Show an advisory's CVE IDs in its heading, as in "Security Advisory WSO2-2021-1738/CVE-2022-29464".

    Some advisories list their CVE only in the "CVE IDs:" line. The heading carries
    weight with search engines, so the build adds any CVE ID it is missing.
    """
    match = _leading_heading(markdown)
    if not cves or not match:
        return markdown
    heading = match.group(1)
    missing = [cve for cve in cves if cve not in heading]
    if not missing:
        return markdown
    updated = heading + (", " if CVE_RE.search(heading) else "/") + ", ".join(missing)
    if str(meta.get("title", "")).strip() == heading:
        meta["title"] = updated
    return markdown[:match.start(1)] + updated + markdown[match.end(1):]


def _justification(meta, markdown, sections):
    subject = str(meta.get("title") or "").strip() or (_page_heading(markdown) or "")
    vuln_ids = _unique(VULN_ID_RE.findall(subject))
    products = _product_names(sections.get("REPORTED PRODUCTS", ""))
    title = "{}: Impact on {}".format(subject, _product_phrase(products))

    parts = ["WSO2 analysis of {} in {}.".format(subject, _product_phrase(products, title_case=False))]
    impacted = _doc_info(markdown, r"products?\s+impacted")
    action = _doc_info(markdown, r"actions?\s+required")
    if impacted:
        parts.append("WSO2 products impacted: {}.".format(impacted))
    if action:
        parts.append("Customer action required: {}.".format(action))
    reported = _sentence(_first_paragraph(sections.get("REPORTED VULNERABILITY", "")))
    if reported:
        parts.append("Reported issue: " + reported)

    keywords = vuln_ids + products
    return title, " ".join(parts), keywords


def _listing_description(src, page):
    match = ADVISORY_YEAR_RE.match(src)
    if match:
        return ("Security advisories WSO2 published in {}, listed by WSO2 advisory ID "
                "and CVE ID.".format(match.group(1)))
    match = JUSTIFICATION_YEAR_RE.match(src)
    if match:
        return ("CVE justifications WSO2 published in {}: analyses of reported CVEs and whether "
                "they affect WSO2 products.".format(match.group(1)))
    match = INCIDENT_YEAR_RE.match(src)
    if match:
        return ("Incident clarifications WSO2 published in {}: the impact of publicly reported "
                "security incidents on WSO2 products and services.".format(match.group(1)))
    match = BULLETIN_YEAR_RE.match(src)
    if match:
        service = page.parent.parent.title if page.parent and page.parent.parent else "WSO2 cloud services"
        return ("{} security bulletins WSO2 published in {}, summarizing the vulnerabilities "
                "addressed in the service.".format(service, match.group(1)))
    return None


def _breadcrumbs(page, site_url, current_name):
    items = [{"name": "Home", "item": site_url}]
    for section in reversed(page.ancestors):
        index = _section_index(section)
        if index is None or index is page:
            continue
        items.append({"name": section.title, "item": index.canonical_url})
    items.append({"name": current_name})
    return {
        "@type": "BreadcrumbList",
        "itemListElement": [
            dict(item, **{"@type": "ListItem", "position": position})
            for position, item in enumerate(items, start=1)
        ],
    }


def _section_index(section):
    for child in section.children:
        if child.is_page and (child.is_index or child.file.src_uri in _section_index_paths):
            return child
    return None


def _sections(markdown):
    """Map each upper-cased H2-H4 heading to the text below it."""
    parts = HEADING_RE.split(markdown)
    sections = {}
    for index in range(1, len(parts), 2):
        key = re.sub(r"[\s:]+$", "", parts[index]).upper()
        sections.setdefault(key, parts[index + 1])
    return sections


def _product_names(text):
    names = []
    for bullet in BULLET_RE.findall(text):
        name = _plain(bullet)
        match = VERSION_START_RE.search(name)
        if match:
            name = name[:match.start()]
        name = name.strip(" :,-")
        if name.startswith("WSO2 ") and len(name) <= 70:
            names.append(name)
    return _unique(names)


def _product_phrase(products, title_case=True):
    if len(products) in (1, 2):
        return _join(products)
    if products:
        return "Multiple WSO2 Products" if title_case else "multiple WSO2 products"
    return "WSO2 Products" if title_case else "WSO2 products"


def _product_list(products):
    if len(products) <= 4:
        return _join(products)
    return "{}, and {} other products".format(", ".join(products[:3]), len(products) - 3)


def _join(items):
    if len(items) <= 2:
        return " and ".join(items)
    return "{}, and {}".format(", ".join(items[:-1]), items[-1])


def _first_paragraph(markdown):
    """First prose paragraph, skipping headings, HTML, rules, admonitions, tables and lists."""
    markdown = re.sub(r"^#.*$", "", markdown, flags=re.M)
    for block in re.split(r"\n[ \t]*\n", markdown):
        block = block.strip()
        if not block or block.startswith(("#", "<", "---", "___", "!!!", "???", "|", "{%", "[^")):
            continue
        if BULLET_RE.match(block) or re.match(r"^\d+\.\s", block):
            continue
        text = _plain(block)
        if len(text) >= 20:
            return text
    return ""


def _plain(markdown):
    text = re.sub(r"<!--.*?-->", " ", markdown, flags=re.S)
    text = re.sub(r"\[\^[^\]]+\]", "", text)
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"<((?:https?://|mailto:)?[^<>\s]+@[^<>\s]+|https?://[^<>\s]+)>", r"\1", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\{\{#?[^}]*#?\}\}", "", text)
    text = re.sub(r"(\*\*|__|`)", "", text)
    text = re.sub(r"(?<!\w)\*(?=\S)|(?<=\S)\*(?!\w)", "", text)
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def _sentence(text):
    text = text.strip()
    if text and text[-1] not in ".!?":
        text += "."
    return text


def _truncate(text, limit):
    if len(text) <= limit:
        return text
    cut = text[:limit - 3].rsplit(" ", 1)[0].rstrip(",;:")
    return cut + "..."


def _doc_info(markdown, label):
    match = re.search(r'class="doc-info">[^<]*?' + label + r'\s*:\s*([^<]+)<', markdown, re.I)
    if not match:
        return None
    value = match.group(1).strip().rstrip(".")
    return value[:1].upper() + value[1:]


def _rfc822(iso_date):
    day = datetime.strptime(iso_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return format_datetime(day)


def _cvss_score(value):
    match = re.match(r"\s*(\d+(?:\.\d+)?)", str(value or ""))
    return "{:.1f}".format(float(match.group(1))) if match else None


def _iso_date(value):
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if not value:
        return None
    try:
        return datetime.strptime(str(value).strip(), "%B %d, %Y").date().isoformat()
    except ValueError:
        return None


def _page_title(page):
    return page.meta.get("title") or page.title


def _page_heading(markdown):
    match = re.search(r"^#[ \t]+(.+?)[ \t]*$", markdown, re.M)
    return _plain(match.group(1)) if match else None


def _first(pattern, text):
    match = pattern.search(text)
    return match.group(0) if match else None


def _unique(items):
    seen = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen

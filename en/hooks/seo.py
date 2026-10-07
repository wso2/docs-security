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
advisories and CVE justifications, publication dates, schema.org structured
data, and an RSS feed from the front matter and the standard section headings
the announcement templates use. theme/material/main.html and sitemap.xml
render the values. A `description` set in front matter always wins.

Runs after announcements.py (see mkdocs.yml), so it sees each announcement's
rendered heading and info lines. Must stay compatible with Python 3.8 (the WSO2
docs builder version).
"""

import json
import os
import posixpath
import re
import sys
from datetime import datetime, timezone
from email.utils import format_datetime
from urllib.parse import urljoin
from xml.sax.saxutils import escape

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from security_announcements import formats, listings, text  # noqa: E402

ORGANIZATION = {
    "@type": "Organization",
    "name": "WSO2",
    "url": "https://wso2.com/",
}
DESCRIPTION_LIMIT = 300
FEED_FILE = "feed.xml"
FEED_TITLE = "WSO2 Security Announcements"
FEED_LIMIT = 50
SEVERITIES = ("Critical", "High", "Medium", "Low", "Informative")

# Announcement pages for the RSS feed, collected during the build.
_feed_items = []

# Paths of the pages written as `'': path` in `nav`. Such a page is its
# section's index, like an index.md.
_section_index_paths = set()


def on_config(config):
    _section_index_paths.clear()
    del _feed_items[:]
    _collect_section_indexes(config.get("nav") or [])
    return config


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
    sections = text.sections(markdown)
    seo = {"type": "TechArticle", "og_type": "article"}

    if formats.ADVISORY_RE.match(src):
        title, description, keywords = _advisory(page.file.name, meta, markdown, sections)
        seo["feed"] = "Security Advisory"
    elif formats.JUSTIFICATION_RE.match(src):
        title, description, keywords = _justification(meta, markdown, sections)
        seo["feed"] = "CVE Justification"
    else:
        title, keywords = None, []
        description = _listing_description(src, page)
        if description:
            seo["type"], seo["og_type"] = "CollectionPage", "website"
        else:
            description = text.first_paragraph(markdown)
        if formats.BULLETIN_RE.match(src):
            keywords = text.unique(text.TABLE_ID_RE.findall(sections.get("VULNERABILITIES ADDRESSED", "")))
            seo["feed"] = "Cloud Security Bulletin"
        elif formats.INCIDENT_RE.match(src):
            keywords = text.unique(text.CVE_RE.findall(str(meta.get("title", ""))))
            seo["feed"] = "Incident Clarification"

    if page.is_homepage:
        seo["type"], seo["og_type"] = "WebSite", "website"

    if meta.get("seo_title"):
        title = str(meta["seo_title"])
    if title:
        seo["title"] = title
    if description and not meta.get("description"):
        meta["description"] = text.truncate(description, DESCRIPTION_LIMIT)
    seo["keywords"] = keywords

    # The date readers see wins: search engines compare structured data with the page.
    # Some advisories moved their front matter date forward when revised, so that date
    # counts as a revision, as do an "Updated:" line and change log entries.
    front_matter_date = text.iso_date(meta.get("published") or meta.get("date"))
    published = text.iso_date(text.doc_info(markdown, r"published")) or front_matter_date
    revised = [front_matter_date, text.iso_date(meta.get("updated")), text.iso_date(text.doc_info(markdown, r"updated"))]
    revised += [text.iso_date(d) for d in text.DATE_RE.findall(sections.get("CHANGE LOG", ""))]
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
            cves = [k for k in seo["keywords"] if text.CVE_RE.fullmatch(k)]
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
    advisory_id = name if text.ADVISORY_ID_RE.fullmatch(name) else text.first(text.ADVISORY_ID_RE, markdown)
    cves = formats.advisory_cves(meta.get("title"), markdown, sections)
    products = text.product_names(sections.get("AFFECTED PRODUCTS", ""))
    overview = text.first_paragraph(sections.get("OVERVIEW", ""))
    summary, usable = formats.title_summary(overview, drop_cves=bool(cves))

    if cves:
        lead = text.join(cves[:3]) + (" and Others" if len(cves) > 3 else "")
    else:
        lead = advisory_id or str(meta.get("title") or "WSO2")
    if usable:
        title = "{}: {}".format(lead, summary)
    else:
        title = "{} Security Advisory for {}".format(lead, text.product_phrase(products))
    if cves and advisory_id:
        title += " ({})".format(advisory_id)

    parts = [text.sentence(overview)]
    if products:
        parts.append("Affects {}.".format(text.product_list(products)))
    severity = text.plain(str(meta.get("severity") or "")).capitalize()
    if severity not in SEVERITIES:
        severity = ""
    score = _cvss_score(meta.get("cvss"))
    if severity and score:
        parts.append("Severity: {} (CVSS {}).".format(severity, score))
    elif severity:
        parts.append("Severity: {}.".format(severity))
    description = "{}: {}".format(lead, " ".join(p for p in parts if p))

    cwes = ["CWE-" + cwe for cwe in text.unique(formats.CWE_ID_RE.findall(str(meta.get("cwe") or "")))]
    keywords = cves + ([advisory_id] if advisory_id else []) + cwes + products
    return title, description, keywords


def _justification(meta, markdown, sections):
    subject = str(meta.get("title") or "").strip() or (text.page_heading(markdown) or "")
    vuln_ids = text.unique(text.VULN_ID_RE.findall(subject))
    products = text.product_names(sections.get("REPORTED PRODUCTS", ""))
    title = "{}: Impact on {}".format(subject, text.product_phrase(products))

    parts = ["WSO2 analysis of {} in {}.".format(subject, text.product_phrase(products, title_case=False))]
    impacted = text.doc_info(markdown, r"products?\s+impacted")
    action = text.doc_info(markdown, r"actions?\s+required")
    if impacted:
        parts.append("WSO2 products impacted: {}.".format(impacted))
    if action:
        parts.append("Customer action required: {}.".format(action))
    reported = text.sentence(text.first_paragraph(sections.get("REPORTED VULNERABILITY", "")))
    if reported:
        parts.append("Reported issue: " + reported)

    keywords = vuln_ids + products
    return title, " ".join(parts), keywords


def _listing_description(src, page):
    match = listings.ADVISORY_YEAR_RE.match(src)
    if match:
        return ("Security advisories WSO2 published in {}, listed by WSO2 advisory ID "
                "and CVE ID.".format(match.group(1)))
    match = listings.JUSTIFICATION_YEAR_RE.match(src)
    if match:
        return ("CVE justifications WSO2 published in {}: analyses of reported CVEs and whether "
                "they affect WSO2 products.".format(match.group(1)))
    match = listings.INCIDENT_YEAR_RE.match(src)
    if match:
        return ("Incident clarifications WSO2 published in {}: the impact of publicly reported "
                "security incidents on WSO2 products and services.".format(match.group(1)))
    match = listings.BULLETIN_YEAR_RE.match(src)
    if match:
        service = page.parent.parent.title if page.parent and page.parent.parent else "WSO2 cloud services"
        return ("{} security bulletins WSO2 published in {}, summarizing the vulnerabilities "
                "addressed in the service.".format(service, match.group(1)))
    return None


def _breadcrumbs(page, site_url, current_name):
    items = [{"name": "Home", "item": site_url}]
    if not page.ancestors and page.file.src_uri.startswith("security-announcements/cve-justifications/") \
            and page.file.src_uri != listings.JUSTIFICATIONS_PAGE:
        # Not in the nav; the CVE Justifications page lists it.
        items.append({"name": "CVE Justifications", "item": urljoin(site_url, text.page_path(listings.JUSTIFICATIONS_PAGE))})
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


def _rfc822(iso_date):
    day = datetime.strptime(iso_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return format_datetime(day)


def _cvss_score(value):
    match = re.match(r"\s*(\d+(?:\.\d+)?)", str(value or ""))
    return "{:.1f}".format(float(match.group(1))) if match else None


def _page_title(page):
    return page.meta.get("title") or page.title

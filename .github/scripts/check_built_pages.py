#!/usr/bin/env python3
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

"""Fail when the built pages show search engines the menu instead of the page.

    menu-entries   the menu lists advisories or CVE justifications from a year
                   folder other than the page's own. Search engines then find
                   every advisory ID on every page and rank the wrong page for
                   it. The theme lists only the open section
                   (en/theme/material/partials/nav-item.html).
    nosnippet      a sidebar is not marked data-nosnippet
                   (en/theme/material/main.html), so search results can quote
                   menu or table of contents text instead of the page.
    unlisted       an announcement page is not linked from the page that lists
                   it: an advisory from its year's list, a CVE justification
                   from the CVE Justifications page, an incident clarification
                   or a cloud security bulletin from its year page. A page in
                   another folder, or an advisory file not named after its ID,
                   is published but never listed, so it fails too.
    llms-txt       llms.txt (en/hooks/seo.py) is missing, does not start with the
                   site name and description, or links to a page the site
                   does not have.
    latest-advisories  the home page does not list the newest advisories,
                   newest published first, as their structured data dates
                   them (en/hooks/security_announcements/listings.py,
                   latest_advisories). The home page link is how a new
                   advisory gets crawled soon after it is published.

Usage: check_built_pages.py <site-dir>
"""

import os
import posixpath
import re
import sys
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO_ROOT, "en", "hooks"))
from security_announcements import listings  # noqa: E402

# A page in a year folder of advisories or CVE justifications, and that year's list page.
ENTRY = re.compile(r"(?:^|/)(security-announcements/(?:security-advisories|cve-justifications)/\d{4})/([^/]+)(?:/|$)")
SIDEBARS = {"md-sidebar--primary": "menu", "md-sidebar--secondary": "table of contents"}
ADVISORY_ID = re.compile(r"WSO2-\d{4}-\d{4}")
PUBLISHED = re.compile(r'"datePublished":\s*"(\d{4}-\d{2}-\d{2})"')


class Sidebars(HTMLParser):
    """Collects the links in the menu and whether each sidebar is marked data-nosnippet."""

    def __init__(self):
        super().__init__()
        self.current = None
        self.depth = 0
        self.nosnippet = {}
        self.menu_links = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if self.current:
            if tag == "div":
                self.depth += 1
            elif tag == "a" and self.current == "menu" and attributes.get("href"):
                self.menu_links.append(attributes["href"])
            return
        if tag == "div":
            for css, name in SIDEBARS.items():
                if css in (attributes.get("class") or "").split():
                    self.current, self.depth = name, 1
                    self.nosnippet[name] = "data-nosnippet" in attributes

    def handle_endtag(self, tag):
        if self.current and tag == "div":
            self.depth -= 1
            if self.depth == 0:
                self.current = None


class LatestAdvisories(HTMLParser):
    """Collects the advisory IDs the home page's list of the newest advisories links to."""

    def __init__(self):
        super().__init__()
        self.depth = 0
        self.found = False
        self.ids = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if self.depth:
            if tag == "div":
                self.depth += 1
            match = ADVISORY_ID.search(attributes.get("href") or "") if tag == "a" else None
            if match:
                self.ids.append(match.group(0))
        elif tag == "div" and "latest-advisories" in (attributes.get("class") or "").split():
            self.depth, self.found = 1, True

    def handle_endtag(self, tag):
        if self.depth and tag == "div":
            self.depth -= 1


def newest_advisories(site_dir):
    """The IDs of the newest advisories, by the datePublished of their structured data."""
    advisories = []
    root = os.path.join(site_dir, "security-announcements", "security-advisories")
    for year in os.listdir(root) if os.path.isdir(root) else []:
        if not (re.fullmatch(r"\d{4}", year) and os.path.isdir(os.path.join(root, year))):
            continue
        for name in os.listdir(os.path.join(root, year)):
            page = os.path.join(root, year, name, "index.html")
            if not (ADVISORY_ID.fullmatch(name) and os.path.isfile(page)):
                continue
            with open(page, encoding="utf-8") as handle:
                published = PUBLISHED.search(handle.read())
            if published:
                advisories.append(((published.group(1), int(name[5:9]), int(name[10:])), name))
    return [name for _, name in sorted(advisories, reverse=True)[:listings.LATEST_ADVISORIES]]


def check_home_page(site_dir):
    """A problem message if the home page does not list the newest advisories, else None."""
    home = os.path.join(site_dir, "index.html")
    parser = LatestAdvisories()
    with open(home, encoding="utf-8") as handle:
        parser.feed(handle.read())
    newest = newest_advisories(site_dir)
    if not parser.found:
        return "index.html: the home page has no list of the newest advisories [latest-advisories]"
    if parser.ids != newest:
        return ("index.html: the home page lists {} as the newest advisories, but they are {} "
                "[latest-advisories]".format(", ".join(parser.ids) or "none", ", ".join(newest)))
    return None


# Each announcement section, and the list page (under security-announcements/) that links a page
# whose path below the section is the given parts, or None when the build does not list that folder.
LIST_PAGES = {
    "security-advisories": lambda parts: "security-advisories/{0}/{0}-advisories".format(parts[0])
    if len(parts) == 2 and re.fullmatch(r"\d{4}", parts[0]) and ADVISORY_ID.fullmatch(parts[1]) else None,
    "cve-justifications": lambda parts: "cve-justifications" if len(parts) == 2 and re.fullmatch(r"\d{4}", parts[0]) else None,
    "incident-clarifications": lambda parts: "incident-clarifications/" + parts[0]
    if len(parts) == 2 and re.fullmatch(r"\d{4}", parts[0]) else None,
    "cloud-security-bulletins": lambda parts: "cloud-security-bulletins/{}/{}".format(*parts[:2])
    if len(parts) == 3 and re.fullmatch(r"\d{4}", parts[1]) else None,
}


class ArticleLinks(HTMLParser):
    """Collects the links in a page's article, and whether the page is a redirect stub."""

    def __init__(self):
        super().__init__()
        self.inside = False
        self.links = []
        self.redirect = False

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "meta" and (attributes.get("http-equiv") or "").lower() == "refresh":
            self.redirect = True
        if tag == "article":
            self.inside = True
        elif tag == "a" and self.inside and attributes.get("href"):
            self.links.append(attributes["href"])

    def handle_endtag(self, tag):
        if tag == "article":
            self.inside = False


def read_page(site_dir, rel):
    parser = ArticleLinks()
    with open(os.path.join(site_dir, rel, "index.html"), encoding="utf-8") as handle:
        parser.feed(handle.read())
    return parser


def is_list_page(section, parts, folder):
    """The section's own page, its year pages, a bulletin product's page, and the yearly advisory lists.

    folder is the page's folder in the built site; a bulletin product's page has year folders below it.
    """
    year = bool(parts) and re.fullmatch(r"\d{4}", parts[-1 if section != "security-advisories" else 0]) is not None
    if not parts:
        return True
    if section == "security-advisories":
        return (len(parts) == 1 and year) or (len(parts) == 2 and parts[1] == "{}-advisories".format(parts[0]))
    if section == "cloud-security-bulletins":
        if len(parts) == 1:
            return any(re.fullmatch(r"\d{4}", name) for name in os.listdir(folder))
        return len(parts) == 2 and year
    return len(parts) == 1 and year


def check_listed(site_dir):
    """A problem message for each announcement page that the page listing it does not link."""
    problems, linked = [], {}
    root = os.path.join(site_dir, "security-announcements")
    for section, list_page in sorted(LIST_PAGES.items()):
        for folder, _, files in sorted(os.walk(os.path.join(root, section))):
            if "index.html" not in files:
                continue
            rel = os.path.relpath(folder, site_dir).replace(os.sep, "/")
            parts = rel.split("/")[2:]
            if is_list_page(section, parts, folder) or read_page(site_dir, rel).redirect:
                continue
            target = list_page(parts)
            if target is None:
                problems.append("{}/: the page is not in a folder the build lists; move it into its year folder, "
                                "named as the others are [unlisted]".format(rel))
                continue
            target = "security-announcements/" + target
            if target not in linked:
                if not os.path.isfile(os.path.join(site_dir, target, "index.html")):
                    linked[target] = None
                else:
                    links = set()
                    for href in read_page(site_dir, target).links:
                        path = unquote(urlsplit(href).path)
                        path = posixpath.normpath(posixpath.join("/" + target + "/", path) if not path.startswith("/")
                                                  else re.sub(r"^/[^/]+/[^/]+/", "/", path))
                        links.add(path.strip("/"))
                    linked[target] = links
            if linked[target] is None:
                problems.append("{}/: its list page {}/ does not exist [unlisted]".format(rel, target))
            elif rel not in linked[target]:
                problems.append("{}/: the page is not listed on {}/ [unlisted]".format(rel, target))
    return problems


def check_llms_txt(site_dir):
    """Problem messages for llms.txt: it exists, has the llmstxt.org header, and every link resolves."""
    path = os.path.join(site_dir, "llms.txt")
    if not os.path.isfile(path):
        return ["llms.txt: the build did not write it [llms-txt]"]
    with open(path, encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    problems = []
    if len(lines) < 3 or not lines[0].startswith("# ") or not lines[2].startswith("> "):
        problems.append("llms.txt: start with \"# <site name>\", a blank line, and \"> <description>\" [llms-txt]")
    for number, line in enumerate(lines, 1):
        for link in re.findall(r"\]\(([^)\s]+)\)", line):
            target = re.sub(r"^/[^/]+/[^/]+/", "", unquote(urlsplit(link).path)).strip("/")
            if not (os.path.isfile(os.path.join(site_dir, target, "index.html"))
                    or os.path.isfile(os.path.join(site_dir, target))):
                problems.append("llms.txt:{}: the link {} is not a page of the site [llms-txt]".format(number, link))
    return problems


def folder_and_entry(path):
    """The year folder and entry name of an advisory or CVE justification path, or None."""
    match = ENTRY.search(path)
    if not match:
        return None
    folder, name = match.groups()
    year = folder[-4:]
    if name in ("index.html", "{}-advisories".format(year)):
        return folder, None
    return folder, name


def main():
    if len(sys.argv) != 2:
        print(__doc__.strip().splitlines()[-1])
        return 2
    site_dir = os.path.abspath(sys.argv[1])

    problems = 0
    checked = 0
    for root, dirs, files in os.walk(site_dir):
        dirs.sort()
        for name in sorted(files):
            if not name.endswith(".html"):
                continue
            page = os.path.join(root, name)
            rel = os.path.relpath(page, site_dir).replace(os.sep, "/")
            parser = Sidebars()
            with open(page, encoding="utf-8") as handle:
                parser.feed(handle.read())
            if not parser.nosnippet:
                continue  # Redirect stubs and other pages without sidebars.
            checked += 1

            for sidebar, marked in sorted(parser.nosnippet.items()):
                if not marked:
                    print("{}: the {} is not marked data-nosnippet [nosnippet]".format(rel, sidebar))
                    problems += 1

            own = folder_and_entry(rel)
            own_folder = own[0] if own else None
            others = set()
            for link in parser.menu_links:
                parts = urlsplit(link)
                if parts.scheme or parts.netloc:
                    continue
                target = posixpath.normpath(posixpath.join(posixpath.dirname(rel), unquote(parts.path)))
                entry = folder_and_entry(target)
                if entry and entry[1] and entry[0] != own_folder:
                    others.add(target)
            if others:
                print("{}: the menu lists {} advisories or CVE justifications from other year folders, such as "
                      "{} [menu-entries]".format(rel, len(others), sorted(others)[0]))
                problems += 1

    for problem in check_listed(site_dir) + check_llms_txt(site_dir):
        print(problem)
        problems += 1

    home_page = check_home_page(site_dir)
    if home_page:
        print(home_page)
        problems += 1

    if problems:
        print("\n{} problem(s) in {} page(s).".format(problems, checked))
        return 1
    print("Checked {} page(s). The menu and sidebars are fine, every announcement is listed, llms.txt is valid, "
          "and the home page lists the newest advisories.".format(checked))
    return 0


if __name__ == "__main__":
    sys.exit(main())

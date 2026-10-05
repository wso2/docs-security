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

Usage: check_built_pages.py <site-dir>
"""

import os
import posixpath
import re
import sys
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

# A page in a year folder of advisories or CVE justifications, and that year's list page.
ENTRY = re.compile(r"(?:^|/)(security-announcements/(?:security-advisories|cve-justifications)/\d{4})/([^/]+)(?:/|$)")
SIDEBARS = {"md-sidebar--primary": "menu", "md-sidebar--secondary": "table of contents"}


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

    if problems:
        print("\n{} problem(s) in {} page(s).".format(problems, checked))
        return 1
    print("Checked {} page(s). The menu and sidebars are fine.".format(checked))
    return 0


if __name__ == "__main__":
    sys.exit(main())

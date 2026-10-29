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

"""Fail when a built page links to a page or file that the build does not contain.

The production server redirects missing URLs to a "page not found" page that
returns HTTP 200, so a crawler on the live site cannot see broken links. This
check runs against the `mkdocs build` output instead. Paths are compared case
sensitively, as the production server does. Absolute links to the site's own
host are checked the same way as root-relative ones.

Usage: check_internal_links.py <site-dir> [<site-url>]
"""

import os
import posixpath
import sys
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

DEFAULT_SITE_URL = "https://security.docs.wso2.com/en/latest/"
LINK_ATTRIBUTES = {"a": "href", "img": "src", "link": "href", "script": "src", "source": "src"}


class LinkCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        name = LINK_ATTRIBUTES.get(tag)
        if not name:
            return
        attributes = dict(attrs)
        if tag == "link" and attributes.get("rel") in ("canonical", "alternate"):
            return
        if attributes.get(name):
            self.links.append(attributes[name])


def exists_case_sensitive(site_dir, relative):
    current = site_dir
    for part in [p for p in relative.split("/") if p]:
        try:
            if part not in os.listdir(current):
                return False
        except (NotADirectoryError, FileNotFoundError):
            return False
        current = os.path.join(current, part)
    if os.path.isdir(current):
        return os.path.isfile(os.path.join(current, "index.html"))
    return True


def main():
    if len(sys.argv) not in (2, 3):
        print(__doc__.strip().splitlines()[-1])
        return 2
    site_dir = os.path.abspath(sys.argv[1])
    site = urlsplit(sys.argv[2] if len(sys.argv) == 3 else DEFAULT_SITE_URL)
    base_path = "/" + site.path.strip("/") + "/"

    broken = []
    for root, _, files in os.walk(site_dir):
        for name in files:
            if not name.endswith(".html"):
                continue
            page = os.path.join(root, name)
            page_dir = posixpath.dirname(os.path.relpath(page, site_dir).replace(os.sep, "/"))
            collector = LinkCollector()
            with open(page, encoding="utf-8") as handle:
                collector.feed(handle.read())
            for link in collector.links:
                parts = urlsplit(link)
                own_host = parts.scheme in ("http", "https") and parts.netloc == site.netloc
                if not own_host and (parts.scheme or parts.netloc):
                    continue
                if not parts.path:
                    continue
                path = unquote(parts.path)
                if path.startswith("/"):
                    if not path.startswith(base_path):
                        broken.append((page, link))
                        continue
                    target = posixpath.normpath(path[len(base_path):] or ".")
                else:
                    target = posixpath.normpath(posixpath.join(page_dir, path))
                if target == ".":
                    target = ""
                if target.startswith("..") or not exists_case_sensitive(site_dir, target):
                    broken.append((page, link))

    for page, link in sorted(set(broken)):
        print("{}: {}".format(os.path.relpath(page, site_dir), link))
    if broken:
        print("\n{} broken internal link(s).".format(len(set(broken))))
        return 1
    print("No broken internal links.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

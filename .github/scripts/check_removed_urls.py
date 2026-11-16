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

"""Fail when a pull request removes a URL that the site has on its base branch.

Search engines, CVE records, and other sites link to the pages of this site,
so a URL that the base branch publishes must still work after the pull
request: as the page, or as a redirect to where the page moved. The check
compares two builds of the site, the base branch's and the pull request's,
and reports every page of the base build, redirects included, that the pull
request's build does not have. To move or remove a page, add a redirect for
its old path to redirect_maps in en/mkdocs.yml.

Usage:

    python3 .github/scripts/check_removed_urls.py <base-site-dir> <site-dir>

Requires Python 3.8 or later and no third-party packages.
"""

import os
import sys


def pages(site_dir):
    """The HTML files of a built site, as paths relative to it."""
    found = set()
    for root, dirs, files in os.walk(site_dir):
        for name in files:
            if name.endswith(".html"):
                found.add(os.path.relpath(os.path.join(root, name), site_dir).replace(os.sep, "/"))
    return found


def url_path(page):
    """The URL path a built page is served at, such as security-reporting/abuse-report/."""
    return page[:-len("index.html")] if page.endswith("index.html") else page


def main():
    if len(sys.argv) != 3:
        print(__doc__.strip().splitlines()[-3].strip())
        return 2
    base_dir, site_dir = (os.path.abspath(path) for path in sys.argv[1:])
    for path in (base_dir, site_dir):
        if not os.path.isdir(path):
            print("{}: not a directory".format(path))
            return 2
    base = pages(base_dir)
    removed = sorted(base - pages(site_dir))
    for page in removed:
        print("{}: the base branch publishes this URL, and this pull request removes it. Keep the page, or add "
              "a redirect from its old Markdown file to redirect_maps in en/mkdocs.yml [removed-url]".format(
                  url_path(page) or "/"))
    if removed:
        print("\nThis pull request removes {} of the {} URLs the base branch publishes.".format(len(removed), len(base)))
        return 1
    print("Checked {} URL(s) the base branch publishes. Every one still works.".format(len(base)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

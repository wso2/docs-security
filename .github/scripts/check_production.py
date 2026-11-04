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

"""Check that the live site serves its pages and answers a missing page with 404.

    sitemap        sitemap.xml, llms.txt, or feed.xml does not load.
    page           a URL that sitemap.xml lists does not return 200.
    soft-404       a URL the site does not have returns 200 instead of 404.
                   Search engines then index the "page not found" page under
                   every mistyped or retired URL.

Usage:

    python3 .github/scripts/check_production.py [SITE_URL]

SITE_URL defaults to the site_url of en/mkdocs.yml. Needs network access.
Requires Python 3.8 or later and no third-party packages.
"""

import os
import re
import sys
import time
import urllib.error
import urllib.request
import uuid

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
USER_AGENT = "wso2-docs-security-site-check"
ATTEMPTS = 4
# The site rate-limits clients (HTTP 429), so pages are fetched one at a time with a pause.
PAUSE = 0.5
MAX_RETRY_AFTER = 120
FILES = ("sitemap.xml", "llms.txt", "feed.xml")


def site_url():
    """The site_url of en/mkdocs.yml."""
    with open(os.path.join(REPO_ROOT, "en", "mkdocs.yml"), encoding="utf-8") as handle:
        return re.search(r"^site_url:[ \t]*(\S+)", handle.read(), re.M).group(1)


def fetch(url):
    """(HTTP status, body) for a URL; status 0 when it cannot be reached.

    Network errors, server errors, and 429 responses are retried; a 429 waits as long as
    its Retry-After header asks, up to MAX_RETRY_AFTER seconds.
    """
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    status, body = 0, b""
    for attempt in range(1, ATTEMPTS + 1):
        wait = 5 * attempt
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            status, body = error.code, b""
            if error.code != 429 and error.code < 500:
                return status, body
            retry_after = (error.headers.get("Retry-After") or "").strip()
            if retry_after.isdigit():
                wait = min(int(retry_after), MAX_RETRY_AFTER)
        except (urllib.error.URLError, OSError) as error:
            status, body = 0, str(error).encode("utf-8")
        if attempt < ATTEMPTS:
            time.sleep(wait)
    return status, body


def main():
    if len(sys.argv) > 2:
        print(__doc__.strip().splitlines()[-4].strip())
        return 2
    base = (sys.argv[1] if len(sys.argv) == 2 else site_url()).rstrip("/") + "/"
    problems = []

    status, sitemap = fetch(base + "sitemap.xml")
    urls = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", sitemap.decode("utf-8", "replace")) if status == 200 else []
    for name in FILES:
        file_status = status if name == "sitemap.xml" else fetch(base + name)[0]
        if file_status != 200:
            problems.append("{}{}: returned {} [sitemap]".format(base, name, file_status or "no response"))
    if status == 200 and not urls:
        problems.append("{}sitemap.xml: lists no URLs [sitemap]".format(base))

    for url in urls:
        time.sleep(PAUSE)
        page_status = fetch(url)[0]
        if page_status != 200:
            problems.append("{}: returned {} [page]".format(url, page_status or "no response"))

    missing = "{}site-check-{}/".format(base, uuid.uuid4().hex)
    missing_status = fetch(missing)[0]
    if missing_status != 404:
        problems.append("{}: a page the site does not have returned {}, not 404 [soft-404]".format(
            missing, missing_status or "no response"))

    for problem in problems:
        print(problem)
    if problems:
        print("\nFound {} problem(s) on {}.".format(len(problems), base))
        return 1
    print("Checked {} on {}: the {} sitemap URLs return 200, and a missing page returns 404.".format(
        ", ".join(FILES), base, len(urls)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

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

"""Check that the CVE records WSO2 assigned link to pages this site has.

A CVE record's references are how readers of cve.org, NVD, and scanners reach
the advisory. For each CVE ID that a page of the site links (as
check_cve_links.py finds them), the script reads the CVE record from the CVE
Program's API and, when WSO2 assigned it, checks every reference to this site
against a build of it:

    missing-page   the record links a URL of this site that the build does
                   not have, as a page or a redirect. Correct the record's
                   reference, or add a redirect from that URL.

It also lists, without failing, the WSO2 records that link no page of this
site, such as records that still link a retired docs.wso2.com page.

Usage:

    python3 .github/scripts/check_cve_records.py <site-dir>

Build the site first (mkdocs build in en/). Needs network access. Requires
Python 3.8 or later and no third-party packages.
"""

import os
import re
import sys
from urllib.parse import unquote, urlsplit

import check_cve_links

REPO_ROOT = check_cve_links.REPO_ROOT
ASSIGNER = "WSO2"


def site_url():
    """The site_url of en/mkdocs.yml, such as https://security.docs.wso2.com/en/latest/."""
    with open(os.path.join(REPO_ROOT, "en", "mkdocs.yml"), encoding="utf-8") as handle:
        match = re.search(r"^site_url:[ \t]*(\S+)", handle.read(), re.M)
    return match.group(1).rstrip("/") + "/"


def linked_ids():
    """Every CVE ID a page of the site links, sorted."""
    ids = set()
    for path in check_cve_links.markdown_files([os.path.join(REPO_ROOT, "en", "docs")]):
        with open(path, encoding="utf-8", newline="") as handle:
            ids.update(cve_id for _, cve_id in check_cve_links.linked_cves(handle.read()))
    return sorted(ids)


def references(record):
    """The reference URLs of a CVE record's CNA container."""
    cna = record.get("containers", {}).get("cna", {})
    return [ref.get("url", "") for ref in cna.get("references", []) if ref.get("url")]


def built_file(site_dir, base, url):
    """The built file a URL of this site is served from, or None when the URL is not under base."""
    parts, root = urlsplit(url), urlsplit(base)
    if parts.netloc.lower() != root.netloc.lower() or not parts.path.startswith(root.path):
        return None
    rel = unquote(parts.path[len(root.path):])
    if not rel or rel.endswith("/"):
        rel += "index.html"
    elif not os.path.splitext(rel)[1]:
        rel += "/index.html"
    return os.path.join(site_dir, *rel.split("/"))


def main():
    if len(sys.argv) != 2:
        print(__doc__.strip().splitlines()[-4].strip())
        return 2
    site_dir = os.path.abspath(sys.argv[1])
    if not os.path.isdir(site_dir):
        print("{}: not a directory".format(site_dir))
        return 2
    base = site_url()
    host = urlsplit(base).netloc.lower()

    problems, unlinked, checked = [], [], 0
    for cve_id in linked_ids():
        try:
            record = check_cve_links.fetch_record(cve_id)
        except OSError as error:
            print(error)
            print("\nThe CVE Program's API could not be reached, so the CVE records were not checked. "
                  "Run the check again.")
            return 1
        if record is None or record.get("cveMetadata", {}).get("assignerShortName") != ASSIGNER:
            continue  # check_cve_links.py --published reports IDs with no record
        checked += 1
        ours = [url for url in references(record) if urlsplit(url).netloc.lower() == host]
        if not ours:
            unlinked.append(cve_id)
        for url in ours:
            path = built_file(site_dir, base, url)
            if path is not None and not os.path.isfile(path):
                problems.append("{}: the CVE record links {}, which the site does not have. Correct the "
                                "record's reference, or add a redirect from that URL [missing-page]".format(cve_id, url))

    for problem in problems:
        print(problem)
    if unlinked:
        print("\n{} WSO2 CVE record(s) link no page of this site: {}".format(len(unlinked), ", ".join(unlinked)))
    if problems:
        print("\nFound {} CVE record reference(s) to pages the site does not have, in the {} WSO2 CVE records "
              "the site links.".format(len(problems), checked))
        return 1
    print("\nChecked the {} WSO2 CVE records the site links. Every reference to this site works.".format(checked))
    return 0


if __name__ == "__main__":
    sys.exit(main())

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

"""Build the security announcements from their front matter and folders.

Renders each advisory's, CVE justification's, and incident clarification's heading
and info lines from front matter, and writes the lists and nav the authors no longer
maintain by hand: the yearly lists, the year sections of the nav, the year links on
the section pages, and the CVE Justifications table. The rules live in the
security_announcements package next to this file, which the content check uses too.

Listed before seo.py in mkdocs.yml, so the search metadata sees the rendered pages.
Must stay compatible with Python 3.8 (the WSO2 docs builder version).
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from security_announcements import formats, listings  # noqa: E402


def on_config(config):
    listings.fill_nav(config.get("nav") or [], config["docs_dir"])
    return config


def on_page_read_source(page, config):
    """Write the generated lists into the pages that show them."""
    src = page.file.src_uri
    if not (listings.ADVISORY_YEAR_RE.match(src) or listings.INCIDENT_YEAR_RE.match(src)
            or src in listings.YEAR_LISTS or src == listings.JUSTIFICATIONS_PAGE):
        return None
    with open(page.file.abs_src_path, encoding="utf-8-sig") as handle:
        return listings.generated_source(src, handle.read(), config["docs_dir"])


def on_page_markdown(markdown, page, config, files):
    return formats.render(page.file.src_uri, markdown, page.meta)

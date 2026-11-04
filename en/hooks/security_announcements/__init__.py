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

"""The security announcements' content model, shared by the build and the content check.

    text       Markdown and text helpers
    formats    the advisory, CVE justification, and incident clarification formats:
               their fields, rules, and how their headings and info lines render
    listings   the lists and nav the build writes from the files: year pages, the
               year sections of the nav, and the CVE Justifications table

The MkDocs hooks in en/hooks (announcements.py and seo.py) and
.github/scripts/check_content.py import it, so the build and the check apply the
same rules. Standard library only; must stay compatible with Python 3.8 (the WSO2
docs builder version).
"""

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

"""Markdown and text helpers for the announcement pages."""

import html
import re
from datetime import date, datetime

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
DATE_RE = re.compile(r"\b(?:January|February|March|April|May|June|July|August|September|October|November|December) \d{1,2}, \d{4}\b")
VULN_ID_RE = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3})\b")
ADVISORY_ID_RE = re.compile(r"\bWSO2-\d{4}-\d{4}\b")
HEADING_RE = re.compile(r"^#{2,4}[ \t]+(.+?)[ \t]*$", re.M)
TABLE_ID_RE = re.compile(r"^\|[ \t]*([A-Z][A-Z0-9]*-\d{4}-[0-9A-Z]+)[ \t]*\|", re.M)
BULLET_RE = re.compile(r"^[*+-][ \t]+(.+)$", re.M)
VERSION_START_RE = re.compile(r"[\s:,(-]+(?:v(?:ersions?)?\.?\s*)?\d")
FRONT_MATTER_RE = re.compile(r"\A---[ \t]*\n(.*?\n)---[ \t]*\n", re.S)


def front_matter(text):
    """A file's front matter fields as plain strings, quotes removed, and its body."""
    front = FRONT_MATTER_RE.match(text)
    if not front:
        return {}, text
    fields = dict(re.findall(r"^([A-Za-z0-9_]+):[ \t]*[\"']?(.*?)[\"']?[ \t]*$", front.group(1), re.M))
    return fields, text[front.end():]


def sections(markdown):
    """Map each upper-cased H2-H4 heading to the text below it."""
    parts = HEADING_RE.split(markdown)
    found = {}
    for index in range(1, len(parts), 2):
        key = re.sub(r"[\s:]+$", "", parts[index]).upper()
        found.setdefault(key, parts[index + 1])
    return found


def leading_heading(markdown):
    """The page's H1 when it is the first line of the body.

    A "# ..." line further down may be a comment inside a code block, not a heading.
    """
    return re.match(r"\s*^#[ \t]+(.+?)[ \t]*$", markdown, re.M)


def page_heading(markdown):
    match = re.search(r"^#[ \t]+(.+?)[ \t]*$", markdown, re.M)
    return plain(match.group(1)) if match else None


def product_names(text):
    """The WSO2 product names in a list of products, without their versions."""
    names = []
    for bullet in BULLET_RE.findall(text):
        name = plain(bullet)
        match = VERSION_START_RE.search(name)
        if match:
            name = name[:match.start()]
        name = name.strip(" :,-")
        if name.startswith("WSO2 ") and len(name) <= 70:
            names.append(name)
    return unique(names)


def product_phrase(products, title_case=True):
    if len(products) in (1, 2):
        return join(products)
    if products:
        return "Multiple WSO2 Products" if title_case else "multiple WSO2 products"
    return "WSO2 Products" if title_case else "WSO2 products"


def product_list(products):
    if len(products) <= 4:
        return join(products)
    return "{}, and {} other products".format(", ".join(products[:3]), len(products) - 3)


def join(items):
    if len(items) <= 2:
        return " and ".join(items)
    return "{}, and {}".format(", ".join(items[:-1]), items[-1])


def first_paragraph(markdown):
    """First prose paragraph, skipping headings, HTML, rules, admonitions, tables and lists."""
    markdown = re.sub(r"^#.*$", "", markdown, flags=re.M)
    for block in re.split(r"\n[ \t]*\n", markdown):
        block = block.strip()
        if not block or block.startswith(("#", "<", "---", "___", "!!!", "???", "|", "{%", "[^")):
            continue
        if BULLET_RE.match(block) or re.match(r"^\d+\.\s", block):
            continue
        text = plain(block)
        if len(text) >= 20:
            return text
    return ""


def plain(markdown):
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


def sentence(text):
    text = text.strip()
    if text and text[-1] not in ".!?":
        text += "."
    return text


def truncate(text, limit):
    if len(text) <= limit:
        return text
    cut = text[:limit - 3].rsplit(" ", 1)[0].rstrip(",;:")
    return cut + "..."


def doc_info(markdown, label):
    """The value of an info line ('<p class="doc-info">Label: value</p>') whose label matches."""
    match = re.search(r'class="doc-info">[^<]*?' + label + r'\s*:\s*([^<]+)<', markdown, re.I)
    if not match:
        return None
    value = match.group(1).strip().rstrip(".")
    return value[:1].upper() + value[1:]


def display_date(value):
    if isinstance(value, datetime):
        value = value.date()
    if isinstance(value, date):
        return "{:%B} {}, {}".format(value, value.day, value.year)
    return str(value or "").strip()


def iso_date(value):
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


def page_path(src):
    """The URL path of a page, as the site links it."""
    return src[:-len("index.md")] if src.endswith("index.md") else src[:-len(".md")] + "/"


def first(pattern, text):
    match = pattern.search(text)
    return match.group(0) if match else None


def unique(items):
    seen = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen

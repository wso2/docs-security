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

"""Check that dates in the documentation are written as "Month D, YYYY".

Accepted forms:

    September 15, 2026    full date
    September 15          month and day
    September 2026        month and year

Anything else that reads as a date is reported, including numeric dates
(2026-09-15, 09/15/2026), abbreviated months (Sep 15, 2026), zero-padded
days (September 05, 2026), ordinals (September 15th, 2026), day-first
dates (15 September 2026) and a missing comma (September 15 2026).

Code blocks, inline code, HTML tags, HTML comments and URLs are skipped,
as is any text between <!-- date-check: off --> and <!-- date-check: on -->.

Usage:

    python3 .github/scripts/check_date_format.py [--fix] [PATH ...]

PATH defaults to en/docs and .announcement-templates. With --fix, dates
that can be rewritten without guessing are corrected in place and the
rest are reported for a manual fix.

Requires Python 3.8 or later and no third-party packages.
"""

import argparse
import bisect
import collections
import datetime
import os
import re
import sys

MONTHS = (
    "January", "February", "March", "April", "May", "June", "July",
    "August", "September", "October", "November", "December",
)
ABBREVIATIONS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "jun": 6, "jul": 7,
    "aug": 8, "sep": 9, "sept": 9, "oct": 10, "nov": 11, "dec": 12,
}
EXAMPLE = "September 15, 2026"
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_PATHS = ("en/docs", ".announcement-templates")
SCRIPT = ".github/scripts/check_date_format.py"

# Month names. A period is allowed after an abbreviation only, so that a
# sentence ending in a full month name followed by a year is not matched.
_MONTH = (
    r"(?P<month>(?:January|February|March|April|May|June|July|August|"
    r"September|October|November|December)"
    r"|(?:Sept|Sep|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Oct|Nov|Dec)\.?)"
)
_SP = r"[ \t\u00a0]"
_DAY = r"(?P<day>\d{1,2})(?P<ord>st|nd|rd|th)?"
_YEAR = r"(?P<year>(?:19|20)\d{2})"
_COMMA = _SP + r"*," + _SP + r"*"

# Full dates, month first: September 15, 2026 / Sep 15 2026 / September 15th, 2026
FULL_MONTH_FIRST = re.compile(
    r"(?<!\w)" + _MONTH + r"(?:" + _COMMA + r"|" + _SP + r"+)" + _DAY
    + r"(?:" + _COMMA + r"|" + _SP + r"+)" + _YEAR + r"(?!\w)",
    re.IGNORECASE,
)
# Full dates, day first: 15 September 2026 / 15th of Sep, 2026
FULL_DAY_FIRST = re.compile(
    r"(?<![\w.:/-])" + _DAY + _SP + r"+(?P<of>of" + _SP + r"+)?" + _MONTH
    + r"(?:" + _COMMA + r"|" + _SP + r"+)" + _YEAR + r"(?!\w)",
    re.IGNORECASE,
)
# Month and year: September 2026 / Sep 2026 / September, 2026
MONTH_YEAR = re.compile(
    r"(?<!\w)" + _MONTH + r"(?:" + _COMMA + r"|" + _SP + r"+)" + _YEAR + r"(?!\w)",
    re.IGNORECASE,
)
# Month and day without a year. Matched case-sensitively, because words
# such as "may" are common in prose.
PARTIAL_MONTH_FIRST = re.compile(
    r"(?<!\w)" + _MONTH + _SP + r"+" + _DAY + r"(?!\w)(?![.:]\d)"
)
PARTIAL_DAY_FIRST = re.compile(
    r"(?<![\w.:/-])" + _DAY + _SP + r"+(?P<of>of" + _SP + r"+)?" + _MONTH + r"(?!\w)"
)
# Year first: 2026-09-15 / 2026/09/15, optionally followed by an ISO 8601 time.
# Dotted forms are left alone because they collide with calendar versions.
YEAR_FIRST = re.compile(
    r"(?<![\w./:-])" + _YEAR + r"(?P<sep>[-/])(?P<month_number>\d{1,2})(?P=sep)"
    r"(?P<day>\d{1,2})"
    r"(?P<time>T\d{1,2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?"
    r"(?![\w/-]|\.\d)"
)
# Day or month first: 15/09/2026 / 09-15-26 / 15.09.2026
NUMERIC = re.compile(
    r"(?<![\w./:-])(?P<first>\d{1,2})(?P<sep>[-/.])(?P<second>\d{1,2})(?P=sep)"
    r"(?P<year>\d{4}|\d{2})(?![\w/-]|\.\d)"
)
_TIME_AFTER = re.compile(_SP + r"+\d{1,2}:\d{2}")

# Regions that are not prose, blanked out before dates are matched.
FENCE = re.compile(r"[ \t]*(?:>[ \t]*)*(?P<fence>`{3,}|~{3,})")
DIRECTIVE = re.compile(r"<!--\s*date-check:\s*(off|on)\s*-->", re.IGNORECASE)
SKIPPED = (
    re.compile(r"<!--.*?-->", re.DOTALL),
    re.compile(r"<(pre|code)\b[^>]*>.*?</\1\s*>", re.DOTALL | re.IGNORECASE),
    re.compile(r"(?<!`)(`+)(?!`).+?(?<!`)\1(?!`)"),
    re.compile(r"\]\([^)\n]*\)"),
    re.compile(r"^[ \t]*\[(?!\^)[^\]\n]+\]:[ \t]*\S+", re.MULTILINE),
    re.compile(r"</?[A-Za-z][^<>]*>"),
    re.compile(r"(?:\b(?:https?|ftp)://|\bwww\.)[^\s<>\"')\]]+", re.IGNORECASE),
)

Finding = collections.namedtuple("Finding", "start end found replacement message")


def month_number(name):
    key = name.rstrip(".").lower()
    for number, full in enumerate(MONTHS, 1):
        if key == full.lower():
            return number
    return ABBREVIATIONS.get(key)


def is_valid(year, month, day):
    try:
        datetime.date(year, month, day)
    except ValueError:
        return False
    return True


def full_date(year, month, day):
    return "{} {}, {}".format(MONTHS[month - 1], day, year)


def suggest(found, expected, fixable=True):
    return (expected if fixable else None,
            '"{}" should be "{}"'.format(found, expected))


def check_month_first(match, found, text):
    month = month_number(match.group("month"))
    day, year = int(match.group("day")), int(match.group("year"))
    if not 1 <= day <= 31:
        return None
    if not is_valid(year, month, day):
        return None, '"{}" is not a valid date'.format(found)
    expected = full_date(year, month, day)
    return None if found == expected else suggest(found, expected)


def check_day_first(match, found, text):
    month = month_number(match.group("month"))
    day, year = int(match.group("day")), int(match.group("year"))
    if not 1 <= day <= 31:
        return None
    if not is_valid(year, month, day):
        return None, '"{}" is not a valid date'.format(found)
    # "the 15th of September 2026" needs rewording, not just reordering.
    fixable = not (match.group("ord") or match.group("of"))
    return suggest(found, full_date(year, month, day), fixable)


def check_month_year(match, found, text):
    expected = "{} {}".format(MONTHS[month_number(match.group("month")) - 1],
                              match.group("year"))
    return None if found == expected else suggest(found, expected)


def check_partial_month_first(match, found, text):
    month, day = month_number(match.group("month")), int(match.group("day"))
    if not 1 <= day <= 31:
        return None
    if not is_valid(2000, month, day):
        return None, '"{}" is not a valid date'.format(found)
    expected = "{} {}".format(MONTHS[month - 1], day)
    return None if found == expected else suggest(found, expected)


def check_partial_day_first(match, found, text):
    month, day = month_number(match.group("month")), int(match.group("day"))
    if not 1 <= day <= 31 or not is_valid(2000, month, day):
        return None
    return suggest(found, "{} {}".format(MONTHS[month - 1], day), fixable=False)


def check_year_first(match, found, text):
    year = int(match.group("year"))
    month, day = int(match.group("month_number")), int(match.group("day"))
    if not (1 <= month <= 12 and 1 <= day <= 31):
        return None
    if not is_valid(year, month, day):
        return None, '"{}" is not a valid date'.format(found)
    expected = full_date(year, month, day)
    if match.group("time") or _TIME_AFTER.match(text, match.end()):
        return None, '"{}" includes a time; write the date as "{}"'.format(found, expected)
    return suggest(found, expected)


def check_numeric(match, found, text):
    first, second = int(match.group("first")), int(match.group("second"))
    year_text = match.group("year")
    if match.group("sep") == "." and len(year_text) != 4:
        return None
    year = int(year_text) if len(year_text) == 4 else 2000 + int(year_text)
    if not 1900 <= year <= 2099:
        return None
    readings = []
    if first <= 12 and is_valid(year, first, second):
        readings.append(full_date(year, first, second))
    if second <= 12 and first != second and is_valid(year, second, first):
        readings.append(full_date(year, second, first))
    if not readings:
        return None
    if len(readings) == 2:
        return None, '"{}" is ambiguous; write "{}" or "{}"'.format(found, *readings)
    return suggest(found, readings[0], fixable=len(year_text) == 4)


CHECKS = (
    (FULL_MONTH_FIRST, check_month_first),
    (FULL_DAY_FIRST, check_day_first),
    (YEAR_FIRST, check_year_first),
    (NUMERIC, check_numeric),
    (MONTH_YEAR, check_month_year),
    (PARTIAL_MONTH_FIRST, check_partial_month_first),
    (PARTIAL_DAY_FIRST, check_partial_day_first),
)


def blank(chars, start, end):
    for i in range(start, end):
        if chars[i] not in "\r\n":
            chars[i] = " "


def fenced_blocks(text):
    spans, fence, start, offset = [], None, 0, 0
    for line in text.splitlines(True):
        match = FENCE.match(line)
        if match:
            marker, rest = match.group("fence"), line[match.end():]
            if fence is None:
                # A backtick in the info string makes it inline code, not a fence.
                if not (marker[0] == "`" and "`" in rest):
                    fence, start = marker, offset
            elif marker[0] == fence[0] and len(marker) >= len(fence) and not rest.strip():
                spans.append((start, offset + len(line)))
                fence = None
        offset += len(line)
    if fence is not None:
        spans.append((start, len(text)))
    return spans


def disabled_regions(text):
    spans, off = [], None
    for match in DIRECTIVE.finditer(text):
        if match.group(1).lower() == "off":
            if off is None:
                off = match.start()
        elif off is not None:
            spans.append((off, match.end()))
            off = None
    if off is not None:
        spans.append((off, len(text)))
    return spans


def prose_only(text):
    """Return text with everything that is not prose replaced by spaces."""
    chars = list(text)
    for spans in (fenced_blocks, disabled_regions):
        for start, end in spans("".join(chars)):
            blank(chars, start, end)
    for pattern in SKIPPED:
        for match in list(pattern.finditer("".join(chars))):
            blank(chars, match.start(), match.end())
    return "".join(chars)


def find_dates(text):
    prose = prose_only(text)
    candidates = []
    for priority, (pattern, check) in enumerate(CHECKS):
        for match in pattern.finditer(prose):
            candidates.append((match.start(), match.start() - match.end(), priority, match, check))
    candidates.sort(key=lambda candidate: candidate[:3])

    findings, taken_until = [], 0
    for start, _, _, match, check in candidates:
        found = text[match.start():match.end()]
        # Skip overlaps and matches that run into a blanked region.
        if start < taken_until or found != match.group(0):
            continue
        taken_until = match.end()
        result = check(match, found, prose)
        if result is not None:
            replacement, message = result
            findings.append(Finding(match.start(), match.end(), found, replacement, message))
    return findings


def apply_fixes(text, findings):
    for finding in sorted(findings, key=lambda f: f.start, reverse=True):
        if finding.replacement is not None:
            text = text[:finding.start] + finding.replacement + text[finding.end:]
    return text


def markdown_files(paths):
    for path in paths:
        if os.path.isfile(path):
            yield path
            continue
        for root, dirs, files in os.walk(path):
            dirs[:] = sorted(d for d in dirs if not d.startswith("."))
            for name in sorted(files):
                if name.endswith(".md"):
                    yield os.path.join(root, name)


def escape_annotation(value):
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def report(path, text, findings, github):
    line_starts = [0] + [m.end() for m in re.finditer(r"\n", text)]
    for finding in findings:
        line = bisect.bisect_right(line_starts, finding.start)
        column = finding.start - line_starts[line - 1] + 1
        print("{}:{}:{}: {}".format(path, line, column, finding.message))
        if github:
            print("::error file={},line={},col={},endColumn={},title=Date format::{}".format(
                path, line, column, column + len(finding.found),
                escape_annotation(finding.message)))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Check that dates are written as "Month D, YYYY" ({}).'.format(EXAMPLE))
    parser.add_argument("paths", nargs="*", metavar="PATH",
                        help="Markdown files or folders (default: {})".format(
                            ", ".join(DEFAULT_PATHS)))
    parser.add_argument("--fix", action="store_true",
                        help="rewrite the dates that can be fixed without guessing")
    args = parser.parse_args(argv)

    paths = args.paths or [os.path.relpath(os.path.join(REPO_ROOT, p)) for p in DEFAULT_PATHS]
    missing = [p for p in paths if not os.path.exists(p)]
    if missing:
        parser.error("path not found: {}".format(", ".join(missing)))

    github = os.environ.get("GITHUB_ACTIONS") == "true"
    checked = fixed = fixed_files = remaining = remaining_files = fixable = 0
    for path in markdown_files(paths):
        with open(path, encoding="utf-8", newline="") as handle:
            text = handle.read()
        checked += 1
        findings = find_dates(text)
        if args.fix and any(f.replacement is not None for f in findings):
            new_text = apply_fixes(text, findings)
            with open(path, "w", encoding="utf-8", newline="") as handle:
                handle.write(new_text)
            fixed += sum(1 for f in findings if f.replacement is not None)
            fixed_files += 1
            text, findings = new_text, find_dates(new_text)
        if findings:
            report(path, text, findings, github)
            remaining += len(findings)
            remaining_files += 1
            fixable += sum(1 for f in findings if f.replacement is not None)

    if args.fix:
        print("Fixed {} date(s) in {} file(s).".format(fixed, fixed_files))
    if not remaining:
        print('Checked {} file(s). All dates use the "Month D, YYYY" format.'.format(checked))
        return 0
    print('\nFound {} date(s) in {} file(s) that do not use the "Month D, YYYY" format ({}).'.format(
        remaining, remaining_files, EXAMPLE))
    if fixable:
        print('Run "python3 {} --fix" to correct {} of them.'.format(SCRIPT, fixable))
    if remaining - fixable:
        print("Fix {} by hand.".format(remaining - fixable))
    return 1


if __name__ == "__main__":
    sys.exit(main())

# WSO2 Security & Compliance Documentation
---

To see the **latest released documentation** for the WSO2 Security & Compliance Documentation, go to: [https://security.docs.wso2.com/en/latest/](https://security.docs.wso2.com/en/latest/)

## Run the project locally

### Step 1 - Install Python

This project requires **Python 3.8.0**. You can verify the version installed on your machine by running the following command.

```shell
$ python3 --version
Python 3.8.0
```

If Python 3.8.0 is not installed, download it from [python.org/downloads](https://www.python.org/downloads/) or use your platform's package manager. The pinned dependencies support Python 3.8 to 3.12; Python 3.13 and later are not yet supported.

### Step 2 - Install Pip
>
> **INFO**
>
> Python 3.8.0 includes pip by default. If pip is missing, download `get-pip.py` and run the following command to install it:
> ```shell
> $ python3 get-pip.py
> ```
>

Pip is most likely installed by default. However, you may need to upgrade pip to the latest version:

```shell
$ pip3 install --upgrade pip
```

### Step 3 - Install the pip packages

1. Navigate to the `<language-folder>/` folder.

    ```shell
    $ cd docs-security/en
    ```

2. Install the required pip packages.

    This will install MkDocs and the required theme, extensions, and plugins.

    ```shell
    $ pip3 install -r requirements.txt
    ```

### Step 4 - Run MkDocs

Follow the steps below to clone the Security & Compliance documentation GitHub repository and to run the site on your local server.

1. Fork the GitHub repository: `https://github.com/wso2/docs-security.git`
2. Navigate to the place where you want to clone the repo.

    Git clone the forked repository.

    ```shell
    $ git clone https://github.com/[git-username]/docs-security.git
    ```

3. Navigate to the folder containing the repo that you cloned in step 4.1 on a terminal window.

    For example:

    ```shell
    $ cd docs-security/<Language-folder>/
    ```

    ```shell
    $ cd docs-security/en/
    ```

4. Run the following command to start the server and view the site on your local server.

    ```shell
    $ mkdocs serve
    ```

    > **NOTE:**
    >
    > If you are making changes and want to see them on the fly, run the following command to start the server and view the site on your local server.
    > 1. Navigate to the `mkdocs.yml` file.
    > 2. Change the following configuration to `false` as shown below. 
    >     ```
    >     #Breaks build if there's a warning
    >     strict: false
    >     ```
    > 3. Run the following command to start the server and to make the server load only the changed items and display the changes faster. 
    >
    >    `mkdocs serve --dirtyreload`
  
5. Open the following URL on a new browser window to view the WSO2 Security & Compliance documentation site locally.

    [http://localhost:8000/](http://localhost:8000/)

> **NOTE:**
>
> If you were running the `mkdocs serve --dirtyreload` command to run the MkDocs server, make sure to change the configuration in the `mkdocs.yml` file as follows before sending a pull request.
>
> `strict: true` 

## Date format

Write every date as `Month D, YYYY`, for example `September 15, 2026`. This applies to front matter fields such as `published`, `updated`, and `date`, to the `Published` and `Updated` lines, and to dates in the page body.

* Spell out the month.
* Do not zero-pad the day. Write `July 4, 2026`, not `July 04, 2026`.
* Do not use ordinals or numeric dates, such as `4th`, `2026-09-15`, or `09/15/2026`.

Write `September 15` when the year is clear from context, and `September 2026` when the day is not needed.

A pull request check fails when a Markdown file that the pull request adds or changes contains a date in any other format. To check all files locally, run the following command from the repository root:

```shell
$ python3 .github/scripts/check_date_format.py
```

Add `--fix` to correct the dates that can be converted without guessing. The check lists the rest, such as ambiguous numeric dates, for a manual fix.

The check skips code blocks, inline code, and URLs. To keep a date in another format on purpose, such as in a quoted HTTP header, put it in inline code or between `<!-- date-check: off -->` and `<!-- date-check: on -->`.

## CVE links

Link to a CVE record on the CVE Program's site, in this form:

```
https://www.cve.org/CVERecord?id=CVE-2026-5430
```

Do not link CVE IDs to NVD, CVE Details, the old MITRE CVE site, or other vulnerability directories. Links to vendor or researcher advisories, such as an Apache or Spring security page, are fine.

A pull request check fails when a Markdown file that the pull request adds or changes links a CVE record anywhere else. To check all files locally, run the following command from the repository root:

```shell
$ python3 .github/scripts/check_cve_links.py
```

Add `--fix` to rewrite the links. When the text cites something that only another site shows, such as NVD's own CVSS score, add `<!-- cve-link-check: allow -->` to the end of the line that holds the link.

## Content checks

Write each value once. For a security advisory, fill in the front matter from the template in `.announcement-templates`: `title` (with the CVE ID), `published`, `updated`, `version`, `severity`, `cvss`, and `cwe`. Do not add a heading or the Published, Version, Severity, CVSS Score, CVE IDs, and CWE lines to the page; the build renders them from front matter.

Use these forms:

* `version`: `1.0.0`
* `severity`: `Critical`, `High`, `Medium`, `Low`, `Informative`, or `Not Applicable`
* `cvss`: `9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)` or `Not Applicable`. The score must be the base score of the vector.
* `severity` must match the CVSS rating of the score: Low for 0.1 to 3.9, Medium for 4.0 to 6.9, High for 7.0 to 8.9, and Critical for 9.0 to 10.0.
* `cwe`: `CWE-79`, or `CWE-79, CWE-352` for several, as the advisory's CVE record gives them. Leave the field out when the advisory has no CVE record or the record names no CWE.
* CVE justifications: `published`, not `date`

Start each line of AFFECTED PRODUCTS (and of a CVE justification's REPORTED PRODUCTS) with an official product name from `en/hooks/security_announcements/products.txt`, such as `* WSO2 API Manager: 4.6.0, 4.5.0`. Write product names that way everywhere else in a page too, such as in update-level tables and in the text. The content check rejects an old spelling listed in that file, or a name in other upper and lower case, outside code. To add a new product, add its name to that file on a line of its own. An old or wrong spelling that `--fix` should correct goes there too, as `old spelling -> official name`.

Start the OVERVIEW with one sentence of up to 100 characters that names the vulnerability type, the component, and the product, such as "Reflected Cross-Site Scripting (XSS) vulnerability in the Management Console of WSO2 API Manager." The search title uses this sentence. Words such as "A potential" and "has been identified" are dropped from the title and do not count. Name the component or product instead of writing "the above-listed products".

List the fixed versions in the SOLUTION table, one row per product version, under the header `Product Name | Product Version | U2 Update Level`: the official product name (not a product code such as `wso2am`), a version such as `4.2.0`, and the update level as a whole number. Put any note about a row in the text, not in the table. From 2021 on, every table in SOLUTION must be this table.

Use the template's section headings: AFFECTED PRODUCTS, OVERVIEW, DESCRIPTION, IMPACT, and SOLUTION (all required), and NOTE, CREDITS, CHANGE LOG, and REFERENCES where needed, each once. A misspelled section would skip the product and table checks, so the check rejects it.

Name the advisory file after its ID, such as `WSO2-2026-5328.md`, use the same ID in the title, and put the file in the folder of the year it is published, such as `security-advisories/2026/`. Do not add the advisory to the yearly list or the `nav` in `en/mkdocs.yml`: the build lists every advisory in its year folder, newest advisory ID first, as `WSO2-2026-5328 (CVE-2026-5430)` with the CVE IDs from the title. For the first advisory of a new year, add the year's list page (copy last year's and change the year). The build adds the year to the `nav` and to the Security Advisories page.

A CVE justification and an incident clarification each have their own format. Start from the template in `.announcement-templates`, and write each value once, in front matter. Do not add a heading or info lines to the page; the build renders the heading from the title and the info lines from these fields, in this order:

| CVE justification field | Shown as | Required | Values |
| ----------------------- | -------- | -------- | ------ |
| `published` | Published | Yes | `Month D, YYYY` |
| `updated` | Updated | No | `Month D, YYYY`, only when the page is revised |
| `wso2_products_impacted` | WSO2 Products impacted | Yes | `"Yes"`, `"No"`, or `"Limited"` |
| `severity` | WSO2 Products severity | No | As for advisories |
| `cvss` | WSO2 Products CVSS score | No | As for advisories |
| `customer_action_required` | Customer action required | Yes | `"Yes"` or `"No"` |

| Incident clarification field | Shown as | Required | Values |
| ---------------------------- | -------- | -------- | ------ |
| `published` | Published | Yes | `Month D, YYYY` |
| `updated` | Updated | No | `Month D, YYYY`, only when the page is revised |
| `version` | Version | No | `1.0.0` |
| `wso2_impacted` | WSO2 impacted | Yes | `"Yes"` or `"No"` |
| `evidence_of_compromise` | Evidence of compromise | Yes | `"Yes"` or `"No"` |
| `customers_impacted` | Customers impacted | No | `"Yes"` or `"No"` |
| `customer_action_required` | Customer action required | Yes | `"Yes"` or `"No"` |

A Yes or No value may end with a short note in parentheses, such as `"No (transitive dependency)"`. Put Yes and No values in quotes: YAML reads a bare `No` as false. Start the file with the front matter's `---` line, because MkDocs ignores front matter that follows a blank line. A CVE justification goes in the folder of the year it is published; an incident clarification goes in the folder of the year of the incident.

Do not list a CVE justification yourself: the CVE Justifications page lists every justification by CVE ID, with its products and status, and justifications are not in the `nav`. Do not add an incident clarification to its year page or the `nav` either: the build lists every incident in its year folder, newest published first, under its title. For a new year of incidents, add the year page (copy last year's and change the year); the build adds it to the `nav` and to the Incident Clarifications page. Cloud security bulletins are listed by hand.

Write an announcement's sections as `##` headings and their parts as `###`, as the templates do. The build renders the page heading (H1) from the title, and a heading must not skip a level.

A pull request check fails when a Markdown file that the pull request adds or changes has one of these problems, or an entry the build lists (an advisory, CVE justification, or incident clarification on its year page or in the `nav`, a year section, or a section page's year link) added by hand, a CVE justification or incident clarification field that is missing or not in its form, a product name that is not on the official list, an OVERVIEW sentence that the search title cannot use, a table row with more or fewer cells than its header, a table that is not in its form (cells padded to their column's width, or one space around each cell when a padded row would be wider than 120 characters), a heading that skips a level, an advisory section heading that is not the template's (or a missing or repeated section), a `cwe` value or an update-level table that is not in its form, a leftover template placeholder, an empty link, a link to a retired `docs.wso2.com/display/` page, a `{{#base_path#}}` page link without a trailing slash, or an image without alt text. To check all files locally, run the following command from the repository root:

```shell
$ python3 .github/scripts/check_content.py
```

Add `--fix` to correct the problems that can be fixed without guessing, such as formatting tables. When the check fails in a pull request, its log also shows the changes `--fix` would make. Known problems that are waiting for a decision are listed in `.github/scripts/content_check_baseline.txt`, with how many each page has when there is more than one. A page with more problems than its line allows fails, so a pull request cannot add a new problem to a listed page. Lower the count, or remove the line, when you fix a problem.

## Build checks

The pull request build runs two checks on the built site:

* `check_internal_links.py` fails on links to pages or files that the build does not contain.
* `check_built_pages.py` fails when a page's menu lists advisories or CVE justifications from other year folders, or when a sidebar is not marked `data-nosnippet`. Search engines index the menu on every page, so the theme lists only the open section and keeps the sidebars out of search result snippets. It also fails when an announcement page is not linked from the page that lists it (an advisory from its year's list, a CVE justification from the CVE Justifications page, an incident clarification or a cloud security bulletin from its year page), which catches a file in the wrong folder, an advisory file not named after its ID, and a bulletin missing from its hand-kept year page. And it fails when the home page does not list the 10 newest advisories, newest published first: a link from the home page gets a new advisory crawled soon after it is published.

To run them locally, build the site and run the following commands from the repository root:

```shell
$ python3 .github/scripts/check_internal_links.py en/site
$ python3 .github/scripts/check_built_pages.py en/site
```

## How the build works

Two MkDocs hooks in `en/hooks` run on every build, in the order `en/mkdocs.yml` lists them:

* `announcements.py` renders each security advisory, CVE justification, and incident clarification from its front matter (the heading and the info lines) and writes the lists that are not maintained by hand: the yearly lists, the year sections of the `nav`, the year links on the section pages, the CVE Justifications table, and the newest advisories on the home page.
* `seo.py` adds search metadata: titles, descriptions, dates, structured data, and the RSS feed.

The rules both hooks follow live in `en/hooks/security_announcements`: `formats.py` defines the three formats and their fields, `listings.py` the generated lists, and `text.py` the shared helpers. `check_content.py` imports the same package, so a change to a format there changes the build and the pull request check together. The package uses only the Python standard library and must stay compatible with Python 3.8.

## License

Licenses this source under the Apache License, Version 2.0 ([LICENSE](LICENSE)), You may not use this file except in compliance with the License.

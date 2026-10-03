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

## License

Licenses this source under the Apache License, Version 2.0 ([LICENSE](LICENSE)), You may not use this file except in compliance with the License.

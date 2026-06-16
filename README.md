# WSO2 Security & Compliance Documentation
---

To see the **latest released documentation** for the WSO2 Security & Compliance Documentation, go to: [https://security.docs.wso2.com/en/latest/](https://security.docs.wso2.com/en/latest/)

## Run the project locally

### Step 1 - Install Python

This project requires **Python 3.12**. You can verify the version installed on your machine by running the following command.

```shell
$ python3 --version
Python 3.12.x
```

If Python 3.12 is not installed, follow the instructions in [this guide](https://docs.python-guide.org/starting/install3/osx/) to install it. Newer releases (Python 3.13 and above) are not yet supported by the pinned dependencies in `requirements.txt`.

### Step 2 - Install Pip
>
> **INFO**
>
> Python 3.12 includes pip by default. If pip is missing, download `get-pip.py` and run the following command to install it:
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

## License

Licenses this source under the Apache License, Version 2.0 ([LICENSE](LICENSE)), You may not use this file except in compliance with the License.

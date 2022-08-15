---
title: Static Code Analysis using FindSecurityBugs
category: security-guidelines
published: October 22, 2018
version: 1.2
---

# Static Code Analysis using FindSecurityBugs

<p class="doc-info">Published: October 22, 2017</p>
<p class="doc-info">Version: 1.2</p>
---

## Revision History

| Version | Release Date    | Contributors / Authosr | Summary of Changes  |
|---------|-----------------|------------------------|---------------------|
| 1.2     | April 25, 2017  | [Ayoma Wijethunga](http://wso2.com/about/team/ayoma-wijethunga)      | Formatting Changes  |
| 1.1     | December 16, 2016   | [Prakhash Sivakumar](http://wso2.com/about/team/prakhash-sivakumar/)     | Minor wording correction |
| 1.0     | June 28, 2016   | [Tharindu Edirisinghe](http://wso2.com/about/team/tharindu-edirisinghe)   | Initial version     |


## Introduction
This document provides details of all necessary steps for configuring FindBugs[^1] and Find Security Bugs[^2] for scanning source code in order to discover security threats. 


## Installation - IntelliJ Idea - FindBugs Plugin
Once you open IntelliJ IDEA, you can go to **Configure** &rarr; **Plugins** in the opening window.

![Placeholder](/assets/images/secure-coding-guidelines/fsb-01.png){ .post-image }

If you have already opened a project in IntelliJ IDEA, you can go to **File** &rarr; **Settings** and in the left panel of the Settings window, select Plugins.

![Placeholder](/assets/images/secure-coding-guidelines/fsb-02.png){ .post-image }

You can install the FindBugs plugin in two ways. If you have an internet connection, you can click on the **Browser repositories** button and get the plugin installed. If not you can download the FindBugs plugin for IntelliJ IDEA[^3] and go with the **Install plugin from disk** option where you can browse and provide the already downloaded plugin.

When you go with the **Browse repositories** option, you can search for the findbugs plugin and select **FindBugs-IDEA** and get it installed.

![Placeholder](/assets/images/secure-coding-guidelines/fsb-03.png){ .post-image }


## Installation - IntelliJ Idea - Find Security Bug Plugin
Once you have installed the FindBugs plugin in IntelliJ IDEA, in the bottom of the IDE you will see the **FindBugs-IDEA** button. Upon clicking on it you can see all the settings of it, in a panel.  

![Placeholder](/assets/images/secure-coding-guidelines/fsb-04.png){ .post-image }

Now we have to enable the **FindSecurityBugs** plugin which comes with FindBugs. This is for finding the security bugs in your code. Click on the **Plugin Preferences** button.

![Placeholder](/assets/images/secure-coding-guidelines/fsb-05.png){ .post-image }

Under the **Plugins** section of the **General** tab, click on the **+** button and select **Add Find Security Bugs**.

![Placeholder](/assets/images/secure-coding-guidelines/fsb-06.png){ .post-image }

Once the FindSecurityBugs plugin is added, click on **Apply** and then **OK**.

![Placeholder](/assets/images/secure-coding-guidelines/fsb-07.png){ .post-image }

Now we have successfully installed FindBugs plugin in IntelliJ IDEA and also have enabled the FindSecurityBugs plugin in it. Let’s perform a static code analysis and get to know all the bugs we have in the code.


## Code Analysis
To analyze the project, right click on the project and go to **FindBugs** -> **Analyze Scope Files**. With this, the scanning will happen only under the selected folder. You can also go with **Analyze Module Files** which would scan the particular module you have selected and also **Analyze Project Files** which would scan the entire project. 

![Placeholder](/assets/images/secure-coding-guidelines/fsb-08.png){ .post-image }

Once the static scan is completed, you can see the identified bugs in the **FindBugs-IDEA** panel. Since we have enabled the FindSecurityBugs plugin, it will list all the identified security issues under the **Security** category. 

![Placeholder](/assets/images/secure-coding-guidelines/fsb-09.png){ .post-image }


## Report Generation 
You can export the reported bugs for further analysis. For that, click on the **Export Bug Collection** to **XML/HTML** button.

![Placeholder](/assets/images/secure-coding-guidelines/fsb-10.png){ .post-image }

A generated report would look like below.

![Placeholder](/assets/images/secure-coding-guidelines/fsb-11.png){ .post-image }

If you go to the **Security Warnings** section, you can see a detailed explanation for each identified security issue.

![Placeholder](/assets/images/secure-coding-guidelines/fsb-12.png){ .post-image }


## References
[^1]: [http://findbugs.sourceforge.net/](http://findbugs.sourceforge.net/)
[^2]: [http://find-sec-bugs.github.io/](http://find-sec-bugs.github.io/)
[^3]: [https://plugins.jetbrains.com/plugin/3847?pr=id](https://plugins.jetbrains.com/plugin/3847?pr=id)

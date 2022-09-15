---
title: External Dependency Analysis Analysis using OWASP Dependency Check
category: security-guidelines
published: October 22, 2018
version: 1.1
---

# External Dependency Analysis Analysis using OWASP Dependency Check

<p class="doc-info">Published: October 22, 2017</p>
<p class="doc-info">Version: 1.2</p>
---

## Revision History

| Version | Release Date    | Contributors / Authosr | Summary of Changes  |
|---------|-----------------|------------------------|---------------------|
| 1.1     | June 22, 2017   | [Nadeeshani Pathirennehelage](http://wso2.com/about/team/pathirennehelage-nadeeshani/)     | Running Maven plugin without POM file modification |
| 1.0     | June 28, 2017   | [Tharindu Edirisinghe](http://wso2.com/about/team/tharindu-edirisinghe)   | Initial version     |


## Introduction
This document provides details of all necessary steps for using OWASP Dependency Check Command Line Client (CLI)[^1] tool and the Maven plugin[^2] for analyzing 3rd party dependencies used in projects for identifying known security vulnerabilities.


## OWASP Dependency Check CLI

This is useful when you have the external dependencies (libraries/jar files) downloaded and put in a folder, where you can run the CLI tool against the folder for analyzing the libraries in it and generate the vulnerability assessment report. 

![Placeholder]({{#base_path#}}/assets/images/secure-coding-guidelines/dc-cli-01.png){ .post-image }

Download the CLI tool[^3] and extract the zip file. In the **bin** directory of the **dependency-check** tool, you can find the executable script **dependency-check.bat** file which is for running the tool on Windows operating system and the **dependency-check.sh** file which is for running on Linux. 
If you just execute the script without providing any parameters, you can see the list of parameters that you need to provide for performing the vulnerability analysis and generating reports. 

![Placeholder]({{#base_path#}}/assets/images/secure-coding-guidelines/dc-cli-02.png){ .post-image }

Following are the basic parameters that are required when running a vulnerability analysis.

| Parameter       | Description                                                                                                 |
|-----------------|-------------------------------------------------------------------------------------------------------------|
| `--project`     | You can specify a name for the project and this would appear in the report                                  |
| `--scan`        | The folder which contains the 3rd party dependency libraries                                                |
| `--out`         | The folder where the vulnerability analysis reports should be generated                                     |
| `--suppression` | An XML file that contains the known vulnerabilities that should be hidden from the report (false positives) |

Now let's do an analysis using OWASP Dependency Check. First download commons-httpclient-3.1[^4] and httpclient-4.5.2[^5] libraries and put them in a folder. 

Following is the sample command to run for performing the vulnerability analysis.

```bash
./dependency-check.sh  --project "<myproject>" --scan <folder containing 3rd party libraries> --out <folder to generate reports> --suppression <xml file containing suppressions>
```

!!! example
    Here, let's skip the suppression and just do the analysis. Put the above downloaded 2 libraries to a folder (*i.e. /home/tharindu/dependencies/mydependencies*) and then create another folder to save the scan reports (*i.e. /home/tharindu/dependencies/reports*). Command would be as following,

    ```bash
    ./dependency-check.sh  --project "myproject" --scan /home/tharindu/dependencies/mydependencies --out /home/tharindu/dependencies/reports
    ```

When you run the OWASP Dependency Check for the very first time, it would download the known vulnerabilities from the National Vulnerability Database (NVD)[^6] and it would maintain these information in a local database. So, when running this for the very first time, it would take some time as it has to download all the vulnerability details.

![Placeholder]({{#base_path#}}/assets/images/secure-coding-guidelines/dc-cli-03.png){ .post-image }

By default the duration for syncing the local database and NVD is 4 hours. If you have run the Dependency Check within 4 hours, it will just use the data in the local database without trying to update the local database with NVD.

![Placeholder]({{#base_path#}}/assets/images/secure-coding-guidelines/dc-cli-04.png){ .post-image }

Once you run the Dependency Check against the folder where your project dependencies are, it would generate the vulnerability analysis report. 


## OWASP Dependency Check Maven Plugin
In the previous chapter, the usage of OWASP Dependency Check CLI tool was explained which requires the user to download the external dependencies to a folder and run the tool against the folder for performing the vulnerability analysis. However in practice, this approach does not scale as we would introduce new dependencies as and when we code. In such cases, the maven plugin of OWASP Dependency Check does the job where every time we build the project, it would analyze all the external dependencies of the project and generate the vulnerability report. In this section it is explained how to use this maven plugin for analyzing the project dependencies and how to identify the reported vulnerabilities of them. 

In the pom.xml file of your maven project, add the following plugin.

```xml
<build>
    <plugins>
        <plugin>
        <groupId>org.owasp</groupId>
        <artifactId>dependency-check-maven</artifactId>
        <version>1.4.5</version>
        <configuration>
            <cveValidForHours>12</cveValidForHours>
            <failBuildOnCVSS>7</failBuildOnCVSS>
        </configuration>
        <executions>
            <execution>
                <goals>
                    <goal>check</goal>
                </goals>
            </execution>
        </executions>
        </plugin>
    </plugins>
</build>
```


Now you can build the project (`mvn clean install`) and it will generate the dependency check report in the target directory.

In the maven plugin under the configuration section, from the **`cveValidForHours`** parameter you can control the duration to check for newly reported vulnerabilities in the National Vulnerability Database (NVD) when the maven project is being built. From the **`failBuildOnCVSS`** parameter, we can define a CVSS score where if any known vulnerability is found in a dependent library which has a CVE with CVSS score equal or greater than to the value we define, it will fail the build no matter even if the project has no syntax errors. This is a useful feature for an organization which has automated building the codebase using tools like Jenkins, so that the threats can be identified and rectified as and when they are introduced.

There are more configuration like above which you can refer the official documentation[^7] to find out. In addition to that, there are few references[^8][^9], useful for finding more information on the plugin. 

You can test the plugin by adding the following two dependencies to your project. There, the 3.1 version of commons-httpclient has known vulnerabilities which will be indicated in the vulnerability report. The 4.5.3 version of httpclient has no reported vulnerabilities and therefore it will not be indicated in the report. 

```xml
<dependencies>

    <dependency>
        <groupId>commons-httpclient</groupId>
        <artifactId>commons-httpclient</artifactId>
        <version>3.1</version>
    </dependency>
    
    <dependency>
        <groupId>org.apache.httpcomponents</groupId>
        <artifactId>httpclient</artifactId>
        <version>4.5.3</version>
    </dependency>

</dependencies>
```

The generated report would look as the same which is the same as using the CLI tool[^10].


## OWASP Dependency Check Maven Plugin - Without POM Modification
We can run OWASP Dependency Check without doing any changes to the maven pom.xml file. We can just run using the mvn command as follows.

```bash
mvn org.owasp:dependency-check-maven:check
```

Then it will build the product with the dependency-check-maven. Thus, it will generate the dependency check report for 3rd party dependencies of your product.

In any case of false positive issues that you want to remove from the generated report, you can suppress those by creating a suppression.xml file. Then, you can give that suppression file as an argument in the `mvn` command.

```bash
-DsuppressionFile="\${path.to.suppression.file}/suppression.xml"
```


This is an example suppression.xml file.

!!! example ""
    ```
    <?xml version="1.0" encoding="UTF-8"?>
    <suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.1.xsd">
        <suppress>
            <notes><![CDATA[
            CVE-2016-7051 is only relevant to jackson-dataformat-xml according to NVD [1] and original bug report [2].
            [1] https://github.com/FasterXML/jackson-dataformat-xml/issues/211
            ]]></notes>
            <cve>CVE-2016-7051</cve>
        </suppress>
        <suppress>
            <notes><![CDATA[
            CVE-2012-4232 is only valid for "a:jcore:jcore" JCore is not used within Ballerina.
            ]]></notes>
            <cve>CVE-2012-4232</cve>
        </suppress>
    </suppressions>
    ```


## Analyzing the Reports
Below is an example on analyzing the vulnerability report.

![Placeholder]({{#base_path#}}/assets/images/secure-coding-guidelines/dc-cli-05.png){ .post-image }

Based on the analysis, we can see that the **commons-httpclient-3.1.jar**[^4] is having 3 known security vulnerabilities, but **httpclient-4.5.2.jar**[^5] is not having any reported security vulnerability. 

Following are the 3 known security vulnerabilities reported against **commons-httpclient-3.1.jar**[^4]. 

![Placeholder]({{#base_path#}}/assets/images/secure-coding-guidelines/dc-cli-06.png){ .post-image }

![Placeholder]({{#base_path#}}/assets/images/secure-coding-guidelines/dc-cli-07.png){ .post-image }

![Placeholder]({{#base_path#}}/assets/images/secure-coding-guidelines/dc-cli-08.png){ .post-image }

A known security vulnerability would have a unique identification number (CVE)[^11] and a score (CVSS[^12], a scale from 0 to 10) and the severity. The severity is decided based on the CVSS score. The identification number follows the format "CVE-`<reported year>`-`sequence number`".

When we identify that there is a known security vulnerability in a 3rd party library, we can check if that library has a higher version where this issue is fixed. In the above example httpclient 3.1’s[^4] vulnerabilities are fixed in its latest version.

If the latest version of a 3rd party library is also having known vulnerabilities, you can try to use an alternative which has no reported vulnerabilities so you can make sure your project is not dependent on any external library that is not safe to use. 

However there comes situations where you have no option other than using a particular 3rd party library, but still that library has some known vulnerabilities. In such a case, you can go through each vulnerability and check if it has any impact on your project. For example, the 3 known issues in httpclient 3.1 are related to SSL, hostname and certificate validation. Let’s say your project uses this library just to call some URL (API) via HTTP (not HTTPS), then your project has no impact from the reported vulnerabilities of httpclient. So these issues become false positives in your case. 

In such a situation, you might need to get a vulnerability analysis report for 3rd party dependencies that clearly reflects the actual vulnerabilities and hides false positives. Then you can use the suppress option in Dependency Check. 


## Vulnerability Suppressions - Marking False Positives

When you get the Dependency Check report, next to each vulnerability in the report, there is a button named **suppress**. If you want to hide that vulnerability from the report, click on this button and it will popup a message that contains some XML content. 

![Placeholder]({{#base_path#}}/assets/images/secure-coding-guidelines/dc-cli-09.png){ .post-image }

You can create an XML file with below content and put the XML content you got by clicking on the suppress button as child elements under the `<suppressions>` tag.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<suppressions xmlns="https://www.owasp.org/index.php/OWASP_Dependency_Check_Suppression">

<!-- add each vulnerability suppression here-->

</suppressions>
```

A sample is below. 

!!! example ""
    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <suppressions xmlns="https://www.owasp.org/index.php/OWASP_Dependency_Check_Suppression">
        <suppress>
            <notes><![CDATA[file name: commons-httpclient-3.1.jar]]></notes>
            <sha1>964cd74171f427720480efdec40a7c7f6e58426a</sha1>
            <cve>CVE-2015-5262</cve>
        </suppress>
    </suppressions>
    ```

When you are using the Dependency Check CLI, you can run it with the `--suppression` parameter where you provide the file path to the XML file that contains the suppressions. 

```bash
./dependency-check.sh  --project "myproject" --scan /home/tharindu/dependencies/mydependencies --out /home/tharindu/dependencies/reports --suppression /home/user/dc/suppress.xml
```

When you are using the Dependency Check Maven plugin, you can add the suppressionFile property to the configuration and point to the XML file which contains the suppressions.

```xml
<plugin>
    <groupId>org.owasp</groupId>
    <artifactId>dependency-check-maven</artifactId>
    <version>1.4.5</version>
    <configuration>
        <cveValidForHours>12</cveValidForHours>
        <failBuildOnCVSS>8</failBuildOnCVSS>
   	    <suppressionFile>/home/user/dc/suppress.xml</suppressionFile>
    </configuration>
    <executions>
        <execution>
            <goals>
              	<goal>check</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

Then the report would show how many vulnerabilities are suppressed. 

![Placeholder]({{#base_path#}}/assets/images/secure-coding-guidelines/dc-cli-10.png){ .post-image }

Also the report would contain a new section called **Suppressed Vulnerabilities** and you can make this section hidden or visible in the report. 

![Placeholder]({{#base_path#}}/assets/images/secure-coding-guidelines/dc-cli-11.png){ .post-image }


## Summary
In conclusion, before using an external library as a dependency for your project, it is important to know those are safe to use. You can simply use a tool like OWASP Dependency Check and do a vulnerability analysis for the 3rd party dependencies. You can follow this as a process in your organization to ensure that you do not use components with known vulnerabilities in your projects. This is one major software security risk listed under OWASP Top 10[^13] as well. 


## References
[^1]: [https://www.owasp.org/index.php/OWASP_Dependency_Check](https://www.owasp.org/index.php/OWASP_Dependency_Check)
[^2]: [http://jeremylong.github.io/DependencyCheck/dependency-check-maven/](http://jeremylong.github.io/DependencyCheck/dependency-check-maven/)
[^3]: [https://github.com/jeremylong/DependencyCheck/releases/download/v7.1.1/dependency-check-7.1.1-release.zip](https://github.com/jeremylong/DependencyCheck/releases/download/v7.1.1/dependency-check-7.1.1-release.zip)
[^4]: [https://mvnrepository.com/artifact/commons-httpclient/commons-httpclient/3.1](https://mvnrepository.com/artifact/commons-httpclient/commons-httpclient/3.1)
[^5]: [https://mvnrepository.com/artifact/org.apache.httpcomponents/httpclient/4.5.2](https://mvnrepository.com/artifact/org.apache.httpcomponents/httpclient/4.5.2)
[^6]: [https://nvd.nist.gov/](https://nvd.nist.gov/)
[^7]: [https://jeremylong.github.io/DependencyCheck/dependency-check-maven/configuration.html](https://jeremylong.github.io/DependencyCheck/dependency-check-maven/configuration.html)
[^8]: [https://blog.lanyonm.org/articles/2015/12/22/continuous-security-owasp-java-vulnerability-check.html](https://blog.lanyonm.org/articles/2015/12/22/continuous-security-owasp-java-vulnerability-check.html)
[^9]: [http://www.securityinternal.com/2017/06/identifying-vulnerable-software.html](http://www.securityinternal.com/2017/06/identifying-vulnerable-software.html)
[^10]: [http://www.securityinternal.com/2016/10/owasp-dependency-check-cli-analyzing.html](http://www.securityinternal.com/2016/10/owasp-dependency-check-cli-analyzing.html)
[^11]: [https://cve.mitre.org/](https://cve.mitre.org/)
[^12]: [https://www.first.org/cvss/specification-document](https://www.first.org/cvss/specification-document)
[^13]: [https://www.owasp.org/index.php/Top_10_2013-Top_10](https://www.owasp.org/index.php/Top_10_2013-Top_10)

---
title: Dynamic Analysis with OWASP ZAP
category: security-guidelines
published: October 22, 2018
version: 1.2
---

# Dynamic Analysis with OWASP ZAP
<p class="doc-info">Version: 1.2</p>
___

## Introduction
This document provides details of all necessary steps for configuring the OWASP Zed Attack Proxy (OWASP ZAP)[^1] tool for scanning WSO2 products in order to discover security threats. 


## OWASP ZAP Setup

### Increase JVM Heap Size for Running ZAP
The heap size is defined in the *zap.sh* (for Linux) and *zap.bat* (for Windows) files. The default value is set to `Xmx512m` (if available free memory is above 1,500 MB) and increase the value appropriately based on the memory availability of your system. (At least 4GB is recommended)

In addition to that, the ZAP scan is a long-running process. Therefore, it is better to run ZAP in a cloud instance or in a dedicated server to avoid any interruptions. 


### Fine Tune ZAP Tool with Pre-Configured Policy 
The ZAP tool should be fine-tuned before running a scan for obtaining better results. For this, you can download the WSO2 policy file for ZAP[^2], which contains the settings to fine-tune ZAP. 

Go to **Analyze** &rarr; **Scan Policy** Manager in ZAP.

![Placeholder](../../assets/images/secure-coding-guidelines/zap-01.png)

In the **Scan Policy Manager** window, click **Import**.

![Placeholder](../../assets/images/secure-coding-guidelines/zap-02.png)

Browse and select the WSO2 Policy file you downloaded.

![Placeholder](../../assets/images/secure-coding-guidelines/zap-03.png)

Since the policy file is imported correctly, you can use this later when you run the spider and the scan. 


### Configuring ZAP Proxy to Trace Browser Traffic
Rather than providing the URL of the WSO2 server and attacking the URL with ZAP, it is much more effective if we record the UI actions we do on the WSO2 server and let the ZAP tool capture the traffic that can then be used for performing attacks. 

Go to **Tools** &rarr; **Options** &rarr; **Local Proxy** and set the hostname/IP address and the port number for the proxy. *(In this example, the port is set to 7777 which is selected randomly)*

![Placeholder](../../assets/images/secure-coding-guidelines/zap-04.png)

Now the ZAP tool is ready to capture the traffic going through the port (set above). The next step is to configure the browser to send traffic through this port number so that the ZAP tool can trace them.

In Firefox, go to **Edit** &rarr; **Preferences** and in the **Advanced** options, click **Settings** under the Network tab. 

Select the **Manual proxy configuration** and set the hostname/IP and the port number.

![Placeholder](../../assets/images/secure-coding-guidelines/zap-05.png)

If any exception for **localhost, 127.0.0.1** or the hostname of the WSO2 server you are trying to scan is given in **No Proxy for:** text box, remove them so ZAP can detect the traffic flow of that as well. 

Now, go to firefox and access the WSO2 server. You will see the SSL warning below because the traffic goes through the ZAP proxy. Add an exception to the site in the browser.

![Placeholder](../../assets/images/secure-coding-guidelines/zap-06.png)

Now the WSO2 Server URL should be opened in the browser. Also, it should be listed in ZAP under the sites. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-07.png)

Select the Mode of the scan as **Protected Mode**. With this, you can choose which sites to be used for attacking. *(For example, if you are trying out the Federated Authentication scenario with WSO2 Identity Server and Facebook, under the Sites in ZAP tool, the Facebook website also will be listed to be attacked. In the scope of scanning, external websites should be removed. With the Protected Mode, you able to select the sites that should be attacked by the ZAP tool)*


## Scanning Process

### Excluding the Server Logout from Spider
When we run the ZAP scan with an active user session, if ZAP executes the action to logout from the server in the middle of the scan, the actions that should be performed with a logged in user session would not be performed after that (because the active session is removed with the logout action ). In order to avoid that, we need to exclude the logout action from the Spider.

For that, first, log in to the WSO2 Server and then log out so that the logout action is traced by ZAP. Then, find the **GET:logout_action.jsp** and right-click it and exclude it from Spider.

The logout action is listed under **<server_url\>** &rarr; **carbon** &rarr; **admin** in the Sites tree.

![Placeholder](../../assets/images/secure-coding-guidelines/zap-08.png)

Then in the **Session Properties** window, it will show the URL regex that ZAP is going to exclude in the spider. Click **OK**. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-09.png)


### Perform UI Actions Manually (or using Selenium)
With the above steps, ZAP is tracing the sites that you visit in the browser. The next step is to manually perform UI actions in the browser so that ZAP traces all the actions which we can then use for attacking. 

This helps test a specific feature. For example, if we want to identify the possible issues in the user creation flow, we can create a new user in Management Console while ZAP traces all actions through the proxy. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-10.png)

On the URLs ZAP discovered, it can perform attacks to find possible issues. We can improve the coverage of the scan by manually performing all actions in the browser (i.e in Management Console) so that ZAP discovers each flow that it can try attacking. 

You can also automate this by having selenium scripts for all UI actions. After setting the ZAP to act as the proxy, you can run selenium scripts so that in the browser, it automatically plays the actions you would do manually. For every action, ZAP will discover the URLs. 


### Removing Unnecessary Sites from Scan
When the ZAP is acting as the proxy, all the URLs that the browser calls will be traced under the Sites in ZAP. We need to remove external websites and select only the WSO2 Server’s scope for the scan. 

Right-click the **Site** that should be included in the scan and select **Include in Context** &rarr; **New Context** .

![Placeholder](../../assets/images/secure-coding-guidelines/zap-11.png)

Then it will show the **Session Properties** window with the regex for including the URL patterns in the scan. Provide a name for the context so that we can identify the site uniquely when we have multiple sites added as different contexts. (For example, when you are testing a product like WSO2 API Manager, the Management Console, API Store and API Publisher can be three major sites where you can add each as a different context)

![Placeholder](../../assets/images/secure-coding-guidelines/zap-12.png)

Once the site is added to the Context for scan, the icon image for each entry under the tree of the site will be changed showing that it is added to the context.

![Placeholder](../../assets/images/secure-coding-guidelines/zap-13.png)

Under the Sites list, you can click the **Show all URLs** button to view only the sites that are added to the contexts. All other sites will be hidden from the Sites panel with this option. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-14.png)

Once you have added the site/s to the context, you can filter the scan results (after running a scan) easily. In the History tab, **Show only URLs in Scope** filters the results and shows only the URLs that belong to the context. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-15.png)

When searching also you can search URLs that belong only to the context with the **Search all URLs** option enabled. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-16.png)

You can also filter the alerts that belong only to the contexts you have added with the **Show all URLs** option enabled.

![Placeholder](../../assets/images/secure-coding-guidelines/zap-17.png)


### Globally Excluding URL Patterns
When the ZAP tool starts crawling the site, it will increase the network traffic heavily. We can reduce the traffic by excluding the URL patterns globally so that ZAP will ignore such URLs when crawling. For example, if we exclude URLs of .mp4 video files, the ZAP tool will not download mp4 video files which saves network bandwidth.

Go to **Tools** &rarr; **Options** and select the Global Exclude URL option. By default, there are some patterns already added to ZAP. You can select all of them for exclusion. Additionally, if there is any URL pattern you need to exclude, you can add the regex for the URL as a new entry. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-18.png)


### Creating the Logged in User Session
When running the spider to crawl the site, we have to let ZAP discover the URLs that are accessible only by logged-in users as well. For that, we need to create a logged-in user session in ZAP, so that same as a logged-in user can browse the URLs in a web browser, ZAP will be able to crawl through those URLs. 

Click  **Show All Tabs** in the toolbox so that it will display all the tabs. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-19.png)

Go to the **Http Sessions** tab. If there are already created sessions listed, you can remove them. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-20.png)

Now while the ZAP proxy is tracing the traffic, go to the browser and log in to the site you need to scan. (When ZAP performs the scan, it will attack the URLs with the associated privileges of the user you logged in to). Once you log in, the session ID should be listed in the **HTTP Sessions** tab. Right-click the session and **Set as Active**. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-21.png)

The above should be done only if the authentication to the site is tracked via the **JSESSIONID**. In a scenario like Single Sign On (*i.e. when testing Identity Server Dashboard*), the session is maintained using the **commonAuthId** cookie. In such a case, go to the Params tab, right-click the **JSESSIONID** and select **Unflag as session Token**.

![Placeholder](../../assets/images/secure-coding-guidelines/zap-22.png)

After that, right-click **commonAuthId** and **Flag as Session Token**. With this ZAP will take commonAuthId value for maintaining the session. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-23.png)

In both cases above, the browser should have an active user *(logged in)* session with the particular session value traced in ZAP which should then be flagged as the session token.


### Configuring and Running AJAX Spider
When you have multiple sites added to the context and when you need all the sites to have the same configuration, you can set them globally. Go to **Tools** &rarr; **Options** and select **AJAX Spider**. 

Set the maximum crawl depth, maximum crawl states and maximum duration to **0** so that the AJAX Spider will go on crawling completely without any limitations. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-24.png)

You can choose the browser to be used for crawling by the AJAX spider. If your browser is not listed in the dropdown, go to **Tools** &rarr; **Options** and in the **Selenium** option, browse and provide the selenium driver for the particular browser. (You can download the selenium driver for the particular web browser from the internet) . Once you have provided the driver, in AJAX Spider configuration’s browser dropdown the browser will be listed.

![Placeholder](../../assets/images/secure-coding-guidelines/zap-25.png)

If you have multiple sites added to the context but need to have separate ajax spider configurations for a particular site, you cannot use global settings. In such a case, right-click the particular site and go to **Attack** &rarr; **AJAX Spider**.

Also, you need to select **Protected Mode** (*from the dropdown in the toolbox*) for running the AJAX spider so that it will crawl through the sites added to the context and will skip any URL that is out of scope. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-26.png)

Select **Show advanced options** in the **Scope** tab which will make the **Options** tab visible. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-27.png)

In the **Options** tab of AJAX Spider, you can set the configuration specific to this particular site. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-28.png)

Once the configuration is set, you can **Start Scan**. 

Before starting the scan, you need to make sure that you have an active user session set in ZAP (Follow the steps in *[Creating the Logged in User Session](#creating-the-logged-in-user-session) section*) so that the AJAX spider can crawl URLs that are accessible by the logged-in user. 


### Running Spider
The global configuration for Spider is in **Tools** &rarr; **Options** under Spider option which applies to all the sites added to the context. 

You can set the maximum depth to crawl to 5. At this point, we have already run the AJAX Spider and discovered most of the URLs with crawling. Therefore, crawling up to a depth of 5 levels would provide sufficient coverage. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-29.png)

When you have multiple sites added to the context and need to have separate Spider configurations for a particular site, you cannot use Global Settings. In such a case, you can right-click the site and go to **Attack** &rarr; **Spider**. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-30.png)

In the **Spider** window, select **Show Advanced options** and go to the **Advanced** tab.

![Placeholder](../../assets/images/secure-coding-guidelines/zap-31.png)

Since we have run the AJAX Spider previously, it should have crawled most of the URLs of the server. Therefore having only **5** as the maximum depth to crawl would be sufficient to complete crawling and covering the URLs of the server. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-32.png)

With the above configuration, start the scan to complete URL discovery.


### Removing False Positives before Scanning
Before running the Active Scan, we can configure the Session Properties such that when reporting alerts, it would avoid known false positive URLs. 

Go to **File** &rarr; **Session Properties** and under the particular context, select **Alert Filters**. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-33.png)

Then click the **Add** button to define the URLs that we have already identified to be reporting false positive alerts. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-34.png)

In the Add **Alert Filter** window, select the type of **Alert** and set it as a **False Positive** in the **New Risk Level** dropdown. If the URL is a direct URL, it can be given in the **URL** textbox. If there are multiple URLs following the same pattern, select the **URL is Regex**? checkbox and define the regular expression for the URL. Finally, **Confirm** the alert filter. 

The alerts generated for these URLs would  be ignored by ZAP during the scanning time and also would not appear in the identified security vulnerabilities. 


### Running Active Scan
When you have multiple sites in the context and need to have a similar active scan configuration for all the sites, you can use the global settings. Go to **Tools** &rarr; **Options** and select **Active Scan**. 

As the default active scan policy and attack mode scan policy, select the WSO2Policy file which you imported in the section [Fine Tune ZAP Tool with Pre-Configured Policy](#fine-tune-zap-tool-with-pre-configured-policy).  

![Placeholder](../../assets/images/secure-coding-guidelines/zap-35.png)

When you have multiple sites added to the context, but need to have a specific active scan configuration for a particular site, you can right-click the particular site and go to **Attack** &rarr; **Active Scan**. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-36.png)

It will show the **Active Scan** window. Select **Show advanced options** and go to the **Policy tab**. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-37.png)

As the **Policy**, select the WSO2Policy file which you imported previously. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-38.png)

Finally, start the scan. Note that you need to have a logged-in user session when running the active scan.(*follow the steps in [Creating the Logged in User Session](#creating-the-logged-in-user-session)*)

Then the scan will begin and you can see the progress in the **Active Scan** tab. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-39.png)


## Report Generation

### Removing False Positives Before Report Generation
Once the **Active Scan** is completed and the alerts are generated, if there are false positive alerts, they can be removed from appearing in the reports generated. For that, go to the **Alerts** tab and double-click the particular alert that should be marked as a false positive. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-40.png)

Then the **Edit Alert** window will appear. In the **Confidence** dropdown, select **False Positive**. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-41.png)


### Generating Reports
Once the **Active Scan** is complete, you can generate the reports for exporting the results of the scan. Go to **Report** &rarr; **Generate HTML Report** from the menu. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-42.png)

Then it will prompt where to save the report. Once you provide a file path, it will export the ZAP scan report. By examining the report, you will be able to identify possible security threats and get them fixed. 

![Placeholder](../../assets/images/secure-coding-guidelines/zap-43.png)


## Scanning RESTful APIs with ZAP
WSO2 products have APIs that are secured with OAuth. In order to consume such APIs, we need to provide an access token in the request. When ZAP is scanning the URLs, since the access token is not passed when making the requests, it will fail to scan the APIs completely. In such cases, we can manually test the APIs using a REST client which can be configured to send traffic through a proxy. Here we can configure the proxy host and port to the same host and port that ZAP is running so that ZAP can trace and record traffic for all the API requests.

OAuth access tokens have a fixed expiration time, which is set to 60 minutes by default in WSO2 products (*i.e Identity Server*). This expiration time is not sufficient when running the active scan. Therefore you have to increase the token expiration time in `<AccessTokenDefaultValidityPeriod>` element in *<CARBON_HOME\>/repository/conf/identity.xml* file. 

1. Configure the proxies in the browser as you do in the usual scenario, since the REST client runs on top of the browser ZAP is intelligent enough to identify the process.
2. Configure the authentication headers in the REST client

    ![Placeholder](../../assets/images/secure-coding-guidelines/zap-44.png)

Now run the requests in the REST client, ZAP can now scan as it does for the web UI. You will be able to do the active scan, spider and ajax spider after that, as you do in the usual way.

If you see any certificate-based errors like the below in your REST client, allow the certificate when pops up when trying to login to the carbon console (In firefox you won’t get any response)

![Placeholder](../../assets/images/secure-coding-guidelines/zap-45.png)


## References
[^1]: [https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)
[^2]: [https://github.com/thariyarox/SecurityTools/blob/master/OWASP_ZAP/policies/WSO2Policy.policy](https://github.com/thariyarox/SecurityTools/blob/master/OWASP_ZAP/policies/WSO2Policy.policy)

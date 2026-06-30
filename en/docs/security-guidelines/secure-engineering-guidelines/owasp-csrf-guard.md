---
title: OWASP CSRFGuard
category: security-guidelines
published: October 22, 2018
version: 1.1
---

# OWASP CSRFGuard
<p class="doc-info">Version: 1.1</p>
___

## Introduction
This document introduces OWASP CSRFGuard and further summarizes best practices and configuration recommendations for applications hosted on the WSO2 platform. In addition, this document further explains configuration values that can be fine-tuned to increase security, based on security requirements of the specific application.

OWASP CSRFGuard[^1] is an OWASP flagship project that provides synchronizer token pattern based CSRF protection in a comprehensive and customizable manner.

CSRFGuard offers complete protection over CSRF scenarios by covering HTTP POST, HTTP GET as well as AJAX based requests.

Forms based on HTTP POST and HTTP GET methods can be protected by injecting CSRF tokens into the “action” of the form, or by embedding a token in a hidden field. In addition, HTTP GET requests sent as a result of resource inclusions and links can also be protected by appending the relevant token in the “href” or “src” attributes. Token inclusions can be done manually using the provided JSP tag library or by using a JavaScript based automated injection mechanism. AJAX requests are protected by injecting an additional header which contains CSRF token.


## Recommended Approach for WSO2 Products
Any state changing actions should be performed with the HTTP POST method, with an exception for the usage of PUT and DELETE methods in REST APIs.

CSRFGuard should not validate HTTP GET requests for CSRF protection. Token injection should be performed using JavaScript mechanism[^2]. Hidden input field injection should be the only injection operation performed by the CSRFGuard which will protect HTTP POST based forms. In addition, AJAX POST requests should be protected by sending the CSRF token in a header.

CSRF token values should not be exposed in the URL. In situations where script injection can not be performed and built-in AJAX protection does not suffice, product teams may decide to use JST tag library based manual inclusion[^3], after verifying with the Security and Compliance Team. 

Product teams should append CSRF exclusion URLs exposed from the root context, relevant to the particular product, in `Owasp.CsrfGuard.Carbon.properties` by following the steps mentioned in section 6.


## Securing Web Applications
Recommended `web.xml` changes:

```xml
<!-- OWASP CSRFGuard context listener used to read CSRF configuration -->
<listener>
   <listener-class>org.owasp.csrfguard.CsrfGuardServletContextListener</listener-class>
</listener>

<!-- OWASP CSRFGuard session listener used to generate per-session CSRF token -->
<listener>
   <listener-class>org.owasp.csrfguard.CsrfGuardHttpSessionListener</listener-class>
</listener>

<!-- OWASP CSRFGuard per-application configuration property file location-->
<context-param>
   <param-name>Owasp.CsrfGuard.Config</param-name>
   <param-value>repository/conf/security/Owasp.CsrfGuard.Carbon.properties</param-value>
</context-param>

<!-- OWASP CSRFGuard filter used to validate CSRF token-->
<filter>
   <filter-name>CSRFGuard</filter-name>
   <filter-class>org.owasp.csrfguard.CsrfGuardFilter</filter-class>
</filter>

<!-- OWASP CSRFGuard filter mapping used to validate CSRF token-->
<filter-mapping>
   <filter-name>CSRFGuard</filter-name>
   <url-pattern>/*</url-pattern>
</filter-mapping>

<!-- OWASP CSRFGuard servlet that serves dynamic token injection JavaScript (application can customize the URL pattern as required)-->
<servlet>
   <servlet-name>JavaScriptServlet</servlet-name>
   <servlet-class>org.owasp.csrfguard.servlet.JavaScriptServlet</servlet-class>
</servlet>
<servlet-mapping>
   <servlet-name>JavaScriptServlet</servlet-name>
   <url-pattern>/csrf.js</url-pattern>
</servlet-mapping>
```

Include `JavaScriptServlet` in the HTML template of the application, so that `<head>` element of all pages that need to be protected, should have JavaScriptServlet as the first JavaScript inclusion.

```html
<html>
<head>
…
<script type=”text/javascript” src=”/csrf.js”></script>

<!-- other JavaScript inclusions should follow “csrf.js” inclusion -->
<script type=”text/javascript” src=”/main.js”></script>
… 
</head>
<body>
...
</body>
</html>
```

Prepare and store per-application CSRF configuration files according to sections 5 and 6 of the document. 


## Securing Jaggery Applications
Update Jaggery version to 0.12.6

Recommended jaggery.conf changes:
```json
"listeners" : [
    {
        "class" : "org.owasp.csrfguard.CsrfGuardServletContextListener"	
    },
    {
        "class" : "org.owasp.csrfguard.CsrfGuardHttpSessionListener"	
    }
],
"servlets" : [
    {
        "name" : "JavaScriptServlet",
        "class" : "org.owasp.csrfguard.servlet.JavaScriptServlet"
    }
],
"servletMappings" : [
    {
        "name" : "JavaScriptServlet",
        "url" : "/csrf.js"
    }
],
"contextParams" : [
    {
        "name" : "Owasp.CsrfGuard.Config",
        "value" : "repository/conf/security/Owasp.CsrfGuard.dashboard.properties"
    }
],
"filters" : [
    {
        "name" : "CSRFGuard",
        "class" : "org.owasp.csrfguard.CsrfGuardFilter"
    }
],
"filterMappings" : [
    {
        "name" : "CSRFGuard",
        "url" : "/*"
    }
],
```

Include `JavaScriptServlet` in the HTML template of the application, so that the `<head>` element of all pages that need to submit or make ajax requests to a protected URL should reference it as the first JavaScript inclusion.

```html
<html>
<head>
…
<script type=”text/javascript” src=”/csrf.js”></script>

<!-- other JavaScript inclusions should follow “csrf.js” inclusion -->
<script type=”text/javascript” src=”/main.js”></script>
… 
</head>
<body>
...
</body>
</html>
```

Prepare and store per-application CSRF configuration files according to sections 5 and 6 of the document. 


## Recommended Default Configuration Changes
Diff available at [^4] highlights recommended changes, which are further listed below.

```toml
# WSO2 : Since state-changing operations are not performed via HTTP GET,
# disabling CSRF validation for GET method.
org.owasp.csrfguard.UnprotectedMethods=GET

# WSO2 : Considering overhead, necessity, as well as current unintended behaviour
# of library after blocking a CSRF attack, disabling per-page tokens.
org.owasp.csrfguard.TokenPerPage=false

# WSO2 : Disabling token rotation after blocking a CSRF attack, since this behaviour
# will break back navigation after blocking an attack.
#org.owasp.csrfguard.action.Rotate=org.owasp.csrfguard.action.Rotate

# WSO2 : Disable redirecting user to an error page after blocking a CSRF attack
#org.owasp.csrfguard.action.Redirect=org.owasp.csrfguard.action.Redirect
#org.owasp.csrfguard.action.Redirect.Page=%servletContext%/error.html

# WSO2 : Enable sending a 403 error after blocking a CSRF attack. Product teams 
# can add error page that handles 403 or “org.owasp.csrfguard.action.Error” to 
# display custom error pages. 
org.owasp.csrfguard.action.Error=org.owasp.csrfguard.action.Error
org.owasp.csrfguard.action.Error.Code=403
org.owasp.csrfguard.action.Error.Message=Security violation.

# WSO2 : Since, CSRFGuard will send relevant token name as HTTP header
# “X-” prefix was added to express that this is a non-standard header.
org.owasp.csrfguard.TokenName=X-CSRF-Token

# WSO2 : Disable printing configuration during start-up
org.owasp.csrfguard.Config.Print = false

# WSO2 : Disable JavaScript from injecting token value to HTTP GET based forms.
# This prevents token leakage that could occur when sending token in URL.
# State-changing actions should not be performed over HTTP GET
org.owasp.csrfguard.JavascriptServlet.injectGetForms = false

# WSO2 : Disable JavaScript from injecting token value to form action.
# This prevents token leakage that could occur when sending token in URL.
org.owasp.csrfguard.JavascriptServlet.injectFormAttributes = false

# WSO2 : Disable JavaScript from injecting token value to “src” and “href”.
# This prevents token leakage that could occur when sending token in URL.
org.owasp.csrfguard.JavascriptServlet.injectIntoAttributes = false 

# WSO2 : Changing X-Request-With header text to avoid unnecessary information disclosure.
org.owasp.csrfguard.JavascriptServlet.xRequestedWith = WSO2 CSRF Protection

# WSO2 - Pseudo-random number generator provider should be configured based on 
# environment (SUN/IBMJCE)
org.owasp.csrfguard.PRNG.Provider=SUN
```


## Excluding URLs from CSRF Validation
Web applications can include property keys with `org.owasp.csrfguard.unprotected.` prefix to exclude relevant patterns from CSRF protection. 

!!! example
    ```toml
    org.owasp.csrfguard.unprotected.Default=%servletContext%/exampleAction
    org.owasp.csrfguard.unprotected.Default_1=%servletContext%/exampleAction
    org.owasp.csrfguard.unprotected.Example=%servletContext%/exampleAction/*
    org.owasp.csrfguard.unprotected.ExampleRegEx=^%servletContext%/.*Public\.do$
    ```

!!! info "Note"
    Do not use additional “.” (period) symbols in unprotected URL alias which is followed by `org.owasp.csrfguard.unprotected.`

Example relevant to above note:

!!! bug error "Example Incorrect Usage"
    ```toml
    org.owasp.csrfguard.unprotected.auth.example=%servletContext%/auth
    ```

!!! success check done "Example Correct Usage"
    ```toml
    org.owasp.csrfguard.unprotected.authExample=%servletContext%/auth
    ```


## Further Enhancing Security
This section lists down configuration values that can be used to further enhance security or introduce additional restrictions. Changes to following configuration values should only be done based on customer request or justifiable application level requirements since they will affect performance or user experience. 

The property below can be used to change the hashing algorithm used to generate CSRF token:
`org.owasp.csrfguard.PRNG=SHA1PRNG`


Following property can be used to define the length of CSRF token:
```toml
org.owasp.csrfguard.TokenLength=32
```

Following property can be enabled to invalidate the user session if an CSRF attack attempt was blocked by CSRFGuard:
```toml
#org.owasp.csrfguard.action.Invalidate=org.owasp.csrfguard.action.Invalidate
```


## WSO2 Product Integration Checklist

Follow this checklist when integrating WSO2 products with CSRFGuard.

### Checklist Item 1
Make sure state changing actions are performed only with HTTP POST method, with an exception for the usage of PUT and DELETE methods in REST APIs. No state changing operation should happen through GET requests.


### Checklist Item 2
CSRFGuard configuration should be changed to allow unauthenticated sessions to pass through the filter, by setting `org.owasp.csrfguard.ValidateWhenNoSessionExists` property to `false` in */repository/conf/security/Owasp.CsrfGuard.Carbon.properties*. This can be done using product distribution POM file by adding below rule in `tasks` section of `maven-antrun-plugin`:

```xml
<!-- Update Owasp.CsrfGuard.properties file with ValidateWhenNoSessionExists to disable validation on requests made with no valid session -->
<replace  
    file="target/wso2carbon-core-${carbon.kernel.version}/repository/conf/security/
        Owasp.CsrfGuard.Carbon.properties" 
    token="org.owasp.csrfguard.ValidateWhenNoSessionExists = true" 
    value="org.owasp.csrfguard.ValidateWhenNoSessionExists = false"/>
```


### Checklist Item 3 (For WSO2 Carbon 4.4.6 / 4.4.7 / 4.4.8 based products only)
CSRFGuard configuration location should be changed in `web.xml` to adapt to IBM JDK and DevStudio deployment environments. The default configuration location should be changed from */repository/conf/security/Owasp.CsrfGuard.Carbon.properties* to *repository/conf/security/Owasp.CsrfGuard.Carbon.properties*. This can be done using the product distribution POM file by adding the below rule in the `tasks` section of `maven-antrun-plugin` (if any product completely replaces the `web.xml` file derived from carbon, the product should add this change in their version of `web.xml`) :

!!! info "Note"
    This path correction should also be done in any `web.xml` files other than carbon `web.xml`, and also in *jaggery.conf* files, if a product contains such.

```xml
<!-- Update Owasp.CsrfGuard.properties file location to fix IBM JDK and DevStudio issue-->
<replace 
   file="target/wso2carbon-core-${carbon.kernel.version}/repository/conf/tomcat/carbon/
      WEB-INF/web.xml" 
   token="/repository/conf/security/Owasp.CsrfGuard.Carbon.properties" 
   value="repository/conf/security/Owasp.CsrfGuard.Carbon.properties"/>
```


### Checklist Item 4
CSRFGuard configuration for the Carbon console is available at */repository/conf/security/Owasp.CsrfGuard.Carbon.properties​​*. The product team should append product-specific CSRF exclusions for "Carbon console" to configuration file, during "distribution" maven build.

Product specific patterns used in the previous implementation are available at [^5] for reference.

Refer to [Excluding URLs from CSRF Validation](#excluding-urls-from-csrf-validation) section for more details on adding exclusion patterns.


### Checklist Item 5
If a product contains Java web applications other than "Carbon console", make sure `web.xml` and template follow instructions in "Securing Web Applications" section. 

While preparing the CSRFGuard configuration file for the web application, you may duplicate */repository/conf/security/Owasp.CsrfGuard.Carbon.properties​​* and make application specific changes (if there are any). Thereafter, use `Owasp.CsrfGuard.Config` context parameter to point to the configuration file location.


### Checklist Item 6
If the product contains Jaggery web applications, make sure jaggery.conf and template follow the instructions in [Securing Jaggery Applications](#securing-jaggery-applications) section.

While preparing the CSRFGuard configuration file for the Jaggery application, you may duplicate */repository/conf/security/Owasp.CsrfGuard.Carbon.properties​​* and make application specific changes (if there are any). Thereafter, use `Owasp.CsrfGuard.Config` context parameter to point to the configuration file location.


### Checklist Item 7
If any component made available within carbon context (root context) product contains a screen that is not rendered within the "Carbon console" template, but submits data to a “CSRF protected” resources exposed from "Carbon console" (root context) :

* Components should include the CSRFGuard JavaScript as the first JavaScript inclusion in `<head>` section. 
* Example : TryIt  (Example PR[^6])


### Checklist Item 8
If  any component contains JavaScript logic that generates forms dynamically using `document.createElement('form')` and submits the same to a CSRF-protected URL, it is required to add a CSRF token manually as a form element using taglib:

* Add taglib to the jsp,
    ```java
    <%@ taglib uri="http://www.owasp.org/index.php/Category:OWASP_CSRFGuard_Project/Owasp.CsrfGuard.tld" prefix="csrf" %>
    ```
* Manually inject the csrf token to form
    ```java
    var input = document.createElement("input"); 
    input.setAttribute('type',"hidden");
    input.setAttribute('name',"<csrf:tokenname/>");
    input.setAttribute('name',"<csrf:tokenvalue/>");
    form.appendChild(input);
    ```


### Checklist Item 9
If any AJAX POST request sent to a CSRF-protected, relative path (path not starting with `http://` or `https://`) contains a colon (`:`) in the request URL,  CSRFGuard will fail to add an `X-CSRF-Token` header. This will result in a CSRF error. As a fix, it is required to include the CSRF token manually as a header similar to the following:

```javascript
jQuery.ajax({
    type: "POST",
    url: "../eventreceiver/get_adapter_properties.jsp?name=example:1.0.0",
    data: {},
    contentType: "application/json; charset=utf-8",
    dataType: "text",
    beforeSend: function(xhr) {
        xhr.setRequestHeader("<csrf:tokenname/>","<csrf:tokenvalue/>");
    },
        success: function (propertiesString) {
        ...
    }
});
```


### Checklist Item 10
If an integration test submits data to a URL protected by CSRFGuard, the test case should do the following to prevent test failures:

* Call configured JavaScriptServlet with HTTP header `FETCH-CSRF-TOKEN: 1` set to retrieve CSRF token for the current session.

    !!! example
        **Request:**
        ```bash
        curl 'https://localhost:9443/carbon/admin/js/csrfPrevention.js' -X POST -H 'FETCH-CSRF-TOKEN: 1' -H 'JSESSIONID=0C3C606B62FC7AC2D175AA1B9DCA971D;' --compressed --insecure
        ```

        **Response:** 
        `X-CSRF-Token:TCPT-DI3J-DVGZ-2684-NQ67-L9OR-DTZU-FW85`
    
* Send CSRF token received in response as a parameter of submission. 


### Checklist Item 11
For file uploads (multipart requests), the recommendation is to manually inject the CSRF token into the action of the form (including requests made to /fileupload path). To do so, the following steps need to be followed:

* Add taglib to the jsp, 
    ```java
    <%@ taglib uri="http://www.owasp.org/index.php/Category:OWASP_CSRFGuard_Project/Owasp.CsrfGuard.tld" prefix="csrf" %>
    ```

* Manually inject the CSRF token to form action
    ```java
    action="../../fileupload/webapp?<csrf:tokenname/>=<csrf:tokenvalue/>"
    ```


## References
[^1]: [https://www.owasp.org/index.php/Category:OWASP_CSRFGuard_Project](https://www.owasp.org/index.php/Category:OWASP_CSRFGuard_Project)
[^2]: [https://www.owasp.org/index.php/CSRFGuard_3_Token_Injection#JavaScript_DOM_Manipulation](https://www.owasp.org/index.php/CSRFGuard_3_Token_Injection#JavaScript_DOM_Manipulation)
[^3]: [https://www.owasp.org/index.php/CSRFGuard_3_Token_Injection#JSP_Tag_Library](https://www.owasp.org/index.php/CSRFGuard_3_Token_Injection#JSP_Tag_Library)
[^4]: [https://github.com/ayomawdb/csrf-guard-configuration/compare/6a7c4e2fd8eef3f9080582b9de9be93bb1b38d22...master](https://github.com/ayomawdb/csrf-guard-configuration/compare/6a7c4e2fd8eef3f9080582b9de9be93bb1b38d22...master)
[^5]: [https://drive.google.com/a/wso2.com/file/d/0B-0UyBaVrBSteDhhd2QyUkNBRVE/view?usp=sharing](https://drive.google.com/a/wso2.com/file/d/0B-0UyBaVrBSteDhhd2QyUkNBRVE/view?usp=sharing)
[^6]: [https://github.com/wso2/carbon-commons/pull/235/files](https://github.com/wso2/carbon-commons/pull/235/files)
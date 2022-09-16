---
title: Security Related HTTP Headers
category: security-guidelines
published: October 22, 2018
version: 1.1
---

# Security Related HTTP Headers

<p class="doc-info">Published: October 22, 2018</p>
<p class="doc-info">Version: 1.1</p>
---

## Revision History

| Version | Release Date | Contributors / Authors | Summary of Changes |
| ------- | ------------ | ---------------------- |------------------- |
| 1.1     | April 07, 2017 | [Ayoma Wijethunga](https://wso2.com/about/team/ayoma-wijethunga/) | Formatting changes |
| 1.0     | May 26, 2016 | [Ayoma Wijethunga](https://wso2.com/about/team/ayoma-wijethunga/) | Initial version |


## Introduction
This document summarizes the **Security Related HTTP Headers** which should be considered by WSO2 engineers while engineering WSO2 products, as well as applications used within the organization.


### Mandatory Headers
Below list consists of standard and non-standard security related HTTP headers, that must be enabled in order to enhance security aspects of web applications:

!!! info ""
    `X-XSS-Protection: 1; mode=block`: Enables reflected XSS protection in supported web browsers[^1].

    `X-Content-Type-Options: nosniff`: Disable mime sniffing, which can result reflected or stored XSS in certain browsers[^2].


### Configurable Headers
In addition, following security headers should be configured according to requirement of the application and they can be customized based on URL pattern: 

!!! info ""
    `X-Frame-Options: DENY`: Disable embedding web application in iframes or frames[^3].

    `X-Frame-Options: SAMEORIGIN`: Allow embedding web application in iframes or frames, only within same origin[^3].


### Production Recommandations
Production or staging deployments (with CA signed certificates) should enable following headers for additional security:

!!! info ""
    `Strict-Transport-Security: max-age=15768000; includeSubDomains`: Prevent any communication over HTTP, since the time last response was received with the aforementioned header, up-to duration defined in max-age[^4].

Security headers that need to be set with external filter (based on customer and security needs) or that should be incorporated into Tomcat filter in future release includes following: 

!!! info ""
    `Public-Key-Pins: pin-sha256="<sha256>"; pin-sha256="<sha256>"; max-age=15768000; includeSubDomains`: Instructs the web client to associate a specific cryptographic public key with a certain web server to prevent MITM attacks with forged certificates[^5].

!!! info ""
    `Content-Security-Policy`: Allow declaring what dynamic resources are allowed to load to serve current response[^6][^7]. Replaces `X-Fame-Options` and `X-XSS-Protection`, non-standard headers with standardized headers. For additional detail refer to Content-Security-Policy.com[^6].


## Securing Java Web Applications

### Recommended Default Configuration
Recommended web.xml filter mapping for development environments is as follows (**WSO2 products should be released with this default configuration**):

```xml
<filter>
    <filter-name>HttpHeaderSecurityFilter</filter-name>
    <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
    <init-param>
        <param-name>hstsEnabled</param-name>
        <param-value>false</param-value>
    </init-param>
</filter>
<filter-mapping>
    <filter-name>HttpHeaderSecurityFilter</filter-name>
    <url-pattern>*</url-pattern>
</filter-mapping>
```


### Recommandation Production Configuration
Recommended web.xml filter mapping for production environments is as follows:

```xml
<filter>
    <filter-name>HttpHeaderSecurityFilter</filter-name>
    <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
    <init-param>
        <param-name>hstsMaxAgeSeconds</param-name>
        <param-value>15768000</param-value>
    </init-param>
</filter>
<filter-mapping>
    <filter-name>HttpHeaderSecurityFilter</filter-name>
    <url-pattern>*</url-pattern>
</filter-mapping>
```


### Customized Configuration
It is possible to use filter mappings to cater product level customizations required. For example in order to enable `X-Frame-Options` only for particular URLs,  below configuration can be used:

```xml
<filter>
    <filter-name>HttpHeaderSecurityFilter</filter-name>
    <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
    <!-- Disable sending X-Frame-Options with all responses-->
    <init-param>
       <param-name>antiClickJackingEnabled</param-name>
       <param-value>false</param-value>
    </init-param>
</filter>
<filter-mapping>
    <filter-name>HttpHeaderSecurityFilter</filter-name>
    <url-pattern>*</url-pattern>
</filter-mapping>
<filter>
    <filter-name>HttpHeaderSecurityFilter_AntiClickJacking</filter-name>
    <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
    <!-- Disable other headers except X-Frame-Options (not required, but enhances performance)-->
    <init-param>
        <param-name>hstsEnabled</param-name>
        <param-value>false</param-value>
    </init-param>
    <init-param>
        <param-name>blockContentTypeSniffingEnabled</param-name>
        <param-value>false</param-value>
    </init-param>
    <init-param>
        <param-name>xssProtectionEnabled</param-name>
        <param-value>false</param-value>
    </init-param>
</filter>
<filter-mapping>
    <filter-name>HttpHeaderSecurityFilter_AntiClickJacking</filter-name>
    <url-pattern>/carbon/*</url-pattern>
    <url-pattern>/dashboard/*</url-pattern>
</filter-mapping>
```

If an application requires enabling `SAMEORIGIN` framing only for a particular URL,  below configuration can be used :

```xml
<filter>
    <filter-name>HttpHeaderSecurityFilter</filter-name>
    <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
    <init-param>
        <param-name>hstsEnabled</param-name>
        <param-value>false</param-value>
    </init-param>
</filter>
<filter>
    <filter-name>HttpHeaderSecurityFilter_AntiClickJacking_SpecialURL</filter-name>
    <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
    <!-- Disable other headers except X-Frame-Options (not required, but enhances performance)-->
    <init-param>
        <param-name>hstsEnabled</param-name>
        <param-value>false</param-value>
    </init-param>
    <init-param>
        <param-name>blockContentTypeSniffingEnabled</param-name>
        <param-value>false</param-value>
    </init-param>
    <init-param>
        <param-name>xssProtectionEnabled</param-name>
        <param-value>false</param-value>
    </init-param>
    <init-param>
        <param-name>antiClickJackingOption</param-name>
        <param-value>SAMEORIGIN</param-value>
    </init-param>
</filter>
<!-- Global filter mapping -->
<filter-mapping>
    <filter-name>HttpHeaderSecurityFilter</filter-name>
    <url-pattern>*</url-pattern>
</filter-mapping>
<!-- Overriding filter mapping for the specific URL, should come after global filter mapping-->
<filter-mapping>
    <filter-name>HttpHeaderSecurityFilter_AntiClickJacking_SpecialURL</filter-name>
    <url-pattern>/special_url/*</url-pattern>
</filter-mapping>
```

Further details on configuration is available at Tomcat official documentation on `HTTP_Header_Security_Filter`[^8] and relevant source files[^9].


## Securing Jaggery Applications
It is required to upgrade Jaggery version to 0.12.6 or later. 


### Recommended Default Configuration
Recommended jaggery.conf filter mapping for development environments is as follows (WSO2 products should be released with this default configuration):

```json
"filters":[
    {
        "name":"HttpHeaderSecurityFilter",
        "class":"org.apache.catalina.filters.HttpHeaderSecurityFilter",
        "params" : [{"name" : "hstsEnabled", "value" : "false"}]
    }
],
"filterMappings":[
    {
        "name":"HttpHeaderSecurityFilter",
        "url":"*"
    }
]
```


### Recommandation Production Configuration
Recommended jaggery.conf filter mapping for production environments is as follows :

```json
"filters":[
    {
        "name":"HttpHeaderSecurityFilter",
        "class":"org.apache.catalina.filters.HttpHeaderSecurityFilter"
        "params" : [{"name" : "hstsMaxAgeSeconds", "value" : "15768000"}]
    }
],
"filterMappings":[
    {
        "name":"HttpHeaderSecurityFilter",
        "url":"*"
    }
]
```


### Customized Configuration
It is possible to use filter mappings to cater product level customizations required. For example in order to enable `X-Frame-Options` only for particular URLs, below configuration can be used:

```json
"filters":[
    {
        "name":"HttpHeaderSecurityFilter",
        "class":"org.apache.catalina.filters.HttpHeaderSecurityFilter"
        "params" : [{"name" : "antiClickJackingEnabled", "value" : "false"}]
    },
    {
        "name":"HttpHeaderSecurityFilter_AntiClickJacking",
        "class":"org.apache.catalina.filters.HttpHeaderSecurityFilter"
        "params" : [
            {"name" : "hstsEnabled", "value" : "false"},
            {"name" : "blockContentTypeSniffingEnabled", "value" : "false"},
            {"name" : "xssProtectionEnabled", "value" : "false"}
        ]
    }
],
"filterMappings":[
    {
        "name":"HttpHeaderSecurityFilter",
        "url":"*"
    },
    {
        "name":"HttpHeaderSecurityFilter_AntiClickJacking",
        "url":"/example1/*"
    },
    {
        "name":"HttpHeaderSecurityFilter_AntiClickJacking",
        "url":"/example2/*"
    }
],
```


If an application requires enabling SAMEORIGIN framing only for a particular URL,  below configuration can be used:

```json
"filters":[
    {
        "name":"HttpHeaderSecurityFilter",
        "class":"org.apache.catalina.filters.HttpHeaderSecurityFilter",
        "params" : [{"name" : "hstsEnabled", "value" : "false"}]
    },
    {
        "name":"HttpHeaderSecurityFilter_AntiClickJacking_SpecialURL",
        "class":"org.apache.catalina.filters.HttpHeaderSecurityFilter"
        "params" : [
            {"name" : "hstsEnabled", "value" : "false"},
            {"name" : "blockContentTypeSniffingEnabled", "value" : "false"},
            {"name" : "xssProtectionEnabled", "value" : "false"},
            {"name" : "antiClickJackingOption", "value" : "SAMEORIGIN"}
       ]
    }
],
"filterMappings":[
    {
        "name":"HttpHeaderSecurityFilter",
        "url":"*"
    },
    {
        "name":"HttpHeaderSecurityFilter_AntiClickJacking_SpecialURL",
        "url":"/special_url/*"
    }
],
```

Further details on configuration is available at Tomcat official documentation on `HTTP_Header_Security_Filter`[^8] and relevant source files[^9].


## References
[^1]: [https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection)
[^2]: [https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options)
[^3]: [https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)
[^4]: [https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)
[^5]: [https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Public-Key-Pins](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Public-Key-Pins)
[^6]: [https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)
[^7]: [https://content-security-policy.com/](https://content-security-policy.com/)
[^8]: [https://tomcat.apache.org/tomcat-7.0-doc/config/filter.html#HTTP_Header_Security_Filter](https://tomcat.apache.org/tomcat-7.0-doc/config/filter.html#HTTP_Header_Security_Filter)
[^9]: [https://github.com/apache/tomcat/blob/trunk/java/org/apache/catalina/filters/HttpHeaderSecurityFilter.java](https://github.com/apache/tomcat/blob/trunk/java/org/apache/catalina/filters/HttpHeaderSecurityFilter.java)
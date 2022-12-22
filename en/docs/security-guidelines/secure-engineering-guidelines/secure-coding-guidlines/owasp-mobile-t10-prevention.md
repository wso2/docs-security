---
title: OWASP Mobile Top 10 Prevention
category: security-guidelines
published: October 22, 2018
version: 2.0
---

# OWASP Mobile Top 10 Prevention
<p class="doc-info">Version: 2.0</p>
___

## Introduction
This section discusses OWASP Mobile Top 10 prevention techniques that should be followed by WSO2 engineers while engineering mobile applications.


## M1 - Improper Platform Usage
This category covers misuse of a platform feature or failure to use platform security controls. It might include Android intents, platform permissions, misuse of TouchID, the Keychain, or some other security control that is part of the mobile operating system[^1].


### Prevention Techniques
The best method of preventing improper platform usage is to follow the guidelines and best practices published by the respective platforms, on secure development of the mobile applications. These guidelines include the proper way to implement the relevant features and how to maintain them. Also, make sure to check whether the application behaves as it was intended without misusing platform features.


### Android Specific Recommendations

#### Using Intents
Intents are used to request an action such as starting an activity, starting a service or delivering a broadcast from another app component. Explicit intents specify the component by the fully qualified class name. Usually, these are used to start a component within the app. Implicit intents declare a general action to be handled by another application.

Do not use an implicit intent to start a service as implicit intents allow any other app component to respond to the intent and start the Service transparently to the user. Use an explicit intent where the component can be specified using the fully qualified class name.   

!!! info "Note"
    From Android 5.0 (API level 21) onwards, the system will throw an exception if an implicit intent is used to start a service.

Set the android:exported attribute to false for the specific activity, service or receiver to limit the exposure to other components.

!!! example
    A Service can be declared in the App Manifest  with the `android:exported` attribute set to false as follows:
    ```xml
    <service 
            android:exported="false"
            >
        . . .
    </service>
    ```

!!! danger error "Alert - Approval Required"
    If any component requires that `android:exported` attribute to be set to true, the use-case, as well as controls in place to provide required protection, must be reviewed and approved by the Security and Compliance Team, before proceeding with the release of such component.


Data received by public components should be treated as untrusted data and needs to be properly validated and sanitized before usage.


!!! example
    An email address received from a public component must be verified against the email address specifications defined by RFC2822[^2].


## M2 - Insecure Data Storage
This category covers insecure data storage and unintended data leakage[^1].


### Prevention Techniques

### Client-side data storage
Data stored in the mobile device has a risk of being exposed to an outside attacker through malware or a lost or stolen device. To reduce the impact of an attack, limit the amount of data stored in a mobile device and use a strong encryption algorithm to encrypt the stored data.


#### Android Specific Recommendations

* **Using internal storage**

    Do not create files with permissions `MODE_WORLD_WRITEABLE`[^3] or `MODE_WORLD_READABLE`[^4] as all applications will have permission to read or write to the file. Use a content provider[^5] to allow other applications to securely access and modify data.

    !!! info "Note"
        Constants `MODE_WORLD_WRITEABLE` and `MODE_WORLD_READABLE` were deprecated in API level 17.

* **Using external storage**

    Files stored in the external storage have global read and write permissions. Therefore external storage should not be used to store any sensitive data. Also, input validations should be applied when using data from external storage. 

    It is not recommended to store executable files in external storage. If the application requires loading executable files from external storage, make sure to sign and cryptographically verify the content before dynamic loading.
 
* **Database Related Recommendations**
    Using a third-party encryption can withstand a threat to the native protection provided by the OS. The master key for the encryption should be randomly generated and encrypted using a passphrase from the user by the time the data is processed. Unencrypted master key or the passphrase should not be stored on the device.

    !!! example
        SQLCipher is an open source extension to SQLite that provides transparent 256-bit AES encryption of database files[^6].


### HTTP response caching
HTTP responses can have sensitive information. Caching them can increase the risk of data leakage. Therefore response caching should be disabled for sensitive data.

!!! example
    API responses can contain sensitive information such as bank account details that should not be cached.


#### Android Specific Recommendations
Do not use `HttpResponseCache`[^7] to cache sensitive data.


### Keyboard press caching
Mobile devices cache the keyboard input to be used in auto-suggesting words to the user. This feature can be a vulnerability when sensitive information of one user is cached and later suggested to a different user. Therefore auto suggest feature must be disabled to avoid keyboard press caching for sensitive information.


#### Android Specific Recommendations
The user dictionary in android saves the words entered by the user to be used for auto-correction. Since this dictionary is available to other applications without permission, sensitive information can get leaked to other apps. To prevent this, use `android:inputType= "textNoSuggestions"` for sensitive data fields or create custom keyboards with auto-suggest disabled.


### Copy/Paste buffer caching
When using copy and pasting, the data is initially copied into a clipboard. Malicious applications can access this clipboard cache to extract sensitive data. Disable the copy or paste functionality for sensitive data fields to prevent these types of copy or paste buffer caching.
!!! example
    The application should not allow users to copy or paste credit card details. 


### Logging
Debug logs are used to identify flaws in the application. However, the information provided by debug logs can be useful for an attacker to gather knowledge about the application. Therefore debug logs should be disabled in the production environment.  


#### Android Specific Recommendations
Logs are a shared resource for Android. Any application with `READ_LOGS` permission can view them. Production applications should limit the logging by using debug flags and configure logging levels by defining custom log classes.
 

#### HTML5 local storage
HTML5 local storage can be used to store data within the browser between HTTP requests. Since this storage is accessible by JavaScript, cross-site scripting attacks can be used to steal the data. Therefore sensitive data should not be stored in HTML5 local storage.


#### Browser Cookie objects
Cookies are used by servers to store data in the browser. Often session related data are stored inside cookies. Use the `Secure` flag to indicate that only HTTPS requests are allowed to transfer cookies and the HTTP Only flag to make cookies inaccessible to JavaScript's `Document.cookie` API. Make sure that both Secure and HTTP Only flags are set to cookies containing sensitive data.


#### Analytics data sent to 3rd parties
Mobile applications may need to have access to user’s personal information for functionality purposes. However, the application should make sure that these sensitive pieces of information are not being sent to third parties violating the privacy of the user. 

!!! example
    Mobile applications send data to Google Analytics and Facebook Graph API for analytical purposes.


## M3 - Insecure Communication
This section covers poor handshaking, incorrect SSL versions, weak negotiation, cleartext communication of sensitive assets, etc[^1].
 

### Prevention Techniques

### SSL/TLS
Use TLS to serve all sensitive and nonsensitive traffic. This will prevent having mixed SSL sessions where the user’s session ID might get exposed.


#### Android Specific Recommendations
The application can choose to avoid unencrypted HTTP traffic by using cleartextTrafficPermitted="false" in the network security config file[^8].
 
!!! example
    To enforce HTTPS on all connections to wso2.com use the following code in the network_security_config.xml
    ```xml
    <network-security-config>
        <domain-config cleartextTrafficPermitted="false">
            <domain includeSubdomains="true">wso2.com</domain>
        </domain-config>
    </network-security-config>
    ```

### Self Signed Certificates
Usually, self-signed certificates are used in the development stage for the easiness of the developer. However, do not accept self-signed certificates in the production application as they allow an attacker to easily intercept the communication using their own self-signed certificate.
 

### Certificate Pinning
The application accepts all the certificates signed by trusted Certificate Authorities(CAs). If one of these trusted CA gets compromised and starts issuing fraudulent certificates, they will be accepted by the application. Certificate pinning can be used to store the certificate locally along with the domain name. This allows the detection of fraudulent certificates as the application can compare previously stored certificates with the new ones.
 
#### Android Specific Recommendations

!!! example
    To use certificate pinning on wso2.com use the following code in the `network_security_config.xml`. Here, base64 encoded Subject Public Key Information of the wso2 certificate should be used as the pin.
    ```xml
    <network-security-config>
        <domain-config>
            <domain includeSubdomains="true">wso2.com</domain>
            <pin-set expiration="2020-01-01">
                <pin digest="SHA-256">2pCcYrG90hDFxwOCsVya7wpbQjqhBy3OPsFyyT+7108=</pin>
            </pin-set>
        </domain-config>
    </network-security-config>
    ```

!!! info "Note"
    Always include a backup pin to use in an event of a  certificate change.

!!! info "Note"
    To protect from compromised CAs, Android has the ability to blacklist certain certificates or even whole CAs. While this list was historically built into the operating system, starting in Android 4.2 this list can be remotely updated to deal with future compromises[^9].

 
### Hostname Verification
Hostname verification is verifying whether the hostname of the server that the application is trying to connect to is specified in the certificate presented by the server. It is important to have this verification as this will make sure that the server has presented the right certificate.


#### Android Specific Recommendations
SSLSocket[^10] does not perform hostname verification. The application has to verify the hostname of the certificate by calling the method `getDefaultHostnameVerifier()` with the expected hostname.

Using `org.apache.http.conn.ssl.AllowAllHostnameVerifier` or `SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER` allows the application to accept all certificates. Make sure that these are not being used in the production code.  
 
!!! info "Note"
    `org.apache.http.conn.ssl.AllowAllHostnameVerifier` and `SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER` were deprecated in API level 22.


### SMS
SMS is a protocol that has been designed for user to user communication. It is unencrypted and not properly authenticated. Therefore, do not use SMS for sensitive data transfer.


#### Android Specific Recommendations
In Android, SMS messages are transmitted as broadcast intents. Anyone with the READ_SMS permission can read the SMS messages on the device.  Therefore, do not use SMS for data transfer. 
 

## M4 - Insecure Authentication

This category captures notions of authenticating the end user or bad session management. This can include:
* Failing to identify the user at all when that should be required
* Failure to maintain the user's identity when it is required
* Weaknesses in session management[^1]
 

### Prevention Techniques

### Local Authentication
Local Authentication can be bypassed if the attacker has the ability to tamper with the application. Therefore, all the authentication checks should be performed by a backend server.

!!! danger error "Alert - Approval Required"
    If any component requires implementing local authentication, the use-case, as well as controls in place to provide the required protection, must be reviewed and approved by the Security and Compliance Team, before proceeding with the release of such component.

### Password Policy
Ensure that a strong password policy is enforced by the authentication server.  Use a similar strong password policy if the authentication is performed locally with the approval mentioned in the Local Authentication section.


### Device Identifiers
Do not use device-specific identifiers for authentication. In an event of a change of ownership of the phone, these IDs can expose the previous owner’s data to the new owner.

### Geo-Location
Geo-location should not be used as an authentication mechanism as attackers can easily spoof the geo-location. If an application requires the use of geo-location, ensure that the application has implemented a proper geo-location spoof detection mechanism to detect location anomalies.


### Token Revocation
In the event of a lost or stolen device, the application should have the ability to invalidate the authenticated session on the lost/stolen device by revoking a device-specific token.


## M5 - Insufficient Cryptography
The code applies cryptography to a sensitive information asset. However, cryptography is insufficient in some ways. Note that anything and everything related to TLS or SSL goes in M3. Also, if the app fails to use cryptography at all when it should, that probably belongs in M2. This category is for issues where cryptography was attempted, but it wasn't done correctly.
 

### Prevention Techniques

### Key Generation
Use a secure random number generator to generate strong keys that can withstand brute force attacks. 


#### Android Specific Recommendations
Use the secure random number generator, `SecureRandom`[^11] to initialize any cryptographic keys generated by `KeyGenerator`[^12]. The use of a key that is not generated with a secure random number generator significantly weakens the strength of the algorithm and may allow offline attacks.


### Key Storage
Do not store keys in plaintext format. Use a cryptographic vault for secure storage of keys and make sure that compromised or outdated keys are properly revoked.  


#### Android Specific Recommendations
Use the `KeyStore`[^13] for long-term storage and retrieval of cryptographic keys.
 

### Custom Encryption Algorithms
Do not implement custom encryption algorithms. Use a proper algorithm that is widely used and accepted as secure. 


#### Android Specific Recommendations
Do not write custom protocols for implementing secure tunnels. Instead, use  `HttpsURLConnection`[^14] or `SSLSocket`[^15]. If a custom protocol is needed, do not implement new algorithms. Instead, use existing cryptographic algorithms such as the implementations of AES and RSA provided in the `Cipher`[^16] class. 


### Deprecated Algorithms
OWASP defines the following algorithms as deprecated and not to be used for encryption purposes.

* RC2
* MD4
* MD5
* SHA1


## M6 - Insecure Authorization
This is a category to capture any failures in the authorization. It is distinct from authentication issues. If the app does not authenticate users at all in a situation where it should, then that is an authentication failure, not an authorization failure[^1].
 

### Prevention Techniques

### Permissions
Do not use roles and permission information coming from the mobile device for authorization. The back-end code should independently verify that any incoming identifiers associated with a request (operands of a requested operation) that come along with the identifier match up and belong to the incoming identity. 

It is a must to request only the minimum number of permissions that your app requests, to reduce the risk of misusing permissions. In application documentation, it is required to mention the actual usage of each permission, so that users and security reviewers have access to this information. 
 
#### Android Specific Recommendations
In Android, permissions are categorized into four protection levels[^17].
 
* **`normal`**
    The default value. A lower-risk permission that gives requesting applications access to isolated application-level features, with minimal risk to other applications, the system, or the user. The system automatically grants this type of permission to a requesting application at installation, without asking for the user's explicit approval (though the user always has the option to review these permissions before installing).

* **`dangerous`**

    A higher-risk permission would give a requesting application access to private user data or control over the device that can negatively impact the user. Because this type of permission introduces potential risk, the system may not automatically grant it to the requesting application. For example, any dangerous permissions requested by an application may be displayed to the user and require confirmation before proceeding, or some other approach may be taken to avoid the user automatically allowing the use of such facilities.

* **`signature`**

    A permission that the system grants only if the requesting application is signed with the same certificate as the application that declared the permission. If the certificates match, the system automatically grants the permission without notifying the user or asking for the user's explicit approval.

* **`signatureOrSystem`**
    
    A permission that the system grants only to applications that are in the Android system image or that are signed with the same certificate as the application that declared the permission. The `signatureOrSystem` permission is used for certain special situations where multiple vendors have applications built into a system image and need to share specific features explicitly because they are being built together.


When defining new permissions, use the dangerous protection level if the permission has the ability to access the stored data or affect the operation of other applications. Use the signature protection level if the permission has the ability to share data between applications signed with the same certificate.
 
When exposing data over Interprocess Communication(IPC), check the permissions of the data that are being exposed. Other applications might not have the same level of permission for the exposed data.
 

### Proof Key for Code Exchange (PKCE)
Using OAuth 2.0 authorization code grant type is susceptible to interception attacks. An attacker has the ability to intercept the authorization code received from the authorization endpoint via unprotected communication such as inter-application communication within the client’s operating system. Proof Key for Code Exchange (PKCE)[^18] is used to mitigate this vulnerability. In PKCE,

* A unique cryptographic random key (code verifier) is created by the application with every authorization request. 
* The code verifier is transformed into a code challenge and sent to the authorization server along with the transform method. 
* The authorization server stores the code challenge and the transform method. 
* During the request for an access token, the application has to send its generated code verifier to the authorization server. 
* The server transforms the received code verifier with the stored transform method and compares it with the previously stored code challenge.
 

## M7-Poor Code Quality
This would be the catch-all for code-level implementation problems in the mobile client. That is distinct from server-side coding mistakes. This would capture things like buffer overflows, format string vulnerabilities, and various other code-level mistakes where the solution is to rewrite some code that is running on the mobile device[^1].


### Prevention Techniques

### Input Validation
All the input from the app and user should be treated as untrusted data. Therefore, input validation must be used when handling such data. 


#### Android Specific Recommendations
When accessing a content provider, use parameterized query methods such as `query()`, `update()`, and `delete()` to prevent potential SQL injection from untrusted sources. 

If the content provider is serving files based on filename, make sure that path traversals are filtered out.


### third-party Libraries
Applications rely heavily on third-party libraries. Making the application secure won’t be enough if the third-party libraries contain vulnerabilities. Therefore, security auditing must thoroughly test third-party libraries for vulnerabilities.
 

### Buffer Overflows
Buffer overflows are not possible in Java. However, the application is susceptible to buffer overflows if it contains native code such as C or C++. To avoid buffer overflows, make sure that the length of the incoming buffer data will not exceed the length of the target buffer.


#### Android Specific Recommendations
Run Android Lint[^19] on the application code using Android SDK and correct any identified issues.
 

## M8 - Code Tampering
This category covers binary patching, local resource modification, method hooking, method swizzling, and dynamic memory modification.
Once the application is delivered to the mobile device, the code and data resources are resident there. An attacker can either directly modify the code, change the contents of memory dynamically, change or replace the system APIs that the application uses, or modify the application's data and resources. This can provide the attacker with a direct method of subverting the intended use of the software for personal or monetary gain[^1].
 

### Prevention Techniques

### Tamper Detection 
Use tamper detection techniques such as checksums or digital signatures to identify code tampering.

In an event of code tampering, use an appropriate mechanism such as wiping the user data or sending a notification to the server to protect the sensitive data.

### Restricting Debuggers
Prevent the operating system from permitting to attach a debugger to the application. This will increase the complexity of an attack[^20].


#### Android Specific Recommendations
Set the `android:debuggable="false"`  in the application manifest to restrict the debuggers.


### Stripping Binaries
Strip the native binaries to increase the difficulty for an attacker to debug or reverse engineer.
 

## M9 - Reverse Engineering
This category includes analysis of the final core binary to determine its source code, libraries, algorithms, and other assets. Binary inspection tools give the attacker insight into the inner workings of the application. This may be used to exploit other nascent vulnerabilities in the application, as well as reveal information about back-end servers, cryptographic constants and ciphers, and intellectual property[^1].

 
### Prevention Techniques

### Obfuscation
Use an obfuscation tool to modify the code to become difficult to understand if the application gets decompiled. To measure the effectiveness of the obfuscator, use a deobfuscator.

!!! example
    Hex Rays and Hopper are popular deobfuscators that are used in reverse engineering applications. 


#### Android Specific Recommendations
`ProGuard`[^21] is a Java class file shrinker, optimizer, obfuscator, and preverifier. The obfuscation step in ProGuard renames the remaining classes, fields, and methods using short meaningless names making it difficult for attackers to reverse engineer.
 

#### Hide Application Logic
In an event of reverse engineering, the attacker might get hold of the source code containing all the application logic. To reduce the impact critical parts of the application logic can be moved to a web service. 


#### Use C/C++ 
Java is easier to decompile when compared to C/C++. Use C/C++ to write security-sensitive sections of the code to make reverse engineering difficult for an attacker. 


## M10 - Extraneous Functionality
Often, developers include hidden backdoor functionality or other internal development security controls that are not intended to be released into a production environment. For example, a developer may accidentally include a password as a comment in a hybrid app. Another example includes disabling 2-factor authentication during testing[^1].


### Prevention Techniques
* Examine the app's configuration settings to discover any hidden switches.
* Verify that all test code is not included in the final production build of the app.
* Examine all API endpoints accessed by the mobile app to verify that these endpoints are well-documented and publicly available.
* Examine all log statements to ensure nothing overly descriptive about the backend is being written to the logs[^22].


## References
[^1]: [https://www.owasp.org/index.php/Mobile_Top_10_2016-Top_10](https://www.owasp.org/index.php/Mobile_Top_10_2016-Top_10)
[^2]: [https://tools.ietf.org/html/rfc2822#page-15](https://tools.ietf.org/html/rfc2822#page-15)
[^3]: [https://developer.android.com/reference/android/content/Context.html#MODE_WORLD_WRITEABLE](https://developer.android.com/reference/android/content/Context.html#MODE_WORLD_WRITEABLE)
[^4]: [https://developer.android.com/reference/android/content/Context.html#MODE_WORLD_READABLE](https://developer.android.com/reference/android/content/Context.html#MODE_WORLD_READABLE)
[^5]: [https://developer.android.com/guide/topics/providers/content-providers.html](https://developer.android.com/guide/topics/providers/content-providers.html)
[^6]: [https://www.zetetic.net/sqlcipher/](https://www.zetetic.net/sqlcipher/)
[^7]: [https://developer.android.com/reference/android/net/http/HttpResponseCache.html](https://developer.android.com/reference/android/net/http/HttpResponseCache.html)
[^8]: [https://developer.android.com/training/articles/security-config.html](https://developer.android.com/training/articles/security-config.html)
[^9]: [https://developer.android.com/training/articles/security-ssl.html](https://developer.android.com/training/articles/security-ssl.html)
[^10]: [https://developer.android.com/reference/javax/net/ssl/SSLSocket.html](https://developer.android.com/reference/javax/net/ssl/SSLSocket.html)
[^11]: [https://developer.android.com/reference/java/security/SecureRandom.html](https://developer.android.com/reference/java/security/SecureRandom.html)
[^12]: [https://developer.android.com/reference/javax/crypto/KeyGenerator.html](https://developer.android.com/reference/javax/crypto/KeyGenerator.html)
[^13]: [https://developer.android.com/reference/java/security/KeyStore.html](https://developer.android.com/reference/java/security/KeyStore.html)
[^14]: [https://developer.android.com/reference/javax/net/ssl/HttpsURLConnection.html](https://developer.android.com/reference/javax/net/ssl/HttpsURLConnection.html)
[^15]: [https://developer.android.com/reference/javax/net/ssl/SSLSocket.html](https://developer.android.com/reference/javax/net/ssl/SSLSocket.html)
[^16]: [https://developer.android.com/reference/javax/crypto/Cipher.html](https://developer.android.com/reference/javax/crypto/Cipher.html)
[^17]: [https://developer.android.com/guide/topics/manifest/permission-element.html](https://developer.android.com/guide/topics/manifest/permission-element.html)
[^18]: [https://tools.ietf.org/html/rfc7636](https://tools.ietf.org/html/rfc7636)
[^19]: [http://tools.android.com/tips/lint](http://tools.android.com/tips/lint)
[^20]: [https://books.nowsecure.com/secure-mobile-development/en/coding-practices/code-complexity-and-obfuscation.html](https://books.nowsecure.com/secure-mobile-development/en/coding-practices/code-complexity-and-obfuscation.html)
[^21]: [https://www.guardsquare.com/en/proguard](https://www.guardsquare.com/en/proguard)
[^22]: [https://www.owasp.org/index.php/Mobile_Top_10_2016-M10-Extraneous_Functionality](https://www.owasp.org/index.php/Mobile_Top_10_2016-M10-Extraneous_Functionality)

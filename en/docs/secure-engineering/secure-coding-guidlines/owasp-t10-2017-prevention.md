---
title: OWASP Top 10 - 2017 Prevention
category: secure-engineering
published: 22nd October 2018
version: 2.1
---

# OWASP Top 10 - 2017 Prevention

<p class="doc-info">Published: 22nd October 2018</p>
<p class="doc-info">Version: 2.1</p>
---

## A1 - Injection

### SQL Injection
A SQL injection attack consists of insertion or **injection** of a SQL query via the input data from the client to the application. A successful SQL injection exploit can read sensitive data from the database, modify database data (Insert/Update/Delete), execute administration operations on the database (such as shutdown the DBMS), recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. SQL injection attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands [1].


#### Prevention Techniques
Use secure language constructs (Example: PreparedStatement in Java) when executing SQL statements. Use language specific best practices when using secure language constructs to avoid any possible misuses.

Restructure the methods so that the application does not accept table names, column names, ordering information, offset details or any other value that cannot be parameterized using language specific best practices.


!!! example
    In Java context, ORDER BY column name of below query can not be provided as a PreparedStatement parameter.

    ```sql
    SELECT ID,NAME FROM EXAMPLE_TABLE WHERE AGE > ? ORDER BY DYNAMIC_COLUMN_NAME;
    ```


If user input must be used in sections that cannot be parameterized using secure language constructs, perform allowlisting against the user input.


!!! example
    A allowlist should be maintained which includes an acceptable list of inputs for **DYNAMIC_COLUMN_NAME**. User input should be rejected if provided input is not within expected set of values.


#### Java Specific Recommendations
Use PreparedStatements to prevent SQL injections. The statement will be compiled and the user variables will be assigned to the query parameters in the runtime. Since user variables are being set to a precompiled SQL statement, this approach avoids possibility of SQL injections.


!!! bug error "Example Incorrect Usage"
    
    ```
    {==String query = "SELECT account_balance FROM user_data WHERE user_name = " + request.getParameter("customerName");==}
    try {
        Statement statement = connection.createStatement( ... );
        ResultSet results = statement.executeQuery( query );
    }
    //Catch block...
    ```


!!! success check done "Example Correct Usage"
    ```java
    String customerName = request.getParameter("customerName");
    //Validations. Etc...

    String query = "SELECT account_balance FROM user_data WHERE user_name = ?";
    try {
    PreparedStatement preparedStatement = connection.prepareStatement( query );
    preparedStatement.setString( 1, customerName );
    ResultSet results = preparedStatement.executeQuery();
    }
    //Catch block...
    ```


When processing dynamic query segments that cannot be set as PreparedStatement parameters (table names, column names, ordering information, offset details), validate user input against a allowlist. This approach avoids the risk of providing end user the ability to append anything uncontrolled to the SQL query.

Example 1:

!!! bug error "Example Incorrect Usage"
    ```java
    String customerType = request.getParameter("customerType");
    String order = request.getParameter("order");
    //Validations. Etc...
    
    String query = "SELECT user_name, account_balance FROM user_data WHERE user_type = ? ORDER BY " +   order;
    try {
        PreparedStatement preparedStatement = connection.prepareStatement( query );
        preparedStatement.setString( 1, customerType );
        ResultSet results = preparedStatement.executeQuery();
    }
    //Catch block...
    ```


!!! success check done "Example Correct Usage"
    ```java
    //Class level static map maintaining "user input to database column" mapping
    private static final Map<String, String> validOrderColumns = new HashMap<String, String>();
    validOrderColumns.add("accountBalance", "account_balance");
    validOrderColumns.add("userName", "user_name");
    
    //Method definition...
    String customerType = request.getParameter("customerType");
    String orderColumn = request.getParameter("orderColumn");
    String orderDirection = request.getParameter("orderDirection");
    
    if (orderDirection.equalsIgnoreCase("DESC")) {
        orderDirection = "DESC";
    } else {
        orderDirection = "ASC";
    }
    
    orderColumn = validOrderColumns.get(orderColumn);
    //Validations. Etc...
    
    String query = "SELECT user_name, account_balance FROM user_data WHERE user_type = ? ORDER BY " +   orderColumn + " " + orderDirection;
    try {
        PreparedStatement preparedStatement = connection.prepareStatement( query );
        preparedStatement.setString( 1, customerType );
        ResultSet results = preparedStatement.executeQuery();
    }
    //Catch block...
    ```


Example 2:


!!! bug error "Example Incorrect Usage"
    ```java
    //...
    query = "SELECT * FROM " + columnFamily + " WHERE " +
    APIUsageStatisticsClientConstants.API_PUBLISHER + " = ?";

    if (selectRowsByColumnName != null) {
        query = query + " AND " + selectRowsByColumnName + " = ? ";
    }

    try {
        PreparedStatement preparedStatement = connection.prepareStatement( query );
        preparedStatement.setString( 1, publisher );
        if (selectRowsByColumnName != null) {
            preparedStatement.setString( 2, selectRowsByColumnValue );
        }
        ResultSet results = preparedStatement.executeQuery();
    }
    //Catch block
    ```


!!! success check done "Example Correct Usage"
    ```java
    //Class level static map maintaining user input to column mapping
    private static final Map<String, String> validSelectColumns = new HashMap<String, String>();
    validSelectColumns.add("apiName", "api_name");
    validSelectColumns.add("apiId", "api_id");

    private static final Map<String, String> validColumnFamilies = new HashMap<String, String>();
    validSelectColumns.add("commonApis", "COMMON_APIS");
    validSelectColumns.add("corporateApis", "CORPORATE_APIS");

    //Method definition...
    String columnFamily = validSelectColumns.get(columnFamilyUserInput)
    if(columnFamily == null) {
        //Throw required exceptions or errors.
        return;
    }

    query = "SELECT * FROM " + columnFamily + " WHERE " +
    APIUsageStatisticsClientConstants.API_PUBLISHER + " = ?";

    if (selectRowsByColumnName != null) {
        String columnName = validSelectColumns.get(selectRowsByColumnName);
        if(columnName != null) {
            query = query + " AND " + columnName + " = ? ";
        } else {
            selectRowsByColumnName = null;
        }
    }

    try {
        PreparedStatement preparedStatement = connection.prepareStatement( query );
        preparedStatement.setString( 1, publisher );
        if (selectRowsByColumnName != null) {
            preparedStatement.setString( 2, selectRowsByColumnValue );
        }
        ResultSet results = preparedStatement.executeQuery();
    }
    //Catch block...
    ```


#### PHP Specific Recommendations
Use PHP Data Objects (PDO) Extension or MySQL Improved Extension when executing queries that include user inputs. Make sure to use parameterizing capabilities of the extensions.


!!! bug error "Example Incorrect Usage"
    ```php
    <?php
        $query = "SELECT id, name, inserted, size FROM products WHERE size ='$size'";
        $result = odbc_exec($conn, $query);
    ?>
    ```

!!! bug error "Example Incorrect Usage"
    ```php
    <?php
        $query = "SELECT id, name, inserted, size FROM products WHERE size = '$size'";
        $result = pg_query($conn, $query);
    ?>
    ```

!!! bug error "Example Incorrect Usage"
    ```php
    <?php
        $query = "SELECT id, name, inserted, size FROM products WHERE size = '$size'";
        $result = mssql_query($conn, $query);
    ?>
    ```


Using PHP Data Objects (PDO) Extension [2],[3]


!!! success check done "Example Correct Usage"
    ```php
    <?php
        $stmt = $pdo->prepare('SELECT * FROM employees WHERE name = :name');
        $stmt->execute(array('name' => $name));
        foreach ($stmt as $row) {
            // do something with $row
        }
    ?>
    ```


Using MySQL Improved Extension [4],[3]


!!! success check done "Example Correct Usage"
    ```php
    <?php
        $stmt = $dbConnection->prepare('SELECT * FROM employees WHERE name = ?');
        $stmt->bind_param('s', $name);

        $stmt->execute();

        $result = $stmt->get_result();
        while ($row = $result->fetch_assoc()) {
            // do something with $row
        }
    ?>
    ```


Example with query segments that cannot be parameterized with PDO or MySQL Improved Extension [5]:


!!! bug error "Example Incorrect Usage"
    ```php
    <?php
        $offset = $argv[0]; // beware, no input validation!
        $query = "SELECT id, name FROM products ORDER BY name LIMIT 20 OFFSET $offset;";
        $result = pg_query($conn, $query);
    ?>


!!! success check done "Example Correct Usage"
    ```php
    <?php
        settype($offset, 'integer');
        $query = "SELECT id, name FROM products ORDER BY name LIMIT 20 OFFSET $offset;";

        // please note %d in the format string, using %s would be meaningless
        $query = sprintf("SELECT id, name FROM products ORDER BY name LIMIT 20 OFFSET %d;",$offset);
        $result = pg_query($conn, $query);
    ?>
    ```


### LDAP Injection
LDAP Injection is an attack used to exploit web based applications that construct LDAP statements based on user input. When an application fails to properly sanitize user input, it's possible to modify LDAP statements using a local proxy. This could result in the execution of arbitrary commands such as granting permissions to unauthorized queries, and content modification inside the LDAP tree. The same advanced exploitation techniques available in SQL Injection can be similarly applied in LDAP Injection [6],[7].

All user inputs that are getting directly appended to any LDAP queries should be filtered through an encoding function that does proper encoding for LDAP [8].


!!! bug error "Example Incorrect Usage"
    ```java
    String grpSearchFilter = searchFilter.replace("?",role);
    groupResults = searchInGroupBase(grpSearchFilter,...)
    ```


!!! success check done "Example Correct Usage"
    ```java
    String grpSearchFilter = searchFilter.replace("?", escapeSpecialCharactersForFilter(role));
    groupResults = searchInGroupBase(grpSearchFilter,...)
    ```


### OS Command Injection
Command injection is an attack in which the goal is execution of arbitrary commands on the host operating system via a vulnerable application. Command injection attacks are possible when an application passes unsafe user supplied data (forms, cookies, HTTP headers etc.) to a system shell. In this attack, the attacker-supplied operating system commands are usually executed with the privileges of the vulnerable application. Command injection attacks are possible largely due to insufficient input validation [9].


#### Prevention Techniques
Products or applications should not use user inputs in constructing OS commands.


!!! danger error "Alert - Approval Required"
    If any component requires that, user input to be appended to an OS command or to be interpreted as OS command, the use-case, as well as controls in place to provide required protection, must be reviewed and approved by Platform Security Team, before proceeding with the release of such component.


#### Java Specific Recommendations
WSO2 Products should not use `java.lang.Runtime.getRuntime()`, `java.lang.ProcessBuilder` or any other method to execute OS commands, constructed based on user input.


!!! bug error "Example Incorrect Usage"
    ```java
    java.lang.Runtime.getRuntime().exec(userInput);
    ```


!!! bug error "Example Incorrect Usage"
    ```java
    java.lang.Runtime.getRuntime().exec("curl -v -k " + userInput);
    ```


!!! bug error "Example Incorrect Usage"
    ```java
    java.lang.ProcessBuilder processBuilder = new java.lang.ProcessBuilder("curl", "-v", "-k", userInput);
    ```


#### PHP Specific Recommendations
PHP applications should not use `exec` function [10], `WScript.Shell` [11] or any other method to execute OS commands, constructed based on user input.


!!! bug error "Example Incorrect Usage"
    ```java
    <?php
        echo exec(userInput);
    ?>
    ```


!!! bug error "Example Incorrect Usage"
    ```java
    <?php
        echo exec("curl -k " . userInput);
    ?>
    ```


!!! bug error "Example Incorrect Usage"
    ```java
    <?php
        $WshShell = new COM("WScript.Shell");
        $oExec = $WshShell->Run("cmd " . userInput, 7, false);
    ?>
    ```


### HTTP Response Splitting (CRLF Injection)
Including unvalidated data in an HTTP header allows an attacker to specify the entirety of the HTTP response rendered by the browser. When an HTTP request contains unexpected CR (carriage return, also given by `%0d` or `\r`) and LF (line feed, also given by `%0a` or `\n`) characters, the server may respond with an output stream that is interpreted as two different HTTP responses (instead of one). An attacker can control the second response and mount attacks such as cross-site scripting and cache poisoning attacks [16].

For example, if below snippet was used to set cookie value, malicious value `Wiley Hacker\r\nContent-Length:45\r\n\r\nHTTP/1.1 200 OK\r\n....` can result in generating two HTTP responses [17].


```java
String author = request.getParameter(AUTHOR_PARAM);
...
Cookie cookie = new Cookie("author", author);
cookie.setMaxAge(cookieExpiration);
response.addCookie(cookie);
```

```http
HTTP/1.1 200 OK
Set-Cookie: author=Wiley Hacker
Content-Length:45

HTTP/1.1 200 OK
...
```


#### Prevention Techniques
With regards to WSO2 Carbon 4 based products, Apache Tomcat will handle this internally, by disallowing **carriage return** and **line feed** characters from the header names or values [18],[19].

If HTTP response generation is done in any other component, or any other HTTP transport implementation, it should be reviewed and confirmed to have a mechanism similar to Tomcat 6 <small>[18]</small> and Tomcat 7 <small>[19]</small> that performs necessary filtering. If such mechanism is not present in transport implementation, a central filter should be used to read all the headers and do the necessary sanitization before passing the responsez to transport.

Sample filter implementation is available in WSO2 Carbon 4.4.x branch [20]. However, this filter is not in use, since Tomcat provides the necessary protection.


!!! danger error "Alert - Approval Required"
    If any transport implementation or component that generates HTTP responses directly require usage of a custom written filter that does the **carriage return** and **line feed** (CRLF) filtering, the logic performing filtering should be reviewed and approved by Platform Security Team. Platform Security Team should be informed and approval should be obtained before releasing such component or a transport implementation.


### Log Injection / Log Forging (CRLF Injection)
Including unvalidated data in log files allows an attacker to forge log entries or inject malicious content into logs. When a log entry contains unexpected CR (carriage return, also given by `%0d` or `\r`) and LF (line feed, also given by `%0a` or `\n`) characters, the server may record them in the log files/monitoring systems as different events. This can be used to forge log entries and might result in business level implications, if logs are used for further actions, such as reconciliation <small>[21]</small>.

For example, if below snippet was used to print a log entry, malicious input `example1\r\n$100 payment made to author: example2` can result in generating two log lines.

```java
String author = request.getParameter(AUTHOR_PARAM);
...
log.info("$100 payment made to author: " + author);
```

```
$100 payment made to author: example1
$100 payment made to author: example2
```


#### Prevention Techniques
In WSO2 Carbon 4 (4.4.3 onwards), log appenders can be configured to append a UUID to each log entry. UUID will be randomly generated during server startup and the UUID regeneration time can be configured if such behavior is required. Therefore, even if a log line was forged, it would be possible to isolate the forged entry, since it will not contain the relevant valid UUID.

UUID in logs can be enabled by adding `%K` in log4j pattern and relevant configuration is further documented in Administration Guide <small>[22]</small>.


## A2 - Broken Authentication

### Session Hijacking
The Session Hijacking attack consists of the exploitation of the web session control mechanism, which is normally managed with a session token.

Because HTTP communication uses different TCP connections, the web server needs a method to recognize every user's connections. The most useful method depends on a token that the Web Server sends to the client browser after a successful client authentication. A session token is normally composed of a string of variable width and it could be used in different ways, like in the URL, in the header of the HTTP requisition as a cookie, in other parts of the header of the HTTP request, or yet in the body of the HTTP request. (In WSO2 products, session ID is maintained as a cookie and will be communicated between browser and the server through HTTP headers).

The Session Hijacking attack compromises the session token by stealing or predicting a valid session token to gain unauthorized access to the Web Server <small>[23]</small>.

The session token could be compromised in different ways; the most common methods controllable by application developer are:

* Session Sniffing
* Eavesdropping attack
* Predictable session token
* Client-side attacks (XSS, malicious JavaScript Codes, Trojans, etc)


#### Prevention Techniques

**Preventing session sniffing and eavesdropping attacks**

**HTTP Strict-Transport-Security Header (HSTS)**
HTTP Strict Transport Security (HSTS) is an opt-in security enhancement that is specified by a web application through the use of a special response header. Once a supported browser receives this header, that browser will prevent any communications from being sent over HTTP, to the specified domain and will instead send all communications over HTTPS <small>[24]</small>.

HSTS header prevents sensitive information exposure over unencrypted channels by avoiding SSLStrip attacks <small>[25]</small> and by preventing a victim from using HTTP links that correspond to HTTPS-protected site, which could lead to session cookie exposure, if not configured properly.


!!! tip hint important "WSO2 Document Reference"
    Further information on required changes and recommended configuration for WSO2 products as well as production deployments are available at [Engineering Guidelines - Security Related HTTP Headers]().
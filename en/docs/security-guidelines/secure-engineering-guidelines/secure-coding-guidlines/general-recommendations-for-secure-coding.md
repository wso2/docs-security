---
title: General Recommendations for Secure Coding
category: security-guidelines
published: 22nd October 2018
version: 2.1
---

# General Recommendations for Secure Coding
<p class="doc-info">Version: 2.1</p>
___

This section discusses different attacks or security threats that engineers must focus on while engineering a product or an application. Prevention techniques are discussed in generic form, and some sections discuss programming language-specific prevention techniques.

## SQL Injection
A SQL injection attack consists of the insertion or **injection** of a SQL query via the input data from the client to the application. A successful SQL injection exploit can read sensitive data from the database, modify database data (Insert/Update/Delete), execute administration operations on the database (such as shutdown the DBMS), recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. SQL injection 
attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands[^1]. 

Prevention Techniques
Use secure language constructs (Example: PreparedStatement in Java) when executing SQL statements. Use language specific best practices when using secure language constructs to avoid any possible misuses. 
Restructure the methods so that the application does not accept table names, column names, ordering information, offset details or any other value that cannot be parameterized using language specific best practices. 


### Prevention Techniques
Use secure language constructs (Example: PreparedStatement in Java) when executing SQL statements. Use language specific best practices when using secure language constructs to avoid any possible misuses. 
Restructure the methods so that the application does not accept table names, column names, ordering information, offset details or any other value that cannot be parameterized using language specific best practices. 

!!! example
    In Java context, ORDER BY column name of below query can not be provided as a PreparedStatement parameter. 
    ```sql
    SELECT ID,NAME FROM EXAMPLE_TABLE WHERE AGE > ? ORDER BY DYNAMIC_COLUMN_NAME;
    ```

If user input must be used in sections that cannot be parameterized using secure language constructs, perform whitelisting against the user input. 

!!! example
    A whitelist should be maintained which includes an acceptable list of inputs for `DYNAMIC_COLUMN_NAME`. User input should be rejected if provided input is not within the expected set of values.

### Java Specific Recommendations
Use PreparedStatements to prevent SQL injections. The statement will be compiled and the user variables will be assigned to the query parameters in the runtime. Since user variables are being set to a precompiled SQL statement, this approach avoids the possibility of SQL injections. 


!!! bug error "Example Incorrect Usage"
    ```
    {==String query = "SELECT account_balance FROM user_data WHERE user_name = " + request.getParameter("customerName");==}
    try {
        Statement statement = connection.createStatement( … );
        ResultSet results = statement.executeQuery( query );
    } 
    # Catch block… 
    ```

!!! success check done "Example Correct Usage"
    ```java
    String customerName = request.getParameter("customerName");
    // Validations. Etc… 

    String query = "SELECT account_balance FROM user_data WHERE user_name = ?"; 
    try {
        PreparedStatement preparedStatement = connection.prepareStatement( query );
        preparedStatement.setString( 1, customerName ); 
        ResultSet results = preparedStatement.executeQuery();
    } 
    // Catch block… 
    ```

When processing dynamic query segments that cannot be set as PreparedStatement parameters (table names, column names, ordering information, offset details), validate user input against a whitelist. This approach avoids the risk of providing the end user with the ability to append anything uncontrolled to the SQL query.

Example 1:

!!! bug error "Example Incorrect Usage"
    ```java
    String customerType = request.getParameter("customerType");
    String order = request.getParameter("order");
    // Validations. Etc… 

    String query = "SELECT user_name, account_balance FROM user_data WHERE user_type = ? ORDER BY " + order; 
    try {
        PreparedStatement preparedStatement = connection.prepareStatement( query );
        preparedStatement.setString( 1, customerType ); 
        ResultSet results = preparedStatement.executeQuery();
    } 
    // Catch block… 
    ```

!!! success check done "Example Correct Usage"
    ```java
    // Class level static map maintaining "user input to database column" mapping
    private static final Map<String, String> validOrderColumns = new HashMap<String, String>();
    validOrderColumns.add("accountBalance", "account_balance");
    validOrderColumns.add("userName", "user_name");

    // Method definition… 
    String customerType = request.getParameter("customerType");
    String orderColumn = request.getParameter("orderColumn");
    String orderDirection = request.getParameter("orderDirection");

    if (orderDirection.equalsIgnoreCase("DESC")) {
        orderDirection = "DESC";
    } else {
        orderDirection = "ASC"; 
    }

    orderColumn = validOrderColumns.get(orderColumn);
    // Validations. Etc… 

    String query = "SELECT user_name, account_balance FROM user_data WHERE user_type = ? ORDER BY " + orderColumn + " " + orderDirection; 
    try {
        PreparedStatement preparedStatement = connection.prepareStatement( query );
        preparedStatement.setString( 1, customerType ); 
        ResultSet results = preparedStatement.executeQuery();
    } 
    # Catch block… 
    ```

Example 2:

!!! bug error "Example Incorrect Usage"
    ```java
    // … 
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
    // Catch block
    ```

!!! success check done "Example Correct Usage"
    ```java
    // Class level static map maintaining user input to column mapping
    private static final Map<String, String> validSelectColumns = new HashMap<String, String>();
    validSelectColumns.add("apiName", "api_name");
    validSelectColumns.add("apiId", "api_id");

    private static final Map<String, String> validColumnFamilies = new HashMap<String, String>();
    validSelectColumns.add("commonApis", "COMMON_APIS");
    validSelectColumns.add("corporateApis", "CORPORATE_APIS");

    // Method definition… 
    String columnFamily = validSelectColumns.get(columnFamilyUserInput)
    if(columnFamily == null) {
        // Throw required exceptions or errors.
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
    // Catch block…
    ```

### PHP Specific Recommendations
Use PHP Data Objects (PDO) Extension or MySQL Improved Extension when executing queries that include user inputs. Make sure to use parameterizing capabilities of the extensions.

!!! bug error "Example Incorrect Usage"
    ```php
    <?php
        $query  = "SELECT id, name, inserted, size FROM products WHERE size = '$size'";
        $result = odbc_exec($conn, $query);
    ?>
    ```

!!! bug error "Example Incorrect Usage"
    ```php
    <?php
        $query  = "SELECT id, name, inserted, size FROM products WHERE size = '$size'";
        $result = pg_query($conn, $query);
    ?>
    ```

!!! bug error "Example Incorrect Usage"
    ```php
    <?php
        $query  = "SELECT id, name, inserted, size FROM products WHERE size = '$size'";
        $result = mssql_query($conn, $query);
    ?>
    ```

Using PHP Data Objects (PDO) Extension[^2][^3]

!!! success check done "Example Correct Usage"
    ```php
    <?php
        $stmt = $pdo->prepare('SELECT * FROM employees WHERE name = :name');
        $stmt->execute(array('name' => $name));
        foreach ($stmt as $row) {
            # do something with $row
        }
    ?>
    ```

Using MySQL Improved Extension[^4][^5]

!!! success check done "Example Correct Usage"
    ```php
    <?php
        $stmt = $dbConnection->prepare('SELECT * FROM employees WHERE name = ?');
        $stmt->bind_param('s', $name);

        $stmt->execute();

        $result = $stmt->get_result();
        while ($row = $result->fetch_assoc()) {
            # do something with $row
        }
    ?>
    ```

Example with query segments that cannot be parameterized with PDO or MySQL Improved Extension[^6]:

!!! bug error "Example Incorrect Usage"
    ```mysql
    <?php
        $offset = $argv[0]; # beware, no input validation!
        $query  = "SELECT id, name FROM products ORDER BY name LIMIT 20 OFFSET $offset;";
        $result = pg_query($conn, $query);
    ?>
    ```

!!! success check done "Example Correct Usage"
    ```mysql
    <?php
        settype($offset, 'integer');
        $query = "SELECT id, name FROM products ORDER BY name LIMIT 20 OFFSET $offset;";

        # please note %d in the format string, using %s would be meaningless
        $query = sprintf("SELECT id, name FROM products ORDER BY name LIMIT 20 OFFSET %d;",$offset);
        $result = pg_query($conn, $query);
    ?>
    ```

### Go Specific Recommendations

Use Go's `database/sql` package with prepared statements to prevent SQL injections. The statement will be compiled and the user variables will be assigned to the query parameters at runtime. Since user variables are being set to a precompiled SQL statement, this approach avoids the possibility of SQL injections.

!!! bug error "Example Incorrect Usage"
    ```go
    customerName := r.FormValue("customerName")
    query := "SELECT account_balance FROM user_data WHERE user_name = " + customerName
    
    rows, err := db.Query(query)
    if err != nil {
        log.Fatal(err)
    }
    defer rows.Close()
    ```

!!! success check done "Example Correct Usage - One-Time Query"
    ```go
    customerName := r.FormValue("customerName")
    // Validations, etc...
    
    query := "SELECT account_balance FROM user_data WHERE user_name = ?"
    rows, err := db.Query(query, customerName)
    if err != nil {
        return err
    }
    defer rows.Close()
    
    // Process rows...
    ```

!!! success check done "Example Correct Usage - Reusable Prepared Statement"
    ```go
    customerName := r.FormValue("customerName")
    // Validations, etc...
    
    query := "SELECT account_balance FROM user_data WHERE user_name = ?"
    stmt, err := db.Prepare(query)
    if err != nil {
        return err
    }
    defer stmt.Close()
    
    rows, err := stmt.Query(customerName)
    if err != nil {
        return err
    }
    defer rows.Close()
    
    // Process rows...
    ```

When processing dynamic query segments that cannot be set as prepared statement parameters (table names, column names, ordering information, offset details), validate user input against a whitelist. This approach avoids the risk of providing the end user with the ability to append anything uncontrolled to the SQL query.

Example 1:

!!! bug error "Example Incorrect Usage"
    ```go
    customerType := r.FormValue("customerType")
    order := r.FormValue("order")
    // Validations, etc...
    
    query := "SELECT user_name, account_balance FROM user_data WHERE user_type = ? ORDER BY " + order
    rows, err := db.Query(query, customerType)
    if err != nil {
        log.Fatal(err)
    }
    defer rows.Close()
    ```

!!! success check done "Example Correct Usage"
    ```go
    // Package level map maintaining "user input to database column" mapping
    var validOrderColumns = map[string]string{
        "accountBalance": "account_balance",
        "userName":       "user_name",
    }
    
    // Function definition...
    customerType := r.FormValue("customerType")
    orderColumn := r.FormValue("orderColumn")
    orderDirection := r.FormValue("orderDirection")
    
    if strings.ToUpper(orderDirection) == "DESC" {
        orderDirection = "DESC"
    } else {
        orderDirection = "ASC"
    }
    
    dbColumn, exists := validOrderColumns[orderColumn]
    if !exists {
        // Handle invalid column error
        return
    }
    
    query := "SELECT user_name, account_balance FROM user_data WHERE user_type = ? ORDER BY " + dbColumn + " " + orderDirection
    rows, err := db.Query(query, customerType)
    if err != nil {
        log.Fatal(err)
    }
    defer rows.Close()
    ```

Example 2:

!!! bug error "Example Incorrect Usage"
    ```go
    query := "SELECT * FROM " + columnFamily + " WHERE api_publisher = ?"
    
    if selectRowsByColumnName != "" {
        query = query + " AND " + selectRowsByColumnName + " = ?"
    }
    
    var rows *sql.Rows
    var err error
    if selectRowsByColumnName != "" {
        rows, err = db.Query(query, publisher, selectRowsByColumnValue)
    } else {
        rows, err = db.Query(query, publisher)
    }
    if err != nil {
        log.Fatal(err)
    }
    defer rows.Close()
    ```

!!! success check done "Example Correct Usage"
    ```go
    // Package level maps maintaining user input to column mapping
    var validSelectColumns = map[string]string{
        "apiName": "api_name",
        "apiId":   "api_id",
    }
    
    var validColumnFamilies = map[string]string{
        "commonApis":    "COMMON_APIS",
        "corporateApis": "CORPORATE_APIS",
    }
    
    // Function definition...
    columnFamily, exists := validColumnFamilies[columnFamilyUserInput]
    if !exists {
        // Handle invalid column family error
        return
    }
    
    query := "SELECT * FROM " + columnFamily + " WHERE api_publisher = ?"
    
    if selectRowsByColumnName != "" {
        columnName, exists := validSelectColumns[selectRowsByColumnName]
        if exists {
            query = query + " AND " + columnName + " = ?"
        } else {
            selectRowsByColumnName = ""
        }
    }
    
    var rows *sql.Rows
    var err error
    if selectRowsByColumnName != "" {
        rows, err = db.Query(query, publisher, selectRowsByColumnValue)
    } else {
        rows, err = db.Query(query, publisher)
    }
    if err != nil {
        log.Fatal(err)
    }
    defer rows.Close()
    ```

## LDAP Injection
LDAP Injection is an attack used to exploit web based applications that construct LDAP statements based on user input. When an application fails to properly sanitize user input, it’s possible to modify LDAP statements using a local proxy. This could result in the execution of arbitrary commands such as granting permissions to unauthorized queries, and content modification inside the LDAP tree. The same advanced exploitation techniques available in SQL Injection can be similarly applied in LDAP Injection[^7][^8].

### Java Specific Recommendations

All user inputs that are getting directly appended to any LDAP queries should be filtered through an encoding function that does proper encoding for LDAP[^9]. 

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

### Go Specific Recommendations

All user inputs that are getting directly appended to any LDAP queries should be filtered through an encoding function that does proper encoding for LDAP. Use the `ldap.EscapeFilter` function to escape special characters in filter values.

!!! bug error "Example Incorrect Usage"
    ```go
    grpSearchFilter := strings.Replace(searchFilter, "?", role, -1)
    groupResults, err := conn.Search(ldap.NewSearchRequest(
        baseDN,
        ldap.ScopeWholeSubtree,
        ldap.NeverDerefAliases,
        0, 0, false,
        grpSearchFilter,
        []string{},
        nil,
    ))
    ```

!!! success check done "Example Correct Usage"
    ```go
    import "github.com/go-ldap/ldap/v3"
    
    grpSearchFilter := strings.Replace(searchFilter, "?", ldap.EscapeFilter(role), -1)
    groupResults, err := conn.Search(ldap.NewSearchRequest(
        baseDN,
        ldap.ScopeWholeSubtree,
        ldap.NeverDerefAliases,
        0, 0, false,
        grpSearchFilter,
        []string{},
        nil,
    ))
    ```

## OS Command Injection
Command injection is an attack in which the goal is the execution of arbitrary commands on the host operating system via a vulnerable application. Command injection attacks are possible when an application passes unsafe user supplied data (forms, cookies, HTTP headers etc.) to a system shell. In this attack, the attacker-supplied operating system commands are usually executed with the privileges of the vulnerable application. Command injection attacks are possible largely due to insufficient input validation[^10].


### Prevention Techniques
Products or applications should not use user inputs in constructing OS commands. 

!!! danger error "Alert - Approval Required"
    If any component requires that, user input be appended to an OS command or to be interpreted as an OS command, the use-case, as well as controls in place to provide the required protection, must be reviewed and approved by the Security and Compliance Team, before proceeding with the release of such component.


### Java Specific Recommendations
WSO2 Products should not use java.lang.Runtime.getRuntime(), java.lang.ProcessBuilder or any other method to execute OS commands, constructed based on user input. 

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


### PHP Specific Recommendations
PHP applications should not use `exec` function[^11], `WScript.Shell`[^12] or any other method to execute OS commands, constructed based on user input. 

!!! bug error "Example Incorrect Usage"
    ```php
    <?php
        echo exec(userInput);
    ?>
    ```

!!! bug error "Example Incorrect Usage"
    ```php
    <?php
        echo exec("curl -k " . userInput);
    ?>
    ```

!!! bug error "Example Incorrect Usage"
    ```php
    <?php
        $WshShell = new COM("WScript.Shell"); 
        $oExec = $WshShell->Run("cmd " . userInput, 7, false); 
    ?>
    ```

### Go Specific Recommendations
Go applications should not use `os/exec.Command`, `os/exec.CommandContext` or any other method from the `os/exec` package to execute OS commands, constructed based on user input.

!!! bug error "Example Incorrect Usage"
    ```go
    cmd := exec.Command(userInput)
    cmd.Run()
    ```

!!! bug error "Example Incorrect Usage"
    ```go
    cmd := exec.Command("curl", "-v", "-k", userInput)
    cmd.Run()
    ```

!!! bug error "Example Incorrect Usage"
    ```go
    cmd := exec.CommandContext(ctx, "sh", "-c", "curl -k "+userInput)
    cmd.Output()
    ```

## Cross-Site Scripting (XSS)
Cross-Site Scripting allows an attacker to execute malicious code (scripts) against the web browser of the user. By leveraging this attack, an attacker could attempt to carry out other forms of attacks such as stealing session cookies to perform [Session Hijacking](#session-hijacking) or stealing token values to conduct [CSRF Attacks](#csrf-attacks), launch a phishing attack etc[^13].


### Prevention Techniques 
There are three best practices that are recommended to be followed in order to prevent XSS threats:


#### Input validation.
User inputs should be validated whenever possible and only characters that are relevant to the particular field should be accepted. Input validation should be done on the server side to prevent any bypass attempts, even though additional front-end validation can be done to increase user experience.

However, in WSO2 Carbon 4 based products, input validation is given a lower priority and is only done in essential screens. Therefore, it is a must to use proper output encoding and output sanitization techniques.


#### Output Encoding
Proper output encoding should be applied, where output consists of user input that is not expected to include HTML content.

!!! example
    User input is the API description. The user might have to add some special characters in the description. However, the application is not expecting any HTML syntax in the description.

    In the example scenario, output encoding will convert special characters to respective HTML character entity references[^14].


#### Output Sanitization
Proper output sanitization should be applied, where output consists of user input that is expected to include HTML content.

!!! example
    User input is the contents of API documentation, which is expected to have some basic HTML syntax used in formatting. 

    In the example scenario, output sanitization will disallow the user from adding HTML tags that could introduce a potential threat such as `<script>` and from using HTML event related attributes.


#### Browser Level Protection
Modern browsers have built-in XSS prevention mechanisms. However, certain browsers require explicitly enabling these mechanisms using special response headers. `X-XSS-Protection: 1; mode=block` header should be set in HTTP responses to make sure browser level protection is enabled in all supported browsers. 

For additional details on HTTP security related headers, refer to [Security Related HTTP Headers](../security-related-http-headers.md) section.

However, this is not a permanent or justifiable solution for XSS. Instead, browser level protection should only be considered as an additional protection mechanism. 


### Java Specific Recommendations 

#### Output Encoding
OWASP Java Encoder[^15] should be used to perform output encoding. OWASP Java Encoder is capable of performing contextual encoding. Following are the contexts and relevant examples that should be used:

Encode within HTML content

!!! bug error "Example Incorrect Usage"
    ```java
    <tr> 
        <td width="30%"><fmt:message key='workflow.impl.name'/></td>                                    
        <td><%=variableWithDynamicText%></td> 
    </tr>
    ```

!!! success check done "Example Correct Usage"
    ```java
    <tr> 
        <td width="30%"><fmt:message key='workflow.impl.name'/></td>                                     
        <td><%=Encode.forHtml(variableWithDynamicText)%></td> 
    </tr>
    ```

Encode Attributes used in JavaScript

!!! bug error "Example Incorrect Usage"
    ```java
    <a title="Title" onclick="jsMethod('<%=variableWithDynamicText%>')”>Link Text</a>
    ```

!!! success check done "Example Correct Usage"
    ```java
    <a title="Title" onclick="jsMethod('<%=Encode.forJavaScript(variableWithDynamicText)%>')”>Link Text</a>
    ```

Encode Variables in Javascript Blocks

!!! bug error "Example Incorrect Usage"
    ```java
    <script type=”text/javascript”>
        //Some JS logic here
        vat x = <%=variableWithDynamicText%>;
        //Some JS logic here
    </script>
    ```

!!! success check done "Example Correct Usage"
    ```java
    <script type=”text/javascript”>
        //Some JS logic here
        vat x = <%=Encode.forJavaScript(variableWithDynamicText)%>;
        //Some JS logic here
    </script>
    ```

Encode with URLs

!!! bug error "Example Incorrect Usage"
    ```java
    <a title="Title" href="<%=variableWithDynamicText%>">Link Text</a>
    ```

!!! success check done "Example Correct Usage"
    ```java
    <a title="Title" href="<%=Encode.forUri(variableWithDynamicText)%>">Link Text</a>
    ```


#### Output Sanitization 
OWASP Java HTML Sanitizer[^16] should be used to perform output sanitization. OWASP Java HTML Sanitizer can be used to allow only a certain set of HTML elements in user input. In addition, it is possible to define allowed attributes and properties of attributes, relevant to an enabled element.

It is recommended to limit to pre-packaged FORMATTING sanitizer policy[^17]. However, if users should be allowed to use images, tables or links, other pre-packaged sanitizer policies can be used. 

!!! danger error "Alert - Approval Required"
    If a custom policy or a custom rule is defined other than the pre-packaged sanitizer policies, the custom policy should be reviewed and approved by the Security and Compliance (SC) Team. Therefore, before the release of components with custom sanitizer policies or rules, The SC Team should be notified, and use cases, as well as rules, should be reviewed.

!!! bug error "Example Incorrect Usage"
    ```java
    <tr> 
        <td width="30%"><fmt:message key='workflow.impl.name'/></td>                                    
        <td><%=variableWithDynamicHtmlContent%></td> 
    </tr>
    ```

!!! success check done "Example Correct Usage"
    ```java
    <tr> 
        <td width="30%"><fmt:message key='workflow.impl.name'/></td>      
        <% PolicyFactory policy = Sanitizers.FORMATTING.and(Sanitizers.LINKS); %>                               
        <td><%=policy.sanitize(variableWithDynamicHtmlContent)%></td> 
    </tr>
    ```


#### Browser Level Protection
`org.apache.catalina.filters.HttpHeaderSecurityFilter` Servlet Filter should be used to add the X-XSS-Protection header to the HTTP response. 

!!! tip hint important "WSO2 Document Reference"
    Further information on required changes and recommended configuration for WSO2 products as well as production deployments are available at [Engineering Guidelines - Security Related HTTP Headers](../security-related-http-headers.md).


### JavaScript Specific Recommendations

#### Output Encoding
When adding content into an HTML document using client-side script (such as JavaScript), avoid inserting HTML content directly into the document. Avoid .html(), .innerHTML, and other related functions.

!!! bug error "Example Incorrect Usage"
    ```javascript
    document.getElementById('example-div').innerHtml = dynamicText;
    ```

!!! success check done "Example Correct Usage"
    ```javascript
    jQuery( '#example-div' ).html( dynamicText );
    jQuery( '#example-div' ).before( dynamicText );
    jQuery( '#example-div' ).after( dynamicText );
    jQuery( '#example-div' ).append( dynamicText );
    jQuery( '#example-div' ).prepend( dynamicText );
    jQuery( dynamicText ).appendTo( '#example-div' );
    jQuery( dynamicText ).prependTo( '#example-div' );
    ```

Use methods such as .text(), .textContent, for adding dynamic text content into DOM. When adding HTML content is required, programmatically create DOM nodes and append content to the newly created DOM and append the new DOM node into HTML document. 

!!! success check done "Example Correct Usage"
    ```javascript
    document.getElementById('example-div').textContent = dynamicText;
    ```

!!! success check done "Example Correct Usage"
    ```javascript
    jQuery( '.some-div' ).text( dynamicText );
    ```

!!! success check done "Example Correct Usage"
    ```javascript
    var text = jQuery('<div />').text( dynamicText );
    jQuery( '#example-div' ).html( text.html() );
    ```

If dynamic input is used to construct a HTML attribute double quote and single quote should be additionally escaped. 

!!! bug error "Example Incorrect Usage"
    ```javascript
    var text = jQuery('<div />').text( dynamicText );
    jQuery( '#example-div' ).attr("href", text.html());
    ```

!!! success check done "Example Correct Usage"
    ```javascript
    var text = jQuery('<div />').text( dynamicText );
    jQuery( '#example-div' ).attr("href", text.html().replace(/"/g, "&quot;").replace(/'/g, '&#39;') );
    ```


### PHP Specific Recommendations

#### Output Encoding
`htmlspecialchars` function[^18] should be used whenever user input is printed back into a response. The mentioned function converts special characters in the input to HTML entities. 

Use `ENT_QUOTES` flag to enable the encoding of both single and double quotes. 

!!! bug error "Example Incorrect Usage"
    ```php
    <a title="Title" href="<?php echo variableWithDynamicText ?>">Link Text</a>
    ```

!!! bug error "Example Incorrect Usage"
    ```php
    <a title="Title" href="<?php echo htmlspecialchars(variableWithDynamicText)?>">Link Text</a>
    ```

!!! success check done "Example Correct Usage"
    ```php
    <a title="Title" href="<?php echo htmlspecialchars(variableWithDynamicText, ENT_QUOTES)?>">Link Text</a>
    ```


#### Output Sanitization 
HTML Purifier[^19] should be used to sanitize HTML content. Default HTML Purifier rules set is recommended. 

!!! danger error "Alert - Approval Required"
    If a custom policy or a custom rule is defined, other than the default sanitizer policy, the custom policy should be reviewed and approved by the Security and Compliance (SC) Team. Therefore, before the release of a component with custom sanitizer policies or rules, the SC Team should be notified, and use cases, as well as rules, should be reviewed.

!!! bug error "Example Incorrect Usage"
    ```php
    <a title="Title" href="<?php echo htmlspecialchars(variableWithDynamicText)?>">Link Text</a>
    ```

!!! success check done "Example Correct Usage"
    ```php
    <?php 
        $config = HTMLPurifier_Config::createDefault();
        $purifier = new HTMLPurifier($config);
    ?>
    <a title="Title" href="<?php echo $purifier->purify(variableWithDynamicText, ENT_QUOTES)?>">Link Text</a>
    ```


#### Browser Level Protection

!!! tip hint important "WSO2 Document Reference"
    Further information on required changes and recommended configuration for WSO2 products as well as production deployments are available at [Engineering Guidelines - Security Related HTTP Headers](../security-related-http-headers.md).

### Go Specific Recommendations

#### Output Encoding
`html/template` package can be used for HTML templating as it provides automatic contextual encoding. For manual encoding, use `html.EscapeString` function to convert special characters to HTML entities.

!!! bug error "Example Incorrect Usage"
    ```go
    import "text/template"
    
    tmpl := `<div>{{.UserInput}}</div>`
    t := template.Must(template.New("example").Parse(tmpl))
    t.Execute(w, data)
    ```

!!! success check done "Example Correct Usage"
    ```go
    import "html/template"
    
    tmpl := `<div>{{.UserInput}}</div>`
    t := template.Must(template.New("example").Parse(tmpl))
    t.Execute(w, data)
    ```

For manual encoding in non-template contexts

!!! bug error "Example Incorrect Usage"
    ```go
    fmt.Fprintf(w, `<a href="%s">Link</a>`, userInput)
    ```

!!! success check done "Example Correct Usage"
    ```go
    import "html"
    
    fmt.Fprintf(w, `<a href="%s">Link</a>`, html.EscapeString(userInput))
    ```

Encode for JavaScript contexts

!!! bug error "Example Incorrect Usage"
    ```go
    fmt.Fprintf(w, `<script>var data = "%s";</script>`, userInput)
    ```

!!! success check done "Example Correct Usage"
    ```go
    import (
        "encoding/json"
        "html/template"
    )
    
    jsData, err := json.Marshal(userInput)
    if err != nil {
        http.Error(w, "Encoding error", http.StatusInternalServerError)
        return
    }

    tmpl := `<script>var data = {{.JSData}};</script>`
    t := template.Must(template.New("js").Parse(tmpl))
    t.Execute(w, map[string]template.JS{"JSData": template.JS(jsData)})
    ```

Encode URLs

!!! bug error "Example Incorrect Usage"
    ```go
    fmt.Fprintf(w, `<a href="%s">Click Here</a>`, userInput)
    ```

!!! success check done "Example Correct Usage"
    ```go
    escapedURL := template.URLQueryEscaper(userInput)
    fmt.Fprintf(w, `<a href="%s">Click Here</a>`, escapedURL)
    ```

#### Output Sanitization

For Go applications, established libraries such as `bluemonday` can be used to sanitize HTML content. The `bluemonday` library allows you to define a policy for allowed HTML elements and attributes, which helps in preventing XSS attacks.

!!! danger error "Alert - Approval Required"
    If a custom sanitization policy is defined, the policy should be reviewed and approved by the Security and Compliance (SC) Team. Therefore, before the release of components with custom sanitizer policies, the SC Team should be notified, and use cases should be reviewed.

!!! bug error "Example Incorrect Usage"
    ```go
    import (
        "html/template"
        "net/http"
    )
    
    func handler(w http.ResponseWriter, r *http.Request) {
        userHTMLContent := r.FormValue("content")
        tmpl := template.Must(template.New("page").Parse("<div>{{.Content}}</div>"))
        tmpl.Execute(w, map[string]string{"Content": userHTMLContent})
    }
    ```

!!! success check done "Example Correct Usage"
    ```go
    import (
        "html/template"
        "net/http"
        
        "github.com/microcosm-cc/bluemonday"
    )
    
    func handler(w http.ResponseWriter, r *http.Request) {
        userHTMLContent := r.FormValue("content")
        
        // Use strict policy that only allows a limited subset of HTML
        p := bluemonday.UGCPolicy()
        sanitized := p.Sanitize(userHTMLContent)
        
        tmpl := template.Must(template.New("page").Parse("<div>{{.Content}}</div>"))
        // Sanitized content is safe to be unescaped in templates
        tmpl.Execute(w, map[string]template.HTML{"Content": template.HTML(sanitized)})
    }
    ```

Alternatively, you can use regular expressions to sanitize HTML content.

!!! success check done "Example Correct Usage"
    ```go
    import (
        "html"
        "regexp"
        "strings"
    )
    
    func sanitizeHTML(input string) string {
        // Remove script tags and their content
        scriptRegex := regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)
        input = scriptRegex.ReplaceAllString(input, "")
        
        // Remove potentially dangerous tags
        dangerousTagsRegex := regexp.MustCompile(`(?i)</?(?:script|object|embed|link|style|iframe)[^>]*>`)
        input = dangerousTagsRegex.ReplaceAllString(input, "")
        
        // Remove event handlers
        eventRegex := regexp.MustCompile(`(?i)\s*on\w+\s*=\s*["'][^"']*["']`)
        input = eventRegex.ReplaceAllString(input, "")
        
        return html.EscapeString(input)
    }
    
    sanitized := sanitizeHTML(userHTMLContent)
    fmt.Fprintf(w, `<div>%s</div>`, sanitized)
    ```

For basic formatting preservation while maintaining security:

!!! success check done "Example Correct Usage"
    ```go
    import (
        "regexp"
        "strings"
    )
    
    func sanitizeBasicHTML(input string) string {
        // Allow only basic formatting tags
        allowedTags := []string{"b", "i", "u", "strong", "em", "p", "br"}
        
        // Remove all tags except allowed ones
        tagRegex := regexp.MustCompile(`</?([a-zA-Z][a-zA-Z0-9]*)\b[^>]*>`)
        return tagRegex.ReplaceAllStringFunc(input, func(match string) string {
            tagNameRegex := regexp.MustCompile(`</?([a-zA-Z][a-zA-Z0-9]*)\b`)
            tagNameMatch := tagNameRegex.FindStringSubmatch(match)
            if len(tagNameMatch) > 1 {
                tagName := strings.ToLower(tagNameMatch[1])
                for _, allowed := range allowedTags {
                    if tagName == allowed {
                        return match
                    }
                }
            }
            return ""
        })
    }
    
    sanitized := sanitizeBasicHTML(userHTMLContent)
    fmt.Fprintf(w, `<div>%s</div>`, sanitized)
    ```

#### Browser Level Protection
Set the `X-XSS-Protection` header in HTTP responses using middleware or manual header setting.

!!! success check done "Example Correct Usage"
    ```go
    func xssProtectionMiddleware(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            w.Header().Set("X-XSS-Protection", "1; mode=block")
            next.ServeHTTP(w, r)
        })
    }
    ```

!!! tip hint important "WSO2 Document Reference"
    Further information on required changes and recommended configuration for WSO2 products as well as production deployments are available at [Engineering Guidelines - Security Related HTTP Headers](../security-related-http-headers.md).


## XML External Entity (XXE)
An XML External Entity attack is a type of attack against an application that parses XML input. This attack occurs when XML input containing a reference to an external entity is processed by a weakly configured XML parser. This attack may lead to the disclosure of confidential data, denial of service, server-side request forgery, port scanning from the perspective of the machine where the parser is located, and other system impacts[^20].


### Java Specific Recommendations
In order to resolve this issue, it is required to configure the XML parser correctly by performing the following actions:

1. Enable the DocumentBuilderFactory namespace awareness
2. Disable the DocumentBuilderFactory entity reference expansion
3. Enable the DocumentBuilderFactory secure processing feature
4. Disable the DocumentBuilderFactory “http://xml.org/sax/features/external-general-entities” feature
5. Use a SecurityManager for the DocumentBuilderFactory
6. Use a custom EntityResolver for the DocumentBuilder created using the above DocumentBuilderFactory

!!! danger error "Alert - Approval Required"
    If any component requires, any of the recommended security flags not to be set in DocumentBuilderFactory, the use-case, as well as controls in place to provide the required protection, must be reviewed and approved by the Security and Compliance Team, before proceeding with the release of such component.


#### DocumentBuilderFactory (DOM Parser)

!!! bug error "Example Incorrect Usage"
    ```java
    DocumentBuilder builder;
    ByteArrayInputStream inputStream;
    Element root = null;

    // xmlConfig is the XML content
    inputStream = new ByteArrayInputStream(xmlConfig.getBytes()); 

    DocumentBuilderFactory builder = DocumentBuilderFactory.newInstance();

    try {
        Document doc = builder.newDocumentBuilder().parse(inputStream);
        root = doc.getDocumentElement();
        //doc is used for further processing from here
    }
    ```

!!! success check done "Example Correct Usage"
    ```java
    import org.apache.xerces.impl.Constants;

    private static final int ENTITY_EXPANSION_LIMIT = 0;
    private static final DocumentBuilderFactory documentBuilderFactory =     
        DocumentBuilderFactory.newInstance();
    
    static {
        documentBuilderFactory.setNamespaceAware(true);
        documentBuilderFactory.setXIncludeAware(false);
        documentBuilderFactory.setExpandEntityReferences(false);
    
        try {
            documentBuilderFactory.setFeature(Constants.SAX_FEATURE_PREFIX + 
                Constants.EXTERNAL_GENERAL_ENTITIES_FEATURE, false);
        } catch (ParserConfigurationException e) {
            logger.error("Failed to load XML Processor Feature " + 
                    Constants.EXTERNAL_GENERAL_ENTITIES_FEATURE);
        }
        try {
            documentBuilderFactory.setFeature(Constants.SAX_FEATURE_PREFIX + 
                Constants.EXTERNAL_PARAMETER_ENTITIES_FEATURE, false);
        } catch (ParserConfigurationException e) {
            logger.error("Failed to load XML Processor Feature " +
                Constants.EXTERNAL_PARAMETER_ENTITIES_FEATURE);
        }
        try {
            documentBuilderFactory.setFeature(Constants.XERCES_FEATURE_PREFIX + 
                Constants.LOAD_EXTERNAL_DTD_FEATURE, false);
        } catch (ParserConfigurationException e) {
            logger.error("Failed to load XML Processor Feature " + 
                Constants.LOAD_EXTERNAL_DTD_FEATURE);
        }
    
        SecurityManager securityManager = new SecurityManager();
        securityManager.setEntityExpansionLimit(ENTITY_EXPANSION_LIMIT);
        documentBuilderFactory.setAttribute(Constants.XERCES_PROPERTY_PREFIX + 
            Constants.SECURITY_MANAGER_PROPERTY, securityManager);
    }

    private DocumentBuilderFactory getSecuredDocumentBuilderFactory() {
        return documentBuilderFactory;
    }
    ```


### XMLInputFactory (Stax Parser)

!!! bug error "Example Incorrect Usage"
    ```java
    DocumentBuilder builder;
    ByteArrayInputStream inputStream;
    Element root = null;

    // xmlConfig is the XML content
    inputStream = new ByteArrayInputStream(xmlConfig.getBytes()); 

    XMLInputFactory factory = XMLInputFactory.newInstance();

    try {
        XMLEventReader eventReader = factory.createXMLEventReader(inputStream);
        while(eventReader.hasNext()) {
        //doc is used for further processing from here
        }
    }
    ```

!!! success check done "Example Correct Usage"
    ```java
    import org.apache.xerces.impl.Constants;

    private static final int ENTITY_EXPANSION_LIMIT = 0;
    
    private static final XMLInputFactory xmlInputFactory;
    
    static {
        xmlInputFactory = XMLInputFactory.newInstance();
        try {
            xmlInputFactory.setProperty(XMLInputFactory.IS_NAMESPACE_AWARE, true);
        } catch (IllegalArgumentException e) {
            log.error("Failed to load XML Processor Feature XMLInputFactory.IS_NAMESPACE_AWARE", 
                e);
        }
    
        try {
            xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        } catch (IllegalArgumentException e) {
            log.error("Failed to load XML Processor Feature XMLInputFactory.SUPPORT_DTD", e);
        }
    
        try {
            xmlInputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        } catch (IllegalArgumentException e) {
            log.error("Failed to load XML Processor Feature 
                XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES", e);
        }
    
        //If Woodstox StAX parser 5+ is used, set following property 
        //to disable entity expansion 
        //try {
        //   factory.setProperty("com.ctc.wstx.maxEntityDepth", 1);
        //} catch (IllegalArgumentException e) {
        //    log.error("Failed to load XML Processor Feature com.ctc.wstx.maxEntityDept", e);
        //}
    }

    private XMLInputFactory getSecuredXMLInputFactory() {
        return factory;
    }
    ```


### PHP Specific Recommendations
If libxml is used in XML processing, `libxml_disable_entity_loader` function[^21] must be used to protect against XXE attacks[^22][^23]. 

!!! danger error "Alert - Approval Required"
    If any component requires, any of the recommended security flags not to be set in libxml, the use-case, as well as controls in place to provide the required protection, must be reviewed and approved by the Security and Compliance Team, before proceeding with the release of such component.


!!! bug error "Example Incorrect Usage"
    ```php
    <?php 
        // User provided XML content here (Hard-coded only as an example).
        $xml = <<<EOD
        <?xml version="1.0"?>
        <!DOCTYPE root
        [
        <!ENTITY foo SYSTEM "file://$dir/content.txt">
        ]>
        <test><testing>&foo;</testing></test>
        EOD;

        $doc = simplexml_load_string($xml);
    ?>
    ```

!!! success check done "Example Correct Usage"
    ```php
    <?php 
        // User provided XML content here (Hard-coded only as an example).
        $xml = <<<EOD
        <?xml version="1.0"?>
        <!DOCTYPE root
        [
        <!ENTITY foo SYSTEM "file://$dir/content.txt">
        ]>
        <test><testing>&foo;</testing></test>
        EOD;

        $oldValue = libxml_disable_entity_loader(true);
        $doc = simplexml_load_string($xml);
        libxml_disable_entity_loader($oldValue);
    ?>
    ```

!!! success check done "Example Correct Usage"
    ```php
    <?php 
        // User provided XML content here (Hard-coded only as an example).
        $xml = <<<EOD
        <?xml version="1.0"?>
        <!DOCTYPE root
        [
        <!ENTITY foo SYSTEM "file://$dir/content.txt">
        ]>
        <test><testing>&foo;</testing></test>
        EOD;


        $oldValue = libxml_disable_entity_loader(true);
        $dom = new DOMDocument;
        $dom->loadXML($xml);
        libxml_disable_entity_loader($oldValue);
    ?>
    ```

### Go Specific Recommendations

Go's standard `encoding/xml` package does **not** process external entities or DTDs, and is therefore not vulnerable to XXE attacks by default. However, using third-party XML libraries or custom entity resolvers may introduce vulnerabilities.

!!! bug error "Example Incorrect Usage"
    ```go
    import (
        "bytes"
        "thirdparty/xmlquery" // Hypothetical third-party library that may process DTDs
    )

    func parseInsecureXML(data []byte) (*xmlquery.Node, error) {
        reader := bytes.NewReader(data)
        doc, err := xmlquery.Parse(reader)
        if err != nil {
            return nil, err
        }
        return doc, nil
    }
    ```

!!! success check done "Example Correct Usage"
    ```go
    import (
        "encoding/xml" // Use Go's standard library for XML parsing
    )

    type Test struct {
        Testing string `xml:"testing"`
    }

    func parseXML(data []byte) (*Test, error) {
        var t Test
        err := xml.Unmarshal(data, &t)
        if err != nil {
            return nil, err
        }
        return &t, nil
    }
    ```

!!! success check done "Example Correct Usage"
    ```go
    import (
        "encoding/xml"
        "io"
    )

    type Test struct {
        Testing string `xml:"testing"`
    }

    func decodeXML(r io.Reader) (*Test, error) {
        decoder := xml.NewDecoder(r)
        var t Test
        err := decoder.Decode(&t)
        if err != nil {
            return nil, err
        }
        return &t, nil
    }
    ```

## HTTP Response Splitting (CRLF Injection)
Including unvalidated data in an HTTP header allows an attacker to specify the entirety of the HTTP response rendered by the browser. When an HTTP request contains unexpected CR (carriage return, also given by %0d or \r) and LF (line feed, also given by %0a or \n) characters, the server may respond with an output stream that is interpreted as two different HTTP responses (instead of one). An attacker can control the second response and mount attacks such as cross-site scripting and cache poisoning attacks[^24].

For example, if the below snippet was used to set cookie value, malicious value `Wiley Hacker\r\nContent-Length:45\r\n\r\nHTTP/1.1 200 OK\r\n….` can result in generating two HTTP responses[^25].


```java
String author = request.getParameter(AUTHOR_PARAM); 
... 
Cookie cookie = new Cookie("author", author); 
cookie.setMaxAge(cookieExpiration); 
response.addCookie(cookie);
```

```bash
HTTP/1.1 200 OK 
Set-Cookie: author=Wiley Hacker
Content-Length:45

HTTP/1.1 200 OK
...
```

### Prevention Techniques
With regards to WSO2 Carbon 4 based products, Apache Tomcat will handle this internally, by disallowing "carriage return" and "line feed" characters from the header names or values[^26][^27].

If HTTP response generation is done in any other component, or any other HTTP transport implementation, it should be reviewed and confirmed to have a mechanism similar to Tomcat 6[^28] and Tomcat 7[^29]  that performs necessary filtering. If such a mechanism is not present in transport implementation, a central filter should be used to read all the headers and do the necessary sanitization before passing the response to transport.

Sample filter implementation is available in WSO2 Carbon 4.4.x branch[^30]. However, this filter is not in use, since Tomcat provides the necessary protection. 

!!! danger error "Alert - Approval Required"
    If any transport implementation or component that generates HTTP responses directly requires the usage of a custom-written filter that does the "carriage return" and "line feed" (CRLF) filtering, the logic performing filtering should be reviewed and approved by the Security and Compliance (SC) Team. The SC Team should be informed and approval should be obtained before releasing such components or a transport implementation.  

### Go Specific Recommendations

When developing HTTP handlers in Go, avoid including untrusted input directly in HTTP headers. Always validate or sanitize user input before using it in headers.

!!! bug error "Example Incorrect Usage"

    ```go
    http.HandleFunc("/set-cookie", func(w http.ResponseWriter, r *http.Request) {
        author := r.URL.Query().Get("author")

        http.SetCookie(w, &http.Cookie{
            Name:  "author",
            Value: author,
            MaxAge: 3600,
        })
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("Cookie set"))
    })
    ```

!!! success check done "Example Correct Usage"

    ```go
    http.HandleFunc("/set-cookie", func(w http.ResponseWriter, r *http.Request) {
        author := r.URL.Query().Get("author")
        // Sanitize input by removing CR and LF characters
        author = strings.ReplaceAll(author, "\r", "")
        author = strings.ReplaceAll(author, "%0d", "")
        author = strings.ReplaceAll(author, "\n", "")
        author = strings.ReplaceAll(author, "%0a", "")

        http.SetCookie(w, &http.Cookie{
            Name:  "author",
            Value: author,
            MaxAge: 3600,
        })
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("Cookie set"))
    })
    ```

!!! success check done "Example Correct Usage"

    ```go
    http.HandleFunc("/set-cookie", func(w http.ResponseWriter, r *http.Request) {
        author := r.URL.Query().Get("author")
        // Reject input with CR or LF characters
        if strings.ContainsAny(author, "\r\n") || strings.ContainsAny(author, "%0d%0a") {
            http.Error(w, "Invalid input", http.StatusBadRequest)
            return
        }

        http.SetCookie(w, &http.Cookie{
            Name:  "author",
            Value: author,
            MaxAge: 3600,
        })
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("Cookie set"))
    })
    ```

## Log Injection / Log Forging (CRLF Injection)
Including unvalidated data in log files allows an attacker to forge log entries or inject malicious content into logs. When a log entry contains unexpected CR (carriage return, also given by `%0d` or `\r`) and LF (line feed, also given by `%0a` or `\n`) characters, the server may record them in the log files/monitoring systems as different events. This can be used to forge log entries and might result in business level implications, if logs are used for further actions, such as reconciliation[^31].

For example, if the below snippet was used to print a log entry, malicious input `example1\r\n$100 payment made to author: example2` can result in generating two log lines.

```java
String author = request.getParameter(AUTHOR_PARAM); 
... 
log.info("$100 payment made to author: " + author);
```

```bash
$100 payment made to author: example1
$100 payment made to author: example2
```

### Prevention Techniques 
In WSO2 Carbon 4 (4.4.3 onwards), log appenders can be configured to append a UUID to each log entry. UUID will be randomly generated during server startup and the UUID regeneration time can be configured if such behavior is required. Therefore, even if a log line was forged, it would be possible to isolate the forged entry, since it will not contain the relevant valid UUID. 

UUID in logs can be enabled by adding %K in log4j pattern and relevant configuration is further documented in Administration Guide[^32].


## Session Hijacking
The Session Hijacking attack consists of the exploitation of the web session control mechanism, which is normally managed with a session token.

Because HTTP communication uses different TCP connections, the web server needs a method to recognize every user’s connections. The most useful method depends on a token that the Web Server sends to the client browser after successful client authentication. A session token is normally composed of a string of variable width and it could be used in different ways, like in the URL, in the header of the HTTP requisition as a cookie, in other parts of the header of the HTTP request, or yet in the body of the HTTP request. (In WSO2 products, session ID is maintained as a cookie and will be communicated between the browser and the server through HTTP headers).

The Session Hijacking attack compromises the session token by stealing or predicting a valid session token to gain unauthorized access to the Web Server[^33].

The session token could be compromised in different ways; the most common methods controllable by the application developer are:

* Session Sniffing
* Man-in-the-middle attack
* Predictable session token
* Client-side attacks (XSS, malicious JavaScript Codes, Trojans, etc)


### Prevention Techniques 

#### Preventing session sniffing and man-in-the-middle attacks

HTTP Strict-Transport-Security Header (HSTS)
:   HTTP Strict Transport Security (HSTS) is an opt-in security enhancement that is specified by a web application through the use of a special response header. Once a supported browser receives this header, that browser will prevent any communications from being sent over HTTP, to the specified domain and will instead send all communications over HTTPS[^34]. 

    HSTS header prevents sensitive information exposure over unencrypted channels by avoiding SSLStrip attacks [^35] and by preventing a victim from using HTTP links that correspond to an HTTPS-protected site, which could lead to session cookie exposure, if not configured properly.

    !!! tip hint important "WSO2 Document Reference"
        Further information on required changes and recommended configuration for WSO2 products as well as production deployments are available at [Engineering Guidelines - Security Related HTTP Headers]().

HTTP Public-Key-Pins Header (HPKP)
:   To ensure the authenticity of a server's public key used in TLS sessions, this public key is wrapped into an X.509 certificate which is usually signed by a certificate authority (CA). Web clients such as browsers trust a lot of these CAs, which can all create certificates for arbitrary domain names. If an attacker is able to compromise a single CA, they can perform MITM attacks on various TLS connections. HPKP can circumvent this threat for the HTTPS protocol by telling the client which public key belongs to a certain web server[^36].

    HPKP is a Trust on First Use (TOFU) technique. The first time a web server tells a client via a special HTTP header which public keys belong to it, the client stores this information for a given period of time. When the client visits the server again, it expects at least one certificate in the certificate chain to contain a public key whose fingerprint is already known via HPKP. If the server delivers an unknown public key, the client should present a warning to the user[^36].

    In addition, HPKP header prevents attack patterns such as SSLSplit attack[^37].

    !!! tip hint important "WSO2 Document Reference"
        Further information on required changes and recommended configuration for WSO2 products as well as production deployments are available at [Engineering Guidelines - Security Related HTTP Headers](../security-related-http-headers.md).


Avoiding predictable session token
:   Please refer to the documentation section [Session Prediction](#session-prediction). 

Preventing client-side attacks
:   Please refer to the documentation section [Cross-Site Scripting (XSS)](#cross-site-scripting-xss). 

Cookie security
:   Cookie attributes should be set properly, in order to prevent session related cookies from getting exposed over unencrypted channels.  Please refer to the documentation section [Securing Cookie](#securing-cookie). 

### Go Specific Recommendations 

When using sessions in Go, consider setting secure and HTTP-only flags on cookies to prevent session theft via XSS attacks.

!!! success check done "Example Correct Usage"
    ```go
    func configureSessionStore() {
        store := sessions.NewCookieStore([]byte("your-secret-key"))
        store.Options = &sessions.Options{
            Path:     "/",
            MaxAge:   86400, // 1 day
            HttpOnly: true,  // Prevents JavaScript access
            Secure:   true,  // Requires HTTPS
            SameSite: http.SameSiteStrictMode,
        }
    }
    ```

## Session Fixation
Session Fixation is an attack that permits an attacker to hijack a valid user session (a type of Session Hijacking attack). The attack explores a limitation in the way the web application manages the session ID, more specifically the vulnerable web application. When authenticating a user, it doesn’t assign a new session ID, making it possible to use an existing session ID. The attack consists of obtaining a valid session ID (e.g. by connecting to the application), inducing a user to authenticate himself with that session ID, and then hijacking the user-validated session by the knowledge of the used session ID. The attacker has to provide a legitimate Web application session ID and try to make the victim's browser use it[^38].


### Prevention Techniques 

#### User Login Flow
When a user is successfully authenticated, a new session should be initiated and the guest session that was maintained to access the login sequence should be invalidated. This approach makes sure that an attacker is unable to use a compromised guest session token to gain access to an active user session.


#### User Logout Flow
When a user logs out of the system, any existing session should be invalidated so that an attacker is unable to login back into the system by re-submitting the previous session token.


### Java Specific Recommendations 

#### User Login Flow
Invalidate the HttpSession and create a new session after authentication is complete, and before setting any values to the user session.

!!! bug error "Example Incorrect Usage"
    ```java
    boolean validLogin = login(username, password);
    if(validLogin) {
        session.setAttribute(Constants.IS_AUTHENTICATED, Constants.AUTHENTICATED);
        session.setAttribute(Constants.AUTHENTICATED_USER, username);
    }
    ```

!!! success check done "Example Correct Usage"
    ```java
    boolean validLogin = login(username, password);
    if(validLogin) {
        session.invalidate();
        session = request.getSession();
        session.setAttribute(Constants.IS_AUTHENTICATED, Constants.AUTHENTICATED);
        session.setAttribute(Constants.AUTHENTICATED_USER, username);
    }
    ```


#### User Logout Flow
Invalidate the HttpSession, rather than just removing user-specific attributes. 

!!! bug error "Example Incorrect Usage"
    ```java
    //… logout sequence
    session.removeAttribute(Constants.IS_AUTHENTICATED);
    session.removeAttribute(Constants.AUTHENTICATED_USER);
    ```

!!! success check done "Example Correct Usage"
    ```java
    //… logout sequence
    session.invalidate();
    ```


#### Other Best Practices
Do not use HttpServletResponse#encodeRedirectURL() or HttpServletResponse#encodeURL, in any operation, since it will append the session ID to the resulting URL. Since WSO2 products are dependent on cookies, there is no functional impact of not running URLs through these methods.

!!! bug error "Example Incorrect Usage"
    ```java
    String redirectUrl = response.encodeRedirectURL(request.getContextPath() + Constant.STORE_FRONT_URL);
    response.sendRedirect(redirectUrl);
    ```

!!! success check done "Example Correct Usage"
    ```java
    String redirectUrl = request.getContextPath() + Constant.STORE_FRONT_URL;
    response.sendRedirect(redirectUrl);
    ```


### PHP Specific Recommendations 

#### User Login Flow
Use session_regenerate_id function to renew the session after successful authentication.

!!! bug error "Example Incorrect Usage"
    ```php
    <?php
        $validLogin = login($username, $password);
        if(validLogin) {
            $_SESSION[Constants::IS_AUTHENTICATE] = Constants::AUTHENTICATED; 
            $_SESSION[Constants::AUTHENTICATED_USER] = $username; 
        }
    ?>
    ```

!!! success check done "Example Correct Usage"
    ```php
        <?php
            boolean validLogin = login($username, $password);
            if(validLogin) {
                if(session_regenerate_id(true)) {
                    $_SESSION[Constants::IS_AUTHENTICATE] = Constants::AUTHENTICATED; 
                    $_SESSION[Constants::AUTHENTICATED_USER] = $username; 
                } else {
                    //...
                }
            }
        ?>
    ```


#### User Logout Flow
Destroy current session using session_destroy function, rather than just removing user specific attributes. 

!!! bug error "Example Incorrect Usage"
    ```php
    <?php
        //… logout sequence
        unset($_SESSION[Constants::IS_AUTHENTICATED]);
        unset($_SESSION[Constants::AUTHENTICATED_USER]);
    ?>
    ```

!!! success check done "Example Correct Usage"
    ```php
    <?php
        //… logout sequence
        session_destroy();
    ?>
    ```


### Go Specific Recommendations 

#### User Login Flow
When managing sessions in Go, generate a new session ID after a successful authentication.

!!! bug error "Example Incorrect Usage"
    ```go
    func loginHandler(w http.ResponseWriter, r *http.Request) {
        session, _ := store.Get(r, "session-name")
        
        // Authenticate user
        if login(username, password) {
            // Set user as authenticated in session
            session.Values["authenticated"] = true
            session.Values["user"] = username
            session.Save(r, w)
        }
    }
    ```

!!! success check done "Example Correct Usage"
    ```go
    func loginHandler(w http.ResponseWriter, r *http.Request) {
        session, _ := store.Get(r, "session-name")
        
        // Authenticate user
        if login(username, password) {
            // Invalidate existing session
            session.Options.MaxAge = -1
            session.Save(r, w)
            
            // Create new session
            session, _ = store.New(r, "session-name")
            session.Values["authenticated"] = true
            session.Values["user"] = username
            session.Save(r, w)
        }
    }
    ```

#### User Logout Flow
When a user logs out, explicitly delete the session rather than simply removing attributes.

!!! bug error "Example Incorrect Usage"
    ```go
    func logoutHandler(w http.ResponseWriter, r *http.Request) {
        session, _ := store.Get(r, "session-name")
        
        // Just remove the authentication flags
        delete(session.Values, "authenticated")
        delete(session.Values, "user")
        session.Save(r, w)
    }
    ```

!!! success check done "Example Correct Usage"
    ```go
    func logoutHandler(w http.ResponseWriter, r *http.Request) {
        session, _ := store.Get(r, "session-name")
        
        // Set MaxAge to -1 to delete the session
        session.Options.MaxAge = -1
        session.Save(r, w)
    }
    ```


## Session Prediction
Session prediction attack focuses on predicting session ID values that permit an attacker to bypass the authentication schema of an application. By analyzing and understanding the session ID generation process, an attacker can predict a valid session ID value and get access to the application.

In the first step, the attacker needs to collect some valid session ID values that are used to identify authenticated users. Then, the attacker must understand the structure of the session ID, the information that is used to create it, and the encryption or hash algorithm used by the application to protect it. Some bad implementations use session IDs composed of usernames or other predictable information, like timestamps or client IP addresses. In the worst case, this information is used in clear text or coded using some weak algorithm like base64 encoding.

In addition, the attacker can implement a brute force technique to generate and test different values of session ID until he successfully gets access to the application[^39].


### Prevention Techniques 
Using a long random number or string as the session key will reduce the risk that an attacker could simply guess a valid session key through trial and error or brute force attacks. Session identifiers should be at least 128 bits long to prevent brute-force session guessing attacks, according to OWASP recommendations[^40].


### Java Specific Recommendations 
WSO2 Carbon 4 based products can use the Apache Tomcat context.xml file to configure the session ID generation. The default session ID length is 16 bytes, which is exactly 128 bit. Therefore, WSO2 Carbon 4 based products match the current recommendation. However, if the recommendations change and if any product needs to increase the session ID length, it is possible to use the `SessionIdGenerator` element of the `context.xml` file to make the required changes as documented in Tomcat 7 "SessionIdGenerator Component" documentation[^41].


### PHP Specific Recommendations 
Below minimum session configuration should be used with PHP applications[^42]:
```ini
session.hash_function   = 1
session.hash_bits_per_character = 6
```

Full set of recommended session configuration is:
```ini
session.auto_start      = Off
#session.save_path       = /path/PHP-session/
#session.name            = CUSTOMSESSID
session.hash_function   = 1
session.hash_bits_per_character = 6
session.use_trans_sid   = 0
session.cookie_domain   = full.qualified.domain.name
#session.cookie_path     = /application/path/
session.cookie_lifetime = 0
session.cookie_secure   = On
session.cookie_httponly = 1
session.use_only_cookies= 1
session.cache_expire    = 30
```


### Go Specific Recommendations 
For Go applications, you can use `crypto/rand` package to generate secure random session IDs rather than using `math/rand` package which is deterministic. Here’s an example of how to generate a secure session ID in Go.

```go
import (
    "crypto/rand"
    "encoding/base64"
)

// GenerateSessionID creates a secure random session ID of at least 128 bits (16 bytes)
func GenerateSessionID() (string, error) {
    b := make([]byte, 16)
    _, err := rand.Read(b)
    if err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(b), nil
}
```


## Heap Inspection Attacks
When sensitive data such as a password or an encryption key is not removed from memory, it could be exposed to an attacker using a "heap inspection" attack that reads the sensitive data using memory dumps or other methods [^43]. 


### Prevention Techniques 
It is recommended to store sensitive information such as user passwords in mutable data types or data structures. Once usage is complete, it is essential to clear the memory space and make sure none of the stored data is present in the memory. 


### Java Specific Recommendations
It would seem logical to collect and store the password in an object of type java.lang.String. However, here's the caveat: Objects of type String are immutable, i.e., there are no methods defined that allow you to change (overwrite) or zero out the contents of a String after usage 29. 

Even if a String object is no longer referenced and available for garbage collection, the object can stay in the memory for multiple garbage collection cycles, allowing a heap inspection attack to capture relevant values.

This feature makes String objects unsuitable for storing security-sensitive information such as user passwords. It is essential to always collect and store security-sensitive information in a char array or a mutable data type instead[^44].

Once operations that require a password are executed, it is required to clear the values from the array elements, before moving the variable out of scope. 

!!! bug error "Example Incorrect Usage"
    ```java
    String userPassword = getUserPassword(request);
    ```

!!! bug error "Example Incorrect Usage"
    ```java
    //… 
    char[] userPassword = getUserPassword(request);
    boolean valid = validateUser(username, userPassword);
    if(valid) {
        //Do valid actions
    }
    return valid;
    //… 
    ```

!!! success check done "Example Correct Usage"
    ```java
    private static final List<String> SENSITIVE_PARAMETER_NAME_LIST = new ArrayList<String>();
    
    //… 
    Map<String, Object> parameterMap = SecurityUtil.getSensitiveDataMap(request, SENSITIVE_PARAMETER_NAME_LIST);

    char[] userPassword = (char[]) parameterMap.get("password");
    String otherNonSensitiveData = (String) parameterMap.get("otherNonSensitiveData");

    boolean valid = validateUser(username, userPassword);
    if(valid) {
        //Do valid actions
    }
    SecurityUtil.clearSensitiveDataMap(userPassword);
    return valid;
    //… 


    public static void clear(char[] arr) {
        for(int i = 0; i < arr.length; i++) {
            arr[0] = '';
        }
    }
    ```


### Go Specific Recommendations
In Go, strings are immutable like in Java. Once a string is created, it cannot be modified, which means sensitive data stored in strings can remain in memory even after they're no longer referenced, making them vulnerable to heap inspection attacks.

For handling sensitive information, use byte slices (`[]byte`) which are mutable, and explicitly zero out the memory before the variable goes out of scope.

!!! bug error "Example Incorrect Usage"
    ```go
    userPassword := getUserPassword(request)  // userPassword is a string, which is immutable
    ```

!!! bug error "Example Incorrect Usage"
    ```go
    userPassword := getUserPassword(request)  // Returns []byte
    valid := validateUser(username, userPassword)
    if valid {
        // Do valid actions
    }
    return valid
    ```

!!! success check done "Example Correct Usage"
    ```go
    userPassword := getUserPassword(request)  // Returns []byte
    valid := validateUser(username, userPassword)
    if valid {
        // Do valid actions
    }
    
    // Clear the password from memory
    ClearSensitiveData(userPassword)
    
    return valid
    
    // Helper function to clear sensitive data
    func ClearSensitiveData(data []byte) {
        for i := range data {
            data[i] = 0
        }
    }
    ```

Another approach is to use a dedicated package like `crypto/subtle` which provides constant-time operations to prevent timing attacks while handling sensitive data:

!!! success check done "Example Using crypto/subtle"
    ```go
    import "crypto/subtle"
    
    // When comparing sensitive data like password hashes
    isEqual := subtle.ConstantTimeCompare(storedHash, computedHash) == 1
    ```


## Privacy Violation - Password AutoComplete
Browsers will sometimes ask a user if they wish to remember the password that they just entered. The browser will then store the password, and automatically enter it whenever the same authentication form is visited. This is a convenience for the user[^45]. 

Having the browser store passwords is not only a convenience for end users, but also for an attacker. If an attacker can gain access to the victim's browser (e.g. through a Cross Site Scripting attack, or through a shared computer), then they can retrieve the stored passwords. It is not uncommon for browsers to store these passwords in an easily retrievable manner, but even if the browsers were to store the passwords encrypted and only retrievable through the use of a master password, an attacker could retrieve the password by visiting the target web application's authentication form, entering the victim's username, and letting the browser to enter the password[^45].

Due to associated security risks relevant to password auto complete, it is recommended to turn autocomplete off, for sensitive text fields. This includes password inputs. 

!!! bug error "Example Incorrect Usage"
    ```html
    <input type="password" name="password" />
    ```


!!! success check done "Example Correct Usage[^46]"
    ```html
    <input type="password" name="password" autocomplete="off"/>
    ```

In order to support password managers and increase the usability features of browsers, some modern browsers do not honor the autocomplete attribute. However, regardless of the behavior of the browser, it is advised to turn autocomplete off, to address security compliance related issues.


## Path Traversal
A path traversal attack (also known as directory traversal) aims to access files and directories that are stored outside the web root folder. By manipulating variables that reference files with “dot-dot-slash (../)” sequences and their variations or by using absolute file paths, it may be possible to access arbitrary files and directories stored on the file system including application source code or configuration and critical system files [^47].


### Prevention Techniques 
Absolute paths should not be accepted from by end user during any operation, apart from administrative configurations. 

!!! danger error "Alert - Approval Required"
    If any component requires that an absolute path must be accepted from the end user (not in administrative configuration), the use-case, as well as recommended security manager rules that are in place to provide the required protection, must be reviewed and approved by the Security and Compliance Team, before proceeding with the release of such component.

The general recommendation is to avoid accepting paths or path fragments (used to build absolute or relative paths) from the end user. 

However, if any such requirement arises, it is necessary to follow language specific recommendations for validating the accepted path fragment. 


### Java Specific Recommendations
Normalize [^48] the final path constructed and check if the normalized path is within the expected boundary. The purpose of this validation is to check if any malicious user has used ".." or other traversal techniques to move out of the expected base directory that the action should be performed on.  

!!! bug error "Example Incorrect Usage"
    ```java
    String userDirectory = request.getParameter("userDirectory");
    File file = new File(Constants.USER_HOME_BASE + File.separator + userDirectory + File.separator + Constants.LOG_FILE_NAME);
    ```

!!! success check done "Example Correct Usage[^49]"
    ```java
    //... 
    String userDirectory = request.getParameter("userDirectory");
    Path resolvedPath = null;
    try {
        resolvedPath = SecurityUtil.resolvePath(Constants.USER_HOME_BASE, userDirectory + File.separator + Constants.LOG_FILE_NAME);
    } catch (IllegalArgumentException e) {
        //Exception handling and informing end-user in the errors
        return;
    }
    File file = new File(resolvedPath.toString());
    //… 

    public class SecurityUtil {
    //…

    /**
        * Resolves an untrusted user-specified path against the API's base directory.
        * Paths that try to escape the base directory are rejected.
        *
        * @param baseDirPath  the absolute path of the base directory that all
                        user-specified paths should be within
        * @param userPath  the untrusted path provided by the API user, expected to be
                    relative to {@code baseDirPath}
        */
        public static Path resolvePath(final Path baseDirPath, final Path userPath) {
            if (!baseDirPath.isAbsolute()) {
                throw new IllegalArgumentException("Base path must be absolute")
            }

            if (userPath.isAbsolute())
                throw new IllegalArgumentException("User path must be relative");
            }

            // Join the two paths together, then normalize so that any ".." elements
            // in the userPath can remove parts of baseDirPath.
            // (e.g. "/foo/bar/baz" + "../attack" -> "/foo/bar/attack")
            final Path resolvedPath = baseDirPath.resolve(userPath).normalize();

            // Make sure the resulting path is still within the required directory.
            // (In the example above, "/foo/bar/attack" is not.)
            if (!resolvedPath.startsWith(baseDirPath)) {
                throw new IllegalArgumentException("User path escapes the base path");
            }

            return resolvedPath;
        }
    }
    ```


### PHP Specific Recommendations
Normalize the final path constructed and check if the normalized path is within the expected boundary. The purpose of this validation is to check if any malicious user has used ".." or other traversal techniques to move out of the expected base directory that the action should be performed on.  

!!! success check done "Example Correct Usage[^50]"
    ```php
    <?php
        $basepath = USER_HOME_BASE;
        $realBase = realpath($basepath);

        $userDirectory = $basepath . DIRECTORY_SEPARATOR . $_GET['userDirectory'];
        $userDirectoryRealPath = realpath($userDirectory);

        if ($userDirectoryRealPath === false || strpos($userDirectoryRealPath, $realBase) !== 0) {
            //Directory Traversal. Informing end-user in the errors.

        } else {
            //No Directory Traversal. Proceed with usual operations based on userDirectoryRealPath.
        }
    ?>
    ```


### Go Specific Recommendations
Normalize the final path constructed and check if the normalized path is within the expected boundary. The purpose of this validation is to check if any malicious user has used ".." or other traversal techniques to move out of the expected base directory that the action should be performed on.

!!! bug error "Example Incorrect Usage"
    ```go
    userDirectory := r.URL.Query().Get("userDirectory")
    filePath := constants.USER_HOME_BASE + "/" + userDirectory + "/" + constants.LOG_FILE_NAME
    file, err := os.Open(filePath)
    ```

!!! success check done "Example Correct Usage"
    ```go
    package main
    
    import (
        "net/http"
        "os"
        "path/filepath"
        "strings"
    )
    
    func handleFileRequest(w http.ResponseWriter, r *http.Request) {
        userDirectory := r.URL.Query().Get("userDirectory")
        
        // Join paths securely and normalize
        requestedPath := filepath.Join(constants.USER_HOME_BASE, userDirectory, constants.LOG_FILE_NAME)
        
        // Clean the path to resolve any ".." or other path manipulations
        requestedPath = filepath.Clean(requestedPath)
        
        // Verify the resulting path is still within the base directory
        baseAbs, err := filepath.Abs(constants.USER_HOME_BASE)
        if err != nil {
            http.Error(w, "Internal server error", http.StatusInternalServerError)
            return
        }
        
        requestedAbs, err := filepath.Abs(requestedPath)
        if err != nil {
            http.Error(w, "Internal server error", http.StatusInternalServerError)
            return
        }
        
        if !strings.HasPrefix(requestedAbs, baseAbs) {
            // Path traversal detected
            http.Error(w, "Invalid path", http.StatusBadRequest)
            return
        }
        
        // Safe to proceed
        file, err := os.Open(requestedPath)
        if err != nil {
            http.Error(w, "Cannot open file", http.StatusInternalServerError)
            return
        }
        defer file.Close()
        
        // Continue with file operations
    }
    ```


## Missing Function Level Access Control
If the authentication check in sensitive request handlers is insufficient or non-existent, the vulnerability can be categorized as Missing Function Level Access Control[^51].


### Prevention Techniques 
* Make sure authentication checks are present for any restricted URLs.
* Make sure user authorization (role permission) is checked before allowing a user to execute any function. It is essential to make sure authorization checks are done, before processing any state-changing operation. 
* "login" permission should not be granted for any user that does not require access to Carbon Management Console (Carbon 4). (Example: API Manager - Store - Self-registered user).
* The enforcement mechanism(s) should deny all access by default, requiring explicit grants to specific roles for access to every function.
* If the function is involved in a workflow, check to make sure the conditions are in the proper state to allow access.
* Make sure audit logs are maintained properly and authentication and authorization related changes are logged in audit logs. 


## Security Misconfiguration
This section is not within the scope of "Secure Coding Guidelines". However, necessary prevention techniques are summarized for information. 

If a component is susceptible to attack due to an insecure configuration it would classify as security misconfiguration[^52]. 


### Prevention Techniques 

#### Product Documentation
Product documentation should explain or reference steps to be executed in order to perform required security hardening and production deployment guidelines should include security-related instructions. 

All the default credentials, default certificates and security sensitive information such as ports being opened should be properly documented. 


#### Deployments 
All WSO2 deployments should follow security hardening guidelines and production deployment guidelines in security sensitive environments. 

Production and staging environments should be configured identically. Configuration, as well as artifact deployment between these environments, should be automated and should follow a proper change management process to make sure no configuration changes are done in production environments without proper security evaluation.

External components of the deployment such as the operating system and runtime environment should be updated regularly and must be updated when relevant "security updates" are released. 

Default credentials, default certificates, and any security sensitive default values should not be used in production environments (as recommended in security hardening guidelines and production deployment guidelines). 


## Insecure Deserialization
Deserialization is the process of creating an object from binary data or text data. It is the opposite process of serialization. When serialized data is in control of an attacker, insecure deserialization flaws can enable an attacker to cause remote code execution upon deserialization or create malicious deserialized objects that can cause remote code execution and data tampering upon usage[^53].


### Prevention Techniques

#### Use language specific guidelines
Use language-specific guidelines to enumerate safe methodologies for deserializing data that can't be trusted.


#### Additional prevention techniques[^54]
* Implementing integrity checks such as digital signatures on any serialized objects to prevent hostile object creation or data tampering.
* Log deserialization exceptions and failures, such as where the incoming type is not the expected type, or the deserialization throws exceptions.


### PHP Specific Recommendations
Check the use of `unserialize()` and review how the external parameters are accepted. Use a safe, standard data interchange format such as JSON (via `json_decode()` and `json_encode()`) if you need to pass serialized data to the user. If you need to deserialize externally-stored data, consider using hash `hmac()` for data validation. Make sure data is not modified by anyone but you[^55].
 

### JAVA Specific Recommendations

#### Secure `java.io.ObjectInputStream`
The technique is overriding the ObjectInputStream#resolveClass() method to prevent arbitrary classes from being deserialized. This safe behavior can be wrapped by using  SerialKiller. SerialKiller inspects Java classes during naming resolution and allows a combination of blacklisting or whitelisting to secure the application[^54].

!!! bug error "Example Usual Usage"
    ```java
    ObjectInputStream ois = new ObjectInputStream(untrustedInputStream);
    String message = (String)ois.readObject();
    ```

In order to detect malicious payloads or allow trusted classes only, SerialKiller should be used instead of the standard `java.io.ObjectInputStream`[^56].

!!! success check done "Example Recommended Usage"
    ```java
    ObjectInputStream ois = new SerialKiller(is, “/etc/serialkiller.conf”);
    String message = (String) ois.readObject();
    ```

The second argument is the location of SerialKiller's configuration file. InvalidClassException exceptions should be used to gracefully handle insecure object deserialization. 


#### Prevent Data Leakage
If there are data members of an object that should never be controlled by end users during deserialization or exposed to users during serialization, they should be declared as "transient".
For a class that is defined as Serializable, the sensitive variables should be declared as 'private transient'. For example, the variable 'name' and 'age' of the class Foo were declared as transient to avoid being serialized[^54].

!!! success check done "Example Recommended Usage"
    ```java
    public class Foo implements Serializable
    {
        private transient String name;
        private transient String age;
        ……….
        ……...
    ```
 

#### Prevent Deserialization of Domain Objects
If a class must implement Serializable only due to their hierarchy, in order to guarantee that the objects can’t be deserialized, readObject method should be declared with the final modifier[^54]. 

!!! success check done "Example Recommended Usage"
    ```java
    private final void readObject(ObjectInputStream in) throws java.io.IOException{
        throw new java.io.IOException(“Cannot be deserialized”);
    }
    ```


#### Harden own `java.io.ObjectInputStream`
Override `ObjectInputStream.html#resolveClass()` to restrict which classes are allowed to be deserialized. 
An example code ensures the SampleObjectInputStream class is guaranteed not to deserialize any type other than the Foo class.

!!! success check done "Example Recommended Usage"
    ```java
    public class SampleObjectInputStream extends ObjectInputStream{
        Public SampleObjectInputStream(InputStream inpuStream) throws IOException{
            super(inputStream);
        }

        @Overide
        protected Class<?> resolveClass(ObjectStreamClass osc) throws IOException,       ClassNotFoundException{
            if(!osc.getName().equals(Foo.class.getName())){
                throw new InvalidClassException(“Unauthorized deserialization attempt”,
                            osc.getName());
            }
            return super.resolveClass(osc);
        } 
    }
    ```


### Go Specific Recommendations

Go provides several packages for serialization and deserialization, such as `encoding/json`, `encoding/xml`, and `encoding/gob`. When handling untrusted input, following secure practices is essential to prevent insecure deserialization vulnerabilities.

#### Use Type-Based Deserialization

Always deserialize into specific types rather than using generic containers like `map[string]interface{}` when dealing with untrusted data. This ensures that the data conforms to expected structures.

!!! bug error "Example Incorrect Usage"
    ```go
    var data map[string]interface{}
    err := json.Unmarshal(untrustedInput, &data)
    // Using data without validation
    ```

!!! success check done "Example Recommended Usage"
    ```go
    type SafeType struct {
        Name string
        Value int
        // Define only the fields you expect
    }
    
    var safeData SafeType
    err := json.Unmarshal(untrustedInput, &safeData)
    if err != nil {
        // Handle error properly
    }
    ```

#### Validate Deserialized Data

Always validate deserialized data before using it, even when deserializing into specific types.

!!! success check done "Example Recommended Usage"
    ```go
    type UserData struct {
        Username string `json:"username"`
        Role     string `json:"role"`
    }
    
    func validateAndProcess(input []byte) error {
        var userData UserData
        if err := json.Unmarshal(input, &userData); err != nil {
            return err
        }
        
        // Validate the data
        if !isValidUsername(userData.Username) || !isAllowedRole(userData.Role) {
            return errors.New("invalid data after deserialization")
        }
        
        // Process the validated data
        return nil
    }
    ```

#### Avoid `gob` Encoding with Untrusted Data

The `encoding/gob` package is designed for sending Go data structures between Go programs. It can deserialize arbitrary types, which is dangerous when handling untrusted input.

!!! bug error "Example Unsafe Usage"
    ```go
    var network bytes.Buffer
    dec := gob.NewDecoder(&network)
    var data interface{}
    err := dec.Decode(&data)
    ```

!!! success check done "Example Recommended Usage"
    ```go
    // When receiving external data, prefer json or other formats with explicit typing
    var network bytes.Buffer
    var safeData DefinedType
    dec := json.NewDecoder(&network)
    dec.DisallowUnknownFields() // Reject JSON with unknown fields
    err := dec.Decode(&safeData)
    ```

#### Limit Input Size

Always limit the size of input you accept to prevent processing extremely large payloads.

!!! success check done "Example Recommended Usage"
    ```go
    func secureDecodeJSON(r io.Reader, v interface{}) error {
        // Limit reader to prevent excessive memory usage
        limitedReader := io.LimitReader(r, 1024*1024) // 1MB limit
        decoder := json.NewDecoder(limitedReader)
        decoder.DisallowUnknownFields()
        return decoder.Decode(v)
    }
    ```


## Using Known Vulnerable Components
Outdated components may have known vulnerabilities that are exploitable. Public databases such as NVD[^57] and ExploitDB[^58] offer information on known vulnerabilities and exploits available. 


### Introducing New External Dependencies
When introducing new external dependency components, use the most up-to-date version of the component. 

Selected the most up-to-date version should be scanned using OWASP Dependency Check for known vulnerabilities by following [Engineering Guidelines - External Dependency Analysis using OWASP Dependency Check](../external-dependency-analysis-analysis-using-owasp-dependency-check.md). 

External dependency, as well as all transitive dependencies getting added, should be scanned using instructions from "OWASP Dependency Check CLI" section of the document.

!!! tip hint important "WSO2 Document Reference"
    Further information on required changes and code-level examples are available at "Engineering Guidelines - External Dependency Analysis using OWASP Dependency Check".

The generated report should be attached with the usual "Approval Request" and the approval request should be copied to the Security Leads Group email. 

If the most up-to-date version contains a known vulnerability, and if there is no active development happening, other alternatives should be considered, rather than using the vulnerable library.

!!! danger error "Alert - Approval Required"
    Any external dependency component approval request should include OWASP Dependency Check report (or else the Security and Compliance Team will downvote the approval request). 

    Any external component with known vulnerability should not be introduced as a dependency. If there is any exceptional situation, the Security and Compliance (SC) Team should be informed and a review should be conducted on the use case, source code, known vulnerabilities and controls in place for mitigating the impact of the vulnerability in usage path. The SC Team's approval is required before introducing such dependency. 


### Vulnerabilities in Current Dependencies 
OWASP Dependency Check maven plugin should be integrated into the build process of the latest product builds, by following [Engineering Guidelines - External Dependency Analysis using OWASP Dependency Check](../external-dependency-analysis-analysis-using-owasp-dependency-check.md). 

!!! tip hint important "WSO2 Document Reference"
    Further information on required changes and code-level examples are available at "Engineering Guidelines - External Dependency Analysis using OWASP Dependency Check".

Engineers can execute Dependency Check by calling the " dependency-check:check" maven goal, in the development environment. However, Jenkins will execute this task by default during the scheduled builds, to identify if any latest product build contains external dependencies with known security vulnerabilities.

When it is identified that a security vulnerability has been identified for a particular external dependency, it is recommended to do the following:

1. Initiate relevant discussion at the Security Group mailing list with the subject "Dependency Vulnerability - [DependencyName] - [DependencyVersion] - [CVE]"
2. Analyze the impact on the usage of WSO2, relevant to the particular dependency and identify if usage of WSO2 makes any product vulnerable.

    1. If yes, take necessary corrective actions to migrate to a higher version of the dependency with no known security vulnerabilities.
    2. If yes, and no new version of the dependency exists, take necessary actions to nullify the impact of the vulnerability on the usage of WSO2, by introducing additional validations or security checks.

    :   !!! danger error "Alert - Approval Required"
            The Security and Compliance Team should review any validations, additional security checks or additional security constraints added in order to nullify the impact of a known vulnerability in an external dependency when no newer version is available and no active development is happening. 

    3. If not, update the mail thread with the reasoning and request approval from the Security and Compliance (SC) Team to add relevant mitigation information into OWASP Dependency Check, suppression file relevant to the component.

    :   !!! danger error "Alert - Approval Required"
            The Security and Compliance Team should review and merge pull requests, adding any entries to a particular component's OWASP Dependency Check suppression file. During the review, mitigated reason, dependency source, and usage path will be reviewed. This is further explained in [Engineering Guidelines - OWASP Dependency Check](../external-dependency-analysis-analysis-using-owasp-dependency-check.md).


## Insufficient logging and Monitoring
Insufficient logging and ineffective integration with security incident response systems allow attackers to pivot to other systems and maintain persistent threats for weeks or months before being detected. This leads attackers to tamper, extract or system data[^59]. 


### Prevention Techniques
As per the risk of the data stored or processed by the WSO2 products[^60]:

* Ensure all login, access control failures, and server-side input validation failures can be logged with sufficient user context to identify suspicious or malicious accounts, and held for sufficient time to allow delayed forensic analysis.
* Ensure that logs are generated in a format that can be easily consumed by centralized log management solutions.
* Ensure high-value transactions have an audit trail with integrity controls to prevent tampering or deletion, such as append-only database tables or similar.


## Cross-Site Request Forgery (CSRF)
Cross-Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated. CSRF attacks specifically target state-changing requests, not theft of data, since the attacker has no way to see the response to the forged request. With a little help of social engineering (such as sending a link via email or chat), an attacker may trick the users of a web application into executing actions of the attacker's choosing. If the victim is a normal user, a successful CSRF attack can force the user to perform state-changing requests like transferring funds, changing their email address, and so forth. If the victim is an administrative account, CSRF can compromise the entire web application[^61].


### Prevention Techniques 
There are multiple techniques used for preventing CSRF attacks which are further documented in Cross-Site Request Forgery (CSRF) Prevention Cheat Sheet[^62]. 


#### Synchronizer Token Pattern
With Synchronizer Token Pattern, any state-changing operation requires a secure random token which is generally known as CSRF Token. CSRF Token is a unique large random string generated per user session, using a [secure pseudorandom number generator](#random-number-generation). 

Once the user session is created, per-session CSRF Token should be added to the server session as well. The storage of CSRF Token happens in the server session. 

Generated CSRF Token should be added to all the forms, generating requests for state-changing operations, as a hidden input. The server should do additional validation and reject the request if the CSRF Token sent in the request does not match the token available in the user session. In addition to forms, AJAX requests for state-changing operations should also include the CSRF Token. 

Ultimately, the attacker will not be able to make a form submission to a protected application, since the attacker will need to know the per-session CSRF Token value in advance, to craft the attack vector. 

This pattern is further discussed in "Core J2EE Patterns"[^63].

!!! bug error "Example of an Incorrectly Designed HTML Form"
    ```html
    <form action="create_user" method="POST">
        <div>Username : <input type="text" name="username"></div>
        <div>Password : <input type="password" name="password"></div>
    </form> 
    ```

!!! success check done "Example of a Correctly Designed HTML Form"
    ```html
    <form action="create_user" method="POST">
        <div>Username : <input type="text" name="username"></div>
        <div>Password : <input type="password" name="password"></div>
        <input type="hidden" name="CSRFToken" value="MJpTVsF0EKZGnqbYxvizCupE9AOxhKWmKdD3E6uMVean36CEENAF7Q3swB8TQT5zAERQvvt3lgq2">
    </form> 
    ```


#### Double Submit Cookie
The difference between "Double Submit Cookie" and "Synchronize Token Pattern" is that, "Synchronize Token Pattern" uses a server session for storing CSRF Token, whereas "Double Submit Cookie" approach uses cookies to store the CSRF Token.

Upon user login, per-session CSRF token value should be generated and it should be sent to the browser as a cookie. The server may decide not to store the CSRF token value.

When rendering HTML pages with forms, client-side JavaScript should read the CSRF Token cookie value and inject the value in all forms. In addition, AJAX requests should be modified to send the same value with AJAX requests. 

When an application sends an HTTP request for a state changing operation (over HTTP method other than GET), the server should compare the CSRF Token received over the request cookies, with the CSRF Token value received in the request payload (query parameter/post data). If values are not matching, the request can be identified as a possible CSRF attack. 

If an attacker creates a forged HTTP request to perform a CSRF attack, the correct CSRF Token value will still be sent in the cookie, but he will not have required cross-domain access to read the token value and inject the same into the HTML forms. 


### Java Specific Recommendations

* WSO2 products based on WSO2 Carbon Kernel versions prior to 4.4.6 use "Referer Header" based CSRF prevention, which is **no longer recommended**. 
* WSO2 products based on WSO2 Carbon Kernel 4 (4.4.6+) should use "Synchronizer Token Pattern" based CSRF prevention, using OWASP CSRFGuard[^64].
* WSO2 Carbon Kernel 5+ based products and any new applications should use "Double Submit Cookie" approach in CSRF prevention.


#### Synchronizer Token Pattern (WSO2 Carbon Kernel 4 (4.4.6+))
OWASP CSRFGuard is used to implement Synchronizer Token Pattern in WSO2 Carbon Kernel 4 (4.4.6+) products. OWASP CSRFGuard provides required classes to generate the per-session token and to do necessary validation on state-changing operations. Furthermore, it provides a JavaScript which is capable of dynamically adding CSRF Token as a hidden input and overriding XMLHttpRequest to include CSRF Token in AJAX requests.

!!! tip hint important "WSO2 Document Reference"
    Further information on required changes and code-level examples are available in [Engineering Guidelines - OWASP CSRF Guard](../owasp-csrf-guard.md) document.


In summary, when integrating OWASP CSRFGuard with a product, it is required to do the following changes:

* Make sure all the state-changing operations are performed using HTTP methods other than GET. **GET requests must not be used for state-changing operations**. 
* In web.xml or jaggery.conf file, add `CsrfGuardServletContextListener`.
    * This class is responsible for loading CSRFGuard configuration and doing the initialization of the component. 
* In web.xml or jaggery.conf file, add `CsrfGuardHttpSessionListener`.
    * This class is responsible for generating and storing per-session CSRF Token.
* In web.xml or jaggery.conf file, add `CsrfGuardFilter`.
    * This class is responsible for comparing the submitted CSRF Token with the token in user session, and generating error response if an attack was detected. 
* In web.xml or jaggery.conf file, add `JavaScriptServlet`.
    * This class is responsible for serving the JavaScript file that is dynamically adding the CSRF Token to forms and AJAX requests.
* Include `JavaScriptServlet` in the HTML template of the application, so that `<head>` element of all pages that need to be protected, should have `JavaScriptServlet` as the first JavaScript inclusion.
* Prepare and store per-application CSRF configuration file according to "*repository/conf/security/Owasp.CsrfGuard.Carbon.properties*" or reuse the Carbon CSRF configuration.
* Do thorough testing on the CSRF protected application to verify that there is no functional impact.


### Go Specific Recommendations

* For Go applications, use established CSRF protection libraries such as `gorilla/csrf` or `justinas/nosurf`.
* Ensure that CSRF tokens are generated using cryptographically secure random number generators.
* Always use HTTP POST, PUT, DELETE (not GET) for state-changing operations.
* Implement proper token validation for all state-changing operations.

!!! bug error "Example Unsafe Usage"
    ```go
    func createUserHandler(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
            return
        }
        
        username := r.FormValue("username")
        password := r.FormValue("password")
        createUser(username, password)
        fmt.Fprintf(w, "User created successfully")
    }
    ```

!!! success check done "Example Recommended Usage"
    ```go
    import (
        "github.com/gorilla/csrf"
        "net/http"
    )
    
    func main() {
        CSRF := csrf.Protect(
            []byte("32-byte-long-auth-key"),
            csrf.Secure(true),
            csrf.HttpOnly(true),
        )
        
        http.HandleFunc("/create_user", createUserHandler)
        http.ListenAndServe(":8000", CSRF(http.DefaultServeMux))
    }
    
    func createUserHandler(w http.ResponseWriter, r *http.Request) {
        // CSRF validation happens automatically via the middleware
        if r.Method != http.MethodPost {
            http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
            return
        }
        
        username := r.FormValue("username")
        password := r.FormValue("password")
        
        // Process the user creation
        createUser(username, password)
        
        fmt.Fprintf(w, "User created successfully")
    }
    ```

!!! success check done "Example Recommended Usage"
    ```go
    import (
        "github.com/justinas/nosurf"
        "net/http"
        "html/template"
    )
    
    func main() {
        mux := http.NewServeMux()
        mux.HandleFunc("/create_user", createUserHandler)
        
        // Wrap the servemux with the nosurf middleware
        csrfHandler := nosurf.New(mux)
        
        // Configure cookie options
        csrfHandler.SetBaseCookie(http.Cookie{
            Path:     "/",
            HttpOnly: true,
            Secure:   true,
            SameSite: http.SameSiteStrictMode,
        })
        
        http.ListenAndServe(":8000", csrfHandler)
    }
    
    func createUserHandler(w http.ResponseWriter, r *http.Request) {
        // nosurf middleware automatically validates the token
        if r.Method != http.MethodPost {
            http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
            return
        }
        
        username := r.FormValue("username")
        password := r.FormValue("password")
        createUser(username, password)
        fmt.Fprintf(w, "User created successfully")
    }
    ```

When implementing CSRF protection in Go applications, remember to use secure random tokens, enforce proper token validation, and ensure that token validation happens before processing any state-changing operation.


## Server Side Request Forgery (SSRF)
By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers from accessing the URLs directly. The server can be used as a proxy to conduct port scanning of hosts in internal networks, use other URLs such as that can access documents on the system (using `file://`), or use other protocols such as `gopher://` or `tftp://`, which may provide greater control over the contents of requests[^65].

This is identified as a high severity attack because it allows an attacker to perform tasks which are usually prevented by the perimeter security devices such as firewalls. For example, an attacker would be able to appear to internal and external nodes as the vulnerable host and perform the following:

* Scan a network segment which is behind a firewall by analyzing responses received from the vulnerable host.
* Perform a service enumerate attack by enumerating through services that are running on a particular host.
* Bypass host based restrictions, policies or authentication mechanisms in place. 
* Query and attack internal hosts that are not normally accessible. 

In detail explanations and analysis on SSRF can be found at SSRF Bible Cheatsheet[^66].


### Prevention Techniques 

#### Avoid Using User Inputs in Backend Requests
Avoid accepting information used in internal requests such as following from the user:

* URLs used in back channel operations (backend calls made, where WSO2 product acts as the client).
* IP addresses used in internal or back channel operations. 
* Unvalidated and unrestricted system paths are used in internal file access.
* Unvalidated XML payloads that are passed to XML parsers without [proper security attributes set](#xml-external-entity-xxe). 


#### Perform Strict Error Handling
Display minimum information on the client side in the event of an error or something unexpected occurring. For example, if content type validation failed, provide a generic error message such as “Invalid Data Retrieved”. Also, ensure that the error message is the same when the request fails in the backend and if invalid data is retrieved. This will make it hard to distinguish between open and closed ports or services.


#### Perform Strict Response Handling
Validate responses received from the remote resource. If a certain content type is expected by the application, validate the received response on the server side before displaying it on the client's side or processing it for the client.


### Java Specific Recommendations 

#### Proper Usage of Java Security Manager
Java Security Manager should be enabled in any production deployment and any other deployment that requires additional security (such as environments used for security related testing). 

Steps relevant to enabling Java Security Manager is explained in "Enabling Java Security Manager" section of the "Administration Guide"[^67]. Security policy file should be used to only allow network level connections to trusted and pre-identified hosts or subnets, using SocketPermission[^68].

!!! example "Example Policy File"
    ```java
    grant signedBy "wso2carbon" {
        // Other policies 
        permission java.net.SocketPermission "internal.example.com:1234", "connect, accept";
    };
    ```


## Unvalidated Redirects and Forwards
Unvalidated redirects and forwards are possible when a web application accepts untrusted input that could cause the web application to redirect the request to a URL contained within untrusted input. By modifying untrusted URL input to a malicious site, an attacker may successfully launch a phishing scam and steal user credentials. Because the server name in the modified link is identical to the original site, phishing attempts may have a more trustworthy appearance. Unvalidated redirect and forward attacks can also be used to maliciously craft a URL that would pass the application’s access control check and then forward the attacker to privileged functions that they would normally not be able to access[^69].


### Prevention Techniques 
Absolute forward URLs or fragments of forward URLs should not be accepted by the end user during any operation. This is advised since an attacker can use a less restricted resource with a malicious forward, to circumvent URL-based security control in place and send requests to a restricted resource.

!!! danger error "Alert - Approval Required"
    If any component requires that, an absolute forward URL must be accepted from the end user by any means (as demonstrated in OWASP Cheat Sheet)[^70], the use-case, as well as controls in place to provide the required protection, must be reviewed and approved by the Security and Compliance Team, before proceeding with the release of such components.

Absolute redirect URLs should not be accepted by the end user during any operation, apart from administrative configurations. 

!!! danger error "Alert - Approval Required"
    If any component requires that, an absolute redirect URL must be accepted from the end user (not in administrative configuration), the use-case, as well as controls in place to provide the required protection, must be reviewed and approved by the Security and Compliance Team, before proceeding with the release of such component.

The general recommendation is to avoid accepting redirect or forward URL fragments (used to build absolute or relative redirect/forward URLs) from the end user. 

However, if there is such a requirement, it is necessary to follow language specific recommendations for validating the accepted URL fragment. 


### Java Specific Recommendations
If an absolute URL is accepted by the end user, it should be validated against a list of allowed redirect/ forward URLs. However, since this is the condition explained in the **Approval Required** blocks above, the Security and Compliance Team should be informed on the use case and approval is required. 

!!! bug error "Example Incorrect Usage"
    ```java
    response.sendRedirect(request.getParameter("url"));
    ```

!!! success check done "Example Correct Usage"
    ```java
    String url = request.getParameter("url");
    boolean allowed = SecurityUtil.validateRedirectUrl(listOfAllowedRedirectUrls, url);
    if(!allowed) {
        //Required logic to show the relevant error to the end-user
        return;
    }
    response.sendRedirect(request.getParameter("url"));
    ```

When a portion of the redirect or forward URL is expected from the user, it is a must to validate if the appended fragment contains only the expected type of value.  

!!! bug error "Example Incorrect Usage"
    ```java
    response.sendRedirect(Constant.BASE_URL + "/info/" + request.getParameter("index"));
    ```

!!! success check done "Example Correct Usage"
    ```java
    String index = request.getParameter("index");
    if(isInteger(index)) {
    response.sendRedirect(Constant.BASE_URL + "/info/" + index);
    } else {
        //Inform end-user about the error
    }
    ```


### Go Specific Recommendations
If an absolute URL is accepted by the end user, it should be validated against a list of allowed redirect/forward URLs. As mentioned in the section above, the Security and Compliance Team must approve such use cases.

!!! bug error "Example Incorrect Usage"
    ```go
    http.Redirect(w, r, r.URL.Query().Get("url"), http.StatusFound)
    ```

!!! success check done "Example Correct Usage"
    ```go
    url := r.URL.Query().Get("url")
    allowed := security.ValidateRedirectURL(allowedRedirectURLs, url)
    if !allowed {
        // Required logic to show the relevant error to the end-user
        http.Error(w, "Invalid redirect URL", http.StatusBadRequest)
        return
    }
    http.Redirect(w, r, url, http.StatusFound)
    ```

When a portion of the redirect or forward URL is expected from the user, you must validate that the appended fragment contains only the expected type of value.

!!! bug error "Example Incorrect Usage"
    ```go
    index := r.URL.Query().Get("index")
    http.Redirect(w, r, constant.BaseURL+"/info/"+index, http.StatusFound)
    ```

!!! success check done "Example Correct Usage"
    ```go
    index := r.URL.Query().Get("index")
    if _, err := strconv.Atoi(index); err == nil {
        http.Redirect(w, r, constant.BaseURL+"/info/"+index, http.StatusFound)
    } else {
        // Inform end-user about the error
        http.Error(w, "Invalid parameter", http.StatusBadRequest)
    }
    ```


## ClickJacking and Cross Frame Scripting
Clickjacking, also known as a "UI redress attack", is when an attacker uses multiple transparent or opaque layers to trick a user into clicking on a button or a link on another page when they were intending to click on the top level page. Thus, the attacker is "hijacking" clicks meant for their page and routing them to another page, most likely owned by another application, domain, or both[^71].

Cross-Frame Scripting (XFS) is an attack that combines malicious JavaScript with an iframe that loads a legitimate page in an effort to steal data from an unsuspecting user. This attack is usually only successful when combined with social engineering. An example would consist of an attacker convincing the user to navigate to a web page the attacker controls. The attacker's page then loads malicious JavaScript and an HTML iframe pointing to a legitimate site. Once the user enters credentials into the legitimate site within the iframe, the malicious JavaScript steals the keystrokes.


### Prevention Techniques 

#### X-Frame-Options
X-Frame-Options HTTP response header should be used to indicate that the browser should not allow rendering relevant responses in a `<frame>` or `<iframe>`. `X-Frame-Options: DENY` should be used in all cases, except in situations where the product itself needs to frame a page exposed elsewhere in the same product. In a situation where the product itself needs to frame a page exposed elsewhere in the same product, "X-Frame-Options: SAMEORIGIN" can be used. 


#### Content-Security-Policy
In addition to the non-standard X-Frame-Options header, the standard frame-ancestors directive can be used in a Content-Security-Policy HTTP response header to indicate whether or not a browser should be allowed to render a page in a `<frame>` or `<iframe>`. `Content-Security-Policy: frame-ancestors 'none'` should be used in all cases, except in situations where the product itself needs to frame a page exposed elsewhere in the same product. In a situation where the product itself needs to frame a page exposed elsewhere in the same product, `Content-Security-Policy: frame-ancestors 'self'` can be used. 

!!! danger error "Alert - Approval Required"
    If any component requires that, framing of the page should be allowed globally, the use-case, as well as controls in place to provide the required protection, must be reviewed and approved by the Security and Compliance Team, before proceeding with the release of such component.


### Java Specific Recommendations 

#### X-Frame-Options
`org.apache.catalina.filters.HttpHeaderSecurityFilter` Servlet Filter should be used to add X-Frame-Options header to the HTTP response. 

!!! tip hint important "WSO2 Document Reference"
    Further information on required changes and recommended configuration for WSO2 products as well as production deployments are available at [Engineering Guidelines - Security Related HTTP Headers](../security-related-http-headers.md).


### Go Specific Recommendations

In Go applications, security headers should be added to all HTTP responses. This can be achieved by using middleware functions that intercept and modify responses before they are sent to the client.

!!! success check done "Example Recommended Usage"
    ```go
    // Example of adding security headers using net/http middleware
    func securityHeadersMiddleware(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            w.Header().Set("X-Frame-Options", "DENY")
            w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
            next.ServeHTTP(w, r)
        })
    }

    // Usage with http.ServeMux
    func main() {
        mux := http.NewServeMux()
        mux.HandleFunc("/", homeHandler)
        securedMux := securityHeadersMiddleware(mux)
        http.ListenAndServe(":8080", securedMux)
    }
    ```


## Cross-Origin Resource Sharing
A wildcard same-origin policy is appropriate when a page or API response is considered completely public content and it is intended to be accessible to everyone, including any code on any site. 

`Access-Control-Allow-Origin: *` should not be used in WSO2 products. If such an option should be available, a user or an admin should have a way to configure between using wildcard and using domain restriction.

!!! danger error "Alert - Approval Required"
    If any component requires that Access-Control-Allow-Origin should be used with wildcard and user/admin is not given the option of switching to domain level restriction, the use-case, as well as controls in place to provide required protection, must be reviewed and approved by the Security and Compliance Team, before proceeding with the release of such component.


## Security Related HTTP Headers
There are HTTP response headers that can be used to configure the security controls enforced by browsers.
WSO2 Document Reference: Further information on required changes and recommended configuration for WSO2 products as well as production deployments are available at [Engineering Guidelines - Security Related HTTP Headers](../security-related-http-headers.md).


## Securing Cookies
Sensitive cookies such as JSESSIONID should be secured to avoid stealing the cookies from an insecure network or with the use of an XSS vulnerability of the application.


### Avoiding sending of cookies over insecure (unencrypted) networks
By setting the "secure" attribute of the cookie, it is possible to instruct the browser not to send the cookie over insecure networks (not to send the cookie unless HTTPS is used).

!!! danger error "Alert - Approval Required"
    If any component requires that, "secure" attribute of the cookie should not be set for a sensitive cookie, the use-case, as well as controls in place to provide required protection, must be reviewed and approved by the Security and Compliance Team, before proceeding with the release of such component.

!!! example "Example of Setting Secure Flag with Java"
    ```java
    cookie.setSecure(true);
    ```

!!! example "Example of Setting Secure Flag with Go"
    ```go
    cookie := &http.Cookie{
        Name:     "sessionID",
        Value:    sessionToken,
        Secure:   true,
    }
    http.SetCookie(w, cookie)
    ```

### Avoiding cookies being read by JavaScript and other client side scripts
If an XSS vulnerability is present in the web application a malicious JavaScript would be able to read sensitive information stored in cookies and communicate those to an external party.

An attacker could leverage this pattern to use an XSS vulnerability to read the session cookie from the victim’s browser and conduct a session hijacking attack.

To prevent JavaScripts and other client-side scripts from accessing cookie values, "HttpOnly" attribute should be set on the cookie.

!!! danger error "Alert - Approval Required"
    If any component requires that, "HttpOnly" attribute of the cookie should not be set for a sensitive cookie, the use-case, as well as controls in place to provide required protection, must be reviewed and approved by the Security and Compliance Team, before proceeding with the release of such component.

!!! example "Example of Setting HttpOnly Flag with Java"
    ```java
    cookie.setHttpOnly(true);
    ```

!!! example "Example of Setting HttpOnly Flag with Go"
    ```go
    cookie := &http.Cookie{
        Name:     "sessionID",
        Value:    sessionToken,
        HttpOnly: true,
    }
    http.SetCookie(w, cookie)
    ```

### Summary of Recommendations
All cookies containing sensitive information should:

* Include the `secure` attribute
* Include the `HttpOnly` attribute 
* Include the `path` attribute and the `path` attribute should contain accurate context information
* Not include the `expires` attribute (cookie should be a session cookie)


## Random Number Generation
When an undesirably low amount of entropy is available, Pseudo Random Number Generators are susceptible to suffering from insufficient entropy when they are initialized, because entropy data may not be available to them yet[^73]. This will leave patterns or clusters of values that are more likely to occur than others[^74].


### Java Specific Recommendations
Avoid usage of java.util.Random class for security sensitive operations and use `java.security.SecureRandom`. 

* Periodically throw away the existing java.security.SecureRandom instance and create a new one. This will generate a new instance with a new seed.
* Periodically add new random material to the PRNG seed by making a call to java.security.SecureRandom.setSeed(java.security.SecureRandom.generateSeed(int)).
* SecureRandom.getInstanceStrong() introduced with Java 8  should not be used in web applications, since application gets blocked until PRNG could collect the required amount of entropy. This could affect Docker containers badly, since when instance spawning happens, entropy gathering will take significant amount of time . 


!!! bug error "Example Incorrect Usage"
    ```java
    int randomPasswordPrefix = new Random().nextInt(9999);
    ```

!!! success check done "Example Correct Usage"
    ```java
    //… 
    int randomPasswordPrefix; 
    try { 
        SecureRandom secureRandom = SecurityUtil.getSecureRandom();
        randomPasswordPrefix = secureRandom.nextInt(9999); 
    } catch (NoSuchAlgorithmException e) { 
        //Exception handling
    }
    //… 

    private class SecurityUtil {
    //…… 

        private static SecureRandom secureRandom = null;
        private static int secureRandomUsageCount = 0;
        private static final int SECURE_RANDOM_ROTATION_LIMIT = 1000;


        private static SecureRandom getSecureRandom() {
            if(secureRandomUsageCount > SECURE_RANDOM_ROTATION_LIMIT) {
                synchronized (SecurityUtil.class) {
                    if(secureRandomUsageCount > SECURE_RANDOM_ROTATION_LIMIT) {
                    secureRandom = null;
                    }
                }
            }
            if(secureRandom == null) {
                synchronized (SecurityUtil.class) {
                    if(secureRandom == null) {
                    secureRandom = SecureRandom.getInstance("SHA1PRNG");
                    }
                }
            }
            secureRandomUsageCount++;
            return secureRandom;
        }
    }
    ```

### Go Specific Recommendations
Avoid usage of `math/rand` package for security sensitive operations and use `crypto/rand` instead.

* Always properly handle errors returned by `crypto/rand` functions as they indicate potential entropy issues.
* For generating random integers within ranges, use appropriate conversion methods that preserve randomness (avoid modulo bias).
* Consider using established libraries like `golang.org/x/crypto` for higher-level cryptographic operations that require randomness.
* In containerized environments, ensure proper entropy sources are available to the Go application.

!!! bug error "Example Incorrect Usage"
    ```go
    import (
        "math/rand"
        "time"
    )
    
    func generateToken() string {
        rand.Seed(time.Now().UnixNano())
        randomValue := rand.Intn(9999)
        // ...
    }
    ```

!!! success check done "Example Correct Usage"
    ```go
    import (
        "crypto/rand"
        "encoding/binary"
        "fmt"
    )
    
    func generateToken() (string, error) {
        // Create a buffer for 4 bytes (for a uint32)
        b := make([]byte, 4)
        
        // Read random bytes from crypto/rand
        _, err := rand.Read(b)
        if err != nil {
            return "", fmt.Errorf("failed to generate random number: %v", err)
        }
        
        // Convert bytes to uint32 and limit to 0-9999 range without modulo bias
        randomValue := binary.BigEndian.Uint32(b) % 10000
        
        // ... further processing
        
        return result, nil
    }
    ```

## Unrestricted File Upload
Unrestricted file upload vulnerabilities[^75] occur when a web server or application permits users to upload files to the filesystem without adequately validating critical file attributes such as name, type, content, or size. Failure to enforce proper validation mechanisms[^76] can lead to severe security risks, including unauthorized file execution and system compromise.

### Potential Risks:
* Overwriting Critical Files:
Attackers may exploit insufficient validation by uploading files with the same name as existing critical files, potentially overwriting them and disrupting application functionality or compromising system integrity.

* Arbitrary File Placement:
If the server is also susceptible to directory traversal attacks, malicious users can upload files to unintended directories. This could lead to the placement of malicious scripts or executables in sensitive areas of the filesystem.

* Backdoor Installation:
In scenarios where server-side code execution is possible, attackers could upload malicious scripts (e.g., web shells) to establish persistent access or backdoors, thereby gaining unauthorized control over the server.

### Java Specific Recommendations

* File Type Validation:
Allow only specific file types and perform server-side validation using whitelisting techniques. Avoid relying solely on client-side checks.

* Filename Sanitization:
Normalize and sanitize filenames to prevent overwriting critical files. Implement unique naming conventions for uploaded files.

* Content Inspection:
Inspect file content to ensure it matches the expected file type and format. Reject files that fail validation checks.

* Directory Restrictions:
Store uploaded files outside the webroot whenever possible. Apply strict access controls to prevent unauthorized file execution.

* Size Limitation:
Enforce file size limits to prevent denial-of-service (DoS) conditions due to large file uploads.

* Access Controls and Permissions:
Assign the minimum required permissions to uploaded files and ensure that executable permissions are not granted unless explicitly necessary.

* Comprehensive Logging and Monitoring:
Log all file upload activities and monitor them for signs of suspicious behavior.

!!! success check done "Example Correct Usage"
    ```java
    private static final String[] ALLOWED_FILE_EXTENSIONS = new String[]{".xml"};

    protected void checkServiceFileExtensionValidity(String fileExtension,String[] allowedExtensions)
        throws FileUploadException {
        boolean isExtensionValid = false;
        StringBuffer allowedExtensionsStr = new StringBuffer();
        for (String allowedExtension : allowedExtensions) {
            allowedExtensionsStr.append(allowedExtension).append(",");
            if (fileExtension.endsWith(allowedExtension)) {
                isExtensionValid = true;
                break;
            }
        }
        if (!isExtensionValid) {
            throw new FileUploadException(" Illegal file type." + " Allowed file extensions are " + allowedExtensionsStr);
        }
    }
    ```

!!! success check done "Example Correct Usage"
    ```java
    public static boolean checkMetaData(File f, String getContentType) {
        try (InputStream is = new FileInputStream(f)) {
            ContentHandler contenthandler = new BodyContentHandler();
            Metadata metadata = new Metadata();
            metadata.set(Metadata.RESOURCE_NAME_KEY, f.getName());
            Parser parser = new AutoDetectParser();
            try {
                parser.parse(is, contenthandler, metadata, new ParseContext());
            } catch (SAXException | TikaException e) {
                return false;}
            if (metadata.get(Metadata.CONTENT_TYPE).equalsIgnoreCase(getContentType)) {
                return true;
            } else {
                return false;
            }
        }
    }
    ```

### Go Specific Recommendations

* File Type Validation:
    Allow only specific file types and perform server-side validation using whitelisting techniques. Avoid relying solely on client-side checks.
    Go's `http.DetectContentType` function can be used to verify the MIME type of uploaded files based on the extension and content.

* Filename Sanitization:
    Normalize and sanitize filenames to prevent overwriting critical files. Implement unique naming conventions for uploaded files.

* Secure Filesystem Operations:
    Use Go's path cleaning functions like `filepath.Clean` to prevent path traversal attacks and ensure files are stored in the intended locations.

* Content Inspection:
    Inspect file content to ensure it matches the expected file type and format. Reject files that fail validation checks.

* Directory Restrictions:
    Store uploaded files outside the webroot whenever possible. Apply strict access controls to prevent unauthorized file execution.

* Size Limitation:
    Enforce file size limits to prevent denial-of-service (DoS) conditions due to large file uploads.

* Access Controls and Permissions:
    Assign the minimum required permissions to uploaded files and ensure that executable permissions are not granted unless explicitly necessary.

* Comprehensive Logging and Monitoring:
    Log all file upload activities and monitor them for signs of suspicious behavior.

!!! success check done "Example Correct Usage"
    ```go
    func validateFileExtension(filename string) error {
        // Define allowed extensions
        allowedExts := map[string]bool{".jpg": true, ".jpeg": true, ".png": true, ".pdf": true}
        
        ext := strings.ToLower(filepath.Ext(filename))
        if !allowedExts[ext] {
            return fmt.Errorf("unsupported file extension: %s", ext)
        }
        
        return nil
    }
    
    func uploadHandler(w http.ResponseWriter, r *http.Request) {
        file, header, err := r.FormFile("file")
        if err != nil {
            http.Error(w, "Failed to get file from form", http.StatusBadRequest)
            return
        }
        defer file.Close()
        
        // Validate file extension
        if err := validateFileExtension(header.Filename); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
    }
    ```

!!! success check done "Example Correct Usage"
    ```go
    func validateFileContent(file multipart.File, expectedType string) error {
        // Save to a buffer to examine content
        buffer := make([]byte, 512)
        _, err := file.Read(buffer)
        if err != nil {
            return err
        }
        
        // Seek back to the beginning of the file
        if _, err = file.Seek(0, io.SeekStart); err != nil {
            return err
        }
        
        // Detect content type from file content
        contentType := http.DetectContentType(buffer)
        
        // Validate that content type matches expected
        if !strings.HasPrefix(contentType, expectedType) {
            return fmt.Errorf("invalid file type: got %s, expected %s", contentType, expectedType)
        }
        
        return nil
    }
    
    func uploadPdfHandler(w http.ResponseWriter, r *http.Request) {
        file, header, err := r.FormFile("pdfFile")
        if err != nil {
            http.Error(w, "Failed to get file from form", http.StatusBadRequest)
            return
        }
        defer file.Close()
        
        // Validate content type
        if err := validateFileContent(file, "application/pdf"); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
    }
    ```


## References
[^1]: [https://www.owasp.org/index.php/SQL_Injection](https://www.owasp.org/index.php/SQL_Injection)
[^2]: [http://php.net/manual/en/book.pdo.php](http://php.net/manual/en/book.pdo.php)
[^3]: [https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)
[^4]: [http://php.net/manual/en/book.mysqli.php](http://php.net/manual/en/book.mysqli.php)
[^5]: [https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)
[^6]: [http://php.net/manual/en/security.database.sql-injection.php](http://php.net/manual/en/security.database.sql-injection.php)
[^7]: [https://www.owasp.org/index.php/LDAP_injection](https://www.owasp.org/index.php/LDAP_injection)
[^8]: [http://file.scirp.org/pdf/WSN20090400001_37847843.pdf](http://file.scirp.org/pdf/WSN20090400001_37847843.pdf)
[^9]: [https://blogs.oracle.com/shankar/entry/what_is_ldap_injection](https://blogs.oracle.com/shankar/entry/what_is_ldap_injection)
[^10]: [https://www.owasp.org/index.php/Command_Injection](https://www.owasp.org/index.php/Command_Injection)
[^11]: [http://php.net/manual/en/function.exec.php](http://php.net/manual/en/function.exec.php)
[^12]: [http://php.net/manual/en/function.exec.php](http://php.net/manual/en/function.exec.php)
[^13]: [https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)](https://www.owasp.org/index.php/Cross-site_Scripting_(XSS))
[^14]: [https://www.w3.org/TR/html4/charset.html#h-5.3.2](https://www.w3.org/TR/html4/charset.html#h-5.3.2)
[^15]: [https://github.com/OWASP/owasp-java-encoder](https://github.com/OWASP/owasp-java-encoder)
[^16]: [https://github.com/owasp/java-html-sanitizer](https://github.com/owasp/java-html-sanitizer)
[^17]: [https://github.com/OWASP/java-html-sanitizer/blob/release-20170329.1/src/main/java/org/owasp/html/Sanitizers.java#L58](https://github.com/OWASP/java-html-sanitizer/blob/release-20170329.1/src/main/java/org/owasp/html/Sanitizers.java#L58)
[^18]: [http://php.net/manual/en/function.htmlspecialchars.php](http://php.net/manual/en/function.htmlspecialchars.php)
[^19]: [http://htmlpurifier.org/docs](http://htmlpurifier.org/docs)
[^20]: [https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing)
[^21]: [http://php.net/libxml_disable_entity_loader](http://php.net/libxml_disable_entity_loader)
[^22]: [http://phpsecurity.readthedocs.io/en/latest/Injection-Attacks.html#xml-external-entity-injection](http://phpsecurity.readthedocs.io/en/latest/Injection-Attacks.html#xml-external-entity-injection)
[^23]: [http://phpsecurity.readthedocs.io/en/latest/Injection-Attacks.html#defenses-against-xml-external-entity-injection](http://phpsecurity.readthedocs.io/en/latest/Injection-Attacks.html#defenses-against-xml-external-entity-injection)
[^24]: [https://cwe.mitre.org/data/definitions/113.html](https://cwe.mitre.org/data/definitions/113.html)
[^25]: [https://www.owasp.org/index.php/HTTP_Response_Splitting](https://www.owasp.org/index.php/HTTP_Response_Splitting)
[^26]: [https://svn.apache.org/viewvc/tomcat/archive/tc6.0.x/tags/TOMCAT_6_0_0/java/org/apache/coyote/http11/InternalOutputBuffer.java?view=markup#l715](https://svn.apache.org/viewvc/tomcat/archive/tc6.0.x/tags/TOMCAT_6_0_0/java/org/apache/coyote/http11/InternalOutputBuffer.java?view=markup#l715)
[^27]: [http://svn.apache.org/viewvc/tomcat/tc7.0.x/tags/TOMCAT_7_0_59/java/org/apache/coyote/http11/AbstractOutputBuffer.java?view=markup#l516](http://svn.apache.org/viewvc/tomcat/tc7.0.x/tags/TOMCAT_7_0_59/java/org/apache/coyote/http11/AbstractOutputBuffer.java?view=markup#l516)
[^28]: [https://svn.apache.org/viewvc/tomcat/archive/tc6.0.x/tags/TOMCAT_6_0_0/java/org/apache/coyote/http11/InternalOutputBuffer.java?view=markup#l715](https://svn.apache.org/viewvc/tomcat/archive/tc6.0.x/tags/TOMCAT_6_0_0/java/org/apache/coyote/http11/InternalOutputBuffer.java?view=markup#l715)
[^29]: [http://svn.apache.org/viewvc/tomcat/tc7.0.x/tags/TOMCAT_7_0_59/java/org/apache/coyote/http11/AbstractOutputBuffer.java?view=markup#l516](http://svn.apache.org/viewvc/tomcat/tc7.0.x/tags/TOMCAT_7_0_59/java/org/apache/coyote/http11/AbstractOutputBuffer.java?view=markup#l516)
[^30]: [https://github.com/malithie/carbon4-kernel/blob/4.4.x/core/org.wso2.carbon.ui/src/main/java/org/wso2/carbon/ui/filters/CRLFPreventionFilter.java](https://github.com/malithie/carbon4-kernel/blob/4.4.x/core/org.wso2.carbon.ui/src/main/java/org/wso2/carbon/ui/filters/CRLFPreventionFilter.java)
[^31]: [https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0201](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0201)
[^32]: [https://docs.wso2.com/display/ADMIN44x/Configuring+Log4j+Properties](https://docs.wso2.com/display/ADMIN44x/Configuring+Log4j+Properties)
[^33]: [https://www.owasp.org/index.php/Session_hijacking_attack](https://www.owasp.org/index.php/Session_hijacking_attack)
[^34]: [https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet](https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet)
[^35]: [https://moxie.org/software/sslstrip/](https://moxie.org/software/sslstrip/)
[^36]: [https://developer.mozilla.org/en-US/docs/Web/HTTP/Public_Key_Pinning](https://developer.mozilla.org/en-US/docs/Web/HTTP/Public_Key_Pinning)
[^37]: [https://www.roe.ch/SSLsplit](https://www.roe.ch/SSLsplit) 
[^38]: [https://www.owasp.org/index.php/Session_fixation](https://www.owasp.org/index.php/Session_fixation)
[^39]: [https://www.owasp.org/index.php/Session_Prediction](https://www.owasp.org/index.php/Session_Prediction)
[^40]: [https://www.owasp.org/index.php/Insufficient_Session-ID_Length](https://www.owasp.org/index.php/Insufficient_Session-ID_Length)
[^41]: [http://tomcat.apache.org/tomcat-7.0-doc/config/sessionidgenerator.html](http://tomcat.apache.org/tomcat-7.0-doc/config/sessionidgenerator.html)
[^42]: [https://www.owasp.org/index.php/PHP_Configuration_Cheat_Sheet](https://www.owasp.org/index.php/PHP_Configuration_Cheat_Sheet)
[^43]: [https://cwe.mitre.org/data/definitions/244.html](https://cwe.mitre.org/data/definitions/244.html)
[^44]: [http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#PBEEx](http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#PBEEx)
[^45]: [https://www.owasp.org/index.php/Testing_for_Vulnerable_Remember_Password_(OTG-AUTHN-005)](https://www.owasp.org/index.php/Testing_for_Vulnerable_Remember_Password_(OTG-AUTHN-005))
[^46]: [http://stackoverflow.com/questions/33083397/filtering-upwards-path-traversal-in-java-or-scala](http://stackoverflow.com/questions/33083397/filtering-upwards-path-traversal-in-java-or-scala)
[^47]: [https://www.owasp.org/index.php/Path_Traversal](https://www.owasp.org/index.php/Path_Traversal)
[^48]: [https://docs.oracle.com/javase/8/docs/api/java/nio/file/Path.html#normalize--](https://docs.oracle.com/javase/8/docs/api/java/nio/file/Path.html#normalize--)
[^49]: [http://stackoverflow.com/questions/33083397/filtering-upwards-path-traversal-in-java-or-scala](http://stackoverflow.com/questions/33083397/filtering-upwards-path-traversal-in-java-or-scala)
[^50]: [http://stackoverflow.com/questions/4205141/preventing-directory-traversal-in-php-but-allowing-paths](http://stackoverflow.com/questions/4205141/preventing-directory-traversal-in-php-but-allowing-paths)
[^51]: [https://blog.detectify.com/2016/07/13/owasp-top-10-missing-function-level-access-control-7/](https://blog.detectify.com/2016/07/13/owasp-top-10-missing-function-level-access-control-7/)
[^52]: [https://blog.detectify.com/2016/06/17/owasp-top-10-security-misconfiguration-5/](https://blog.detectify.com/2016/06/17/owasp-top-10-security-misconfiguration-5/)
[^53]: [https://resources.infosecinstitute.com/10-steps-avoid-insecure-deserialization/#gref](https://resources.infosecinstitute.com/10-steps-avoid-insecure-deserialization/#gref)
[^54]: [https://www.owasp.org/index.php/Deserialization_Cheat_Sheet](https://www.owasp.org/index.php/Deserialization_Cheat_Sheet)
[^55]: [http://php.net/manual/en/function.unserialize.php](http://php.net/manual/en/function.unserialize.php)
[^56]: [https://github.com/ikkisoft/SerialKiller](https://github.com/ikkisoft/SerialKiller)
[^57]: [https://nvd.nist.gov/](https://nvd.nist.gov/)
[^58]: [https://www.exploit-db.com/](https://www.exploit-db.com/)
[^59]: [https://www.veracode.com/blog/security-news/owasp-top-10-updated-2017-here%E2%80%99s-what-you-need-know](https://www.veracode.com/blog/security-news/owasp-top-10-updated-2017-here%E2%80%99s-what-you-need-know)
[^60]: [https://www.owasp.org/index.php/Top_10-2017_A10-Insufficient_Logging%26Monitoring](https://www.owasp.org/index.php/Top_10-2017_A10-Insufficient_Logging%26Monitoring)
[^61]: [https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF))
[^62]: [https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet)
[^63]: [http://www.corej2eepatterns.com/Design/PresoDesign.htm](http://www.corej2eepatterns.com/Design/PresoDesign.htm)
[^64]: [https://www.owasp.org/index.php/Category:OWASP_CSRFGuard_Project](https://www.owasp.org/index.php/Category:OWASP_CSRFGuard_Project)
[^65]: [http://cwe.mitre.org/data/definitions/918.html](http://cwe.mitre.org/data/definitions/918.html)
[^66]: [https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/)
[^67]: [https://docs.wso2.com/display/ADMIN44x/Enabling+Java+Security+Manager](https://docs.wso2.com/display/ADMIN44x/Enabling+Java+Security+Manager)
[^68]: [http://docs.oracle.com/javase/7/docs/technotes/guides/security/permissions.html#SocketPermission](http://docs.oracle.com/javase/7/docs/technotes/guides/security/permissions.html#SocketPermission)
[^69]: [https://www.owasp.org/index.php/Unvalidated_Redirects_and_Forwards_Cheat_Sheet](https://www.owasp.org/index.php/Unvalidated_Redirects_and_Forwards_Cheat_Sheet)
[^70]: [https://www.owasp.org/index.php/Unvalidated_Redirects_and_Forwards_Cheat_Sheet#Dangerous_Forward_Example](https://www.owasp.org/index.php/Unvalidated_Redirects_and_Forwards_Cheat_Sheet#Dangerous_Forward_Example)
[^71]: [https://www.owasp.org/index.php/Clickjacking](https://www.owasp.org/index.php/Clickjacking)
[^72]: [https://www.owasp.org/index.php/Cross_Frame_Scripting](https://www.owasp.org/index.php/Cross_Frame_Scripting)
[^73]: [https://www.owasp.org/index.php/Insufficient_Entropy](https://www.owasp.org/index.php/Insufficient_Entropy)
[^74]: [https://cwe.mitre.org/data/definitions/331.html](https://cwe.mitre.org/data/definitions/331.html)
[^75]: [https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
[^76]: [https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)

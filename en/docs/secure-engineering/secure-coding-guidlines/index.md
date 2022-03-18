# WSO2 Secure Coding Guidelines

<p class="doc-info">Published: 22nd October 2018</p>
<p class="doc-info">Version: 2.1</p>
---

## 2. OWASP Top 10 - 2017 Prevention

### 2.1 A1 - Injection

#### 2.1.1 SQL Injection
A SQL injection attack consists of insertion or **injection** of a SQL query via the input data from the client to the application. A successful SQL injection exploit can read sensitive data from the database, modify database data (Insert/Update/Delete), execute administration operations on the database (such as shutdown the DBMS), recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system. SQL injection attacks are a type of injection attack, in which SQL commands are injected into data-plane input in order to effect the execution of predefined SQL commands [1].


###### 2.1.1.1 Prevention Techniques
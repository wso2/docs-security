---
title: General Recommendations for React Secure Coding
category: security-guidelines
published: January 26, 2021
version: 2.0
---

# General Recommendations for React Secure Coding
<p class="doc-info">Version: 1.0</p>
___

## Introduction
This document summarizes the [WSO2 Secure Coding Guidelines](introduction.md) that should be followed by WSO2 engineers while developing **React** based WSO2 products, as well as applications used within the organization. 

The purpose of this document is to increase security awareness and make sure the products and the applications developed by WSO2 are inherently secure, by making sure security best practices are followed throughout the Software Development Life Cycle. 


## Data Binding
Untrusted user inputs must be handled by the default data binding of React curly brackets. As this binding feature of React can neutralize the HTML tags by default. So malicious user inputs such as the XSS script will not be executed on the client side[^1].

!!! success check done "Example Correct Usage"
  ```js
  function Wso2(){
    Const input="hello <img src=x onerror=alert(0)>";
    Return (<dev>{input}</dev>);}
  ```

The above-mentioned protection only occurs when rendering user input data as text content. Likewise, this security measurement could be bypassed when rendering an untrusted user input as an HTML attribute.

!!! bug error "Example Incorrect Usage"
  ```js
  function wso2(){
    Const input="data:text/html,<script>alert(1)</script>";
    Return (<iframe src={input}></iframe>);
  }
  ```

To avoid these unwanted malicious script execution, all untrusted user input data must be sanitized before they are rendered as HTML attributes.

!!! success check done "Example Correct Usage"
  ```js
  Import purify from “dompurify”;

  function wso2(){
    Const input="data:text/html,<script>alert(1)</script>";
    Return (<iframe src="DOMPurify.sanitize(input)"></iframe>);
  }
  ```


## URL Handling
URLs can also contain dynamic scripts via `javascript protocol urls`. It is highly recommended to validate the URLs before using them. When validating a URL checked whether that link has HTTP or HTTPS components to avoid Javascript-based script injection[^2].

!!! bug error "Example Incorrect Usage"
  ```js
  // Classic XSS via anchor tag href attribute.
  <a href="javascript: alert(1)">Click me!</a>
  ```

!!! success check done "Example Correct Usage"
  ```js
  isSafe(dangerousURL, text) {
    const url = URL(dangerousURL, {})
    if (url.protocol === 'http:') return true
    if (url.protocol === 'https:') return true    

    return false
  }
  ```


## HTML Rendering
It is possible to insert HTML tags directly into rendered DOM nodes using the `dangerouslySetInnerHTML` attribute of the DOM element. If required, use this attribute in the wso2 product and with must be contained properly with sanitization[^3].

!!! bug error "Example Incorrect Usage"
  ```js
  function wso2(){
    Const input="hello <img src=x onerror=alert(0)>";
    Return (<dev dangerouslySetInnerHTML={{_html:input}}></dev>);
  }
  ```

To sanitize the input, you can use a sanitization library like `DOMPurify`[^4] on any values before placing them into `dangerouslySetInnerHTML`.

!!! success check done "Example Correct Usage"
  ```js
  import purify from "dompurify";

  function wso2(){
    Const input="hello <img src=x onerror=alert(0)>";
    Return (<dev dangerouslySetInnerHTML={{_html:DOMPurify.sanitize(input)}}></dev>);
  }
  ```


## Direct DOM Access
Instead of directly accessing DOM nodes to insert content, it's strongly advised to use proper sanitization when `findDomNode()` and `createRef` are used to access rendered DOM elements for injecting content via innerHTML and similar properties."

!!! bug error "Example Incorrect Usage"
  ```js
  class App extends React.Component {   
    changeMe(){
      let input = "<img src=x onerror=alert(0)>";
      ReactDOM.findDOMNode(document.getElementById("wso2")).innerHTML= input;
    }

    render() {
      return (
        <dev>
          <button onClick={this.changeMe}>change me</button><br></br>
          <dev id="wso2">Welcome to XSS Test</dev>
        </dev>
      )
    }
  }
  ```

!!! success check done "Example Correct Usage"
  ```js
  class App extends React.Component {   
    changeMe(){
      let input = "<img src=x onerror=alert(0)>";  ReactDOM.findDOMNode(document.getElementById("wso2")).innerHTML=DOMPurify.sanitize(input);
    }

    render()
    {
      return (
        <dev>
          <button onClick={this.changeMe}>change me</button><br></br>
          <dev id="wso2">Welcome to XSS Test</dev>
        </dev>
      )
    }
  }
  ```

!!! Important
    **All user inputs should be validated or sanitized before rendering on the client side.**

## Markdown
It is highly recommended to use the `react-markdown` [^7] NPM package when working with Markdown elements. It natively provides protection against client-side attacks such as cross-site scripting.

!!! Important
    If you want to use a plugin along with the react-markdown package, it is essential to follow the necessary precautionary actions based on the instructions provided by the plugin. This is crucial because the plugin you use may handle HTML and Script elements in an insecure manner.

!!! Note
    Plugins such as `remarkPlugins` and `rehypePlugins` do not inherently protect against client-side scripting and injection attacks. Therefore, if you use these plugins, it is crucial to also use rehype-sanitize [^8], which allows you to define your own schema of what is and isn’t allowed.


## NPM Packages
Before onboarding or using any NPM packages, it is essential to complete the following checklists:

* **Avoid insecure handling of HTML and Script elements:** It is recommended to avoid using NPM packages that default to handling HTML and Script elements in an insecure manner. This information is typically available in the NPM package's documentation, as illustrated in the rehype [^9] example.
* **Implement sanitization mechanisms:** It is necessary to use a sanitization mechanism [^4] [^8] alongside NPM packages if they handle HTML and Script elements in an unsafe manner by default.
* **Check for vulnerabilities:** Ensure that the packages do not contain any known vulnerabilities. Tools like npm audit[^10] can be used to identify vulnerabilities in third-party components.
* **Initiate the dependency onboarding process:** This step applies specifically to new NPM packages that you plan to incorporate into your project.

## Server Side Rendering

### JSON
Sometimes, when rendering the initial state on the server side, there's a risk in directly generating a `document` variable from a JSON string. This approach is risky because `JSON.stringify()` will convert any data into a string format, assuming it's valid JSON, which can then be re-rendered on the page. This could potentially include fields edited by untrusted users, allowing them to inject malicious scripts.

!!! bug error "Example Incorrect Usage"
  ```js
  <script>
    window._PRELOADED_STATE_ = ${JSON.stringify(untrusted_JSON_data)}
  </script>
  ```

To fix this vulnerability when serializing the state on the server to be sent to the client, it must be serialized in a way that sanitizes the HTML tags. It is highly recommended to use a library like `serialize-javascript`[^5] to avoid unnecessary HTML tag renders[^6].

!!! success check done "Example Correct Usage"
  ```js
  import purify from "dompurify";

  <script>
    window._PRELOADED_STATE_ = ${serialize(untrusted_JSON_data,{isJSON:true})}
  </script>
  ```

## References
[^1]: [https://pragmaticwebsecurity.com/articles/spasecurity/react-xss-part1.html](https://pragmaticwebsecurity.com/articles/spasecurity/react-xss-part1.html)
[^2]: [https://medium.com/javascript-security/avoiding-xss-in-react-is-still-hard-d2b5c7ad9412](https://medium.com/javascript-security/avoiding-xss-in-react-is-still-hard-d2b5c7ad9412)
[^3]: [https://pragmaticwebsecurity.com/articles/spasecurity/react-xss-part2.html](https://pragmaticwebsecurity.com/articles/spasecurity/react-xss-part2.html)
[^4]: [https://github.com/cure53/DOMPurify](https://github.com/cure53/DOMPurify)
[^5]: [https://www.npmjs.com/package/serialize-javascript](https://www.npmjs.com/package/serialize-javascript)
[^6]: [https://www.veracode.com/blog/secure-development/3-security-pitfalls-every-react-developer-should-know](https://www.veracode.com/blog/secure-development/3-security-pitfalls-every-react-developer-should-know)
[^7]: [https://www.npmjs.com/package/react-markdown#security](https://www.npmjs.com/package/react-markdown#security)
[^8]: [https://github.com/rehypejs/rehype-sanitize](https://github.com/rehypejs/rehype-sanitize)
[^9]: [https://www.npmjs.com/package/rehype#security](https://www.npmjs.com/package/rehype#security)
[^10]: [https://docs.npmjs.com/cli/v6/commands/npm-audit](https://docs.npmjs.com/cli/v6/commands/npm-audit)

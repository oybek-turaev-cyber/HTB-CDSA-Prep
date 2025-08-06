## Lab Title: Bike
- Date: 2025-08-06
- Duration: ~30 minutes

### Platform: HTB – Starting Point > Tier 1

### 1. Scenario Summary
- Server Side Template Injection

### 2. Findings
- Nmap              >> Enumeration
    - `nmap $ip -Pn -T4 --top-ports 10000` >> 22,80 >> open ports
    - `nmap $ip -sV -T4 -p T:80` >> Node.js (Express middleware)

- Wappalyzer        >> Technology Profiler >> Identifies used technologies on Websites
    - Can be a browser extensionMore
    - Found that for the `http://$ip` >> Web Servers & Web Framework `Express`
    - Express is web application & API building framework for Node.js

- Server Side Template Injection
    - When certain placeholders in websites accepts user inputs like `{{6*6}} and reveals some dir paths/ remote code execution
    - Template engines are then used by attackers to run some malicious codes
    - These placeholders where we enter email or name info >> are called templates >> there are template engines to process those later on server side

    - There are different template engines for Node.js >> `EJS, Pug, Mustache, Handlebars, Nunjacks`

    - In this website >> the error reveals that `Parser.parseError (/root/Backend/node_modules/handlebars/dist/cjs/handlebars/compiler/parser.js:268:19)"`
        - For parsing, `Handlebars`, Template Engine is used

- Burp Suite        >> Web Exploitation Tool Set
    - `Decoder` Tab used to encode text

- Exploit
    - Need to craft a payload for Handlebars (Node.js)
    - Payload: key part: `{{this.push "return process.mainModule.require('child_process').execSync('whoami');"}}` full version on google
    - With this payload >> possible to run RCE on server
    - Work with BurpSuite >> Catch `POST` request & use `Repeater` Tab >> change `email` value with our payload >> investigate the response
    - 6b**8d726d********0c103d014**81c

### Helpful:
- `https://example.com/search?name=Tim&age=25&lang=en`
    - `?` >> query string >> every query starts with this >> to send to server
    - `&` >> separator

    ```code
        ?query=book is the query string
        query = key
        book = value
    ```
### 3. Idea
- Nice work with BurpSuite Tool and do some Server Side Template Injection

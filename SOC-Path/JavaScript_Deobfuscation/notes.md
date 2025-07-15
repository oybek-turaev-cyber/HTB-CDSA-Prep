# Intro
- Source Code:
    - HTML >> to determine website's main fields & parameters
    - CSS >> design
    - JavaScript >> perform any functions necessary to run the website

    - `CTRL + U` >> to view the source code
    - each website has `client-side source code`

    - **CSS** >>
        - can be internally within HTML file between `<style>`
        - externally as in `.css` file as referenced within HTML code
            -  external `.css` file is referred to with the `<link> tag` within the HTML head
            -  `<link rel="stylesheet" href="style.css">`

    - **JavaScript**
        - can be internally written between `<script>`
        - or externally `.js file`
            - Within HTML >> `<script src="secret.js"></script>`

# Code Obfuscation
- Goal:
    - make it harder to read the script
    - keeps the same functionality of the code
    - just output is different, but inside tout est parfait

- Technique:
    - certain dictionaries with specific chars/strings/ to encode
    - then these dics used to decode as well

- Why Obfuscation with JavaScript?
    - Interpreted Languages are not complied
    - published  executed openly
    - Comparing other langs: Python or PHP (server-side), JavaScript is in `client-side`
    - JavaScript code is sent to User & executed in plaintext
    - So that, devs also use it to secure their codes to make it harder for reverse engineering

- Use Cases:
    - **Red Flags:**
        - `Authentication` >> *A program runs only if certain obfuscated logic passes (e.g., serial key validation or feature flags)*
            - It works >> *The key-checking function is deeply obfuscated to prevent reverse engineering.*
            -
        - `Encryption` >> *Secrets (e.g., API keys or credentials) are stored in an obfuscated string or
                        encrypted and decrypted at runtime with hardcoded keys.*
            - It works >> Obfuscation hides how the key or secret is derived.

# Obfuscation Practices:
- **Tools:**
    - `jsconsole.com` >> JavaScript interpreter

- **Minification:**
    - Code minification >> make it smaller >> one line
    - `javascript-minifier` >> tool >> `.min.js` >> extension

- **Packing:**
    - Tool >> `beautifytools.com`
    - its usual output starts with `eval()...` and `(p,a,c,k,e,d)`

    - `packer` tool >>  convert all words and symbols of the code into a list or dictionaries
    - Pourtant, c'est possible de voir **some code strings** not ideal option

# Advanced Obfuscation:
- Tools
    - Obfuscator >> `https://obfuscator.io`
    - **can't see any remnants of our original code.**

    - These tools >> may take more resources >> slow >> but looks interesting
        - `https://jsfuck.com/`
        - `https://utf-8.jp/public/jjencode.html`
        - `https://utf-8.jp/public/aaencode.html`

# Deobfuscation
- **Beautify:**
    - Here >> more simple >> just the format of the code will be easier to read
        - `https://prettier.io/`  or `https://beautifier.io/`
    - Output correction

- **Deobfuscate:**
    - UnPacker Tool >> `https://matthewfl.com/unPacker.html`
    - Voila, c'est beau maintenant pour comprendre
    - C'est `unpacking` >>  from `eval()`

# Code Analysis
- Goal:
    - Goal of this deobfuscation >> is to try to unveil the logic of this protected functions/ code
    - Usually >> `Web Requests` >> hidden logics with `GET` or `POST` HTTP Requests
    - To retrieve or update some info in a sneaky way >> to avoid detection & prevention mechanisms

- cURL:
    - `curl http://SERVER_IP:PORT/`
    - `curl -s http://SERVER_IP:PORT/ -X POST` >> -s (silent) >> -X (protocol)
    - `curl -s http://SERVER_IP:PORT/ -X POST -d "param1=sample` >> `-d "param1=sample"` >> **To Send Data**

# Decoding
- Obfuscated Code Types:
    - **Text-Encoding Methods:**
        - `base64`
        - `hex`
        - `rot13`

- **Base64**
    - to reduce the use of special chars
    - uses only alpha-numeric chars and `+`, `/`

    - **Detection:**
        - alpha-numeric values
        - padding char `==` >> since strings should be multiplier of 4 >> in case missing >> `=` is added

    - **Use:**
        - `echo "Hello" | base64` >> Encode
        - Decode >> `echo 'aHR0cHM6Ly93d3cuaGFja3RoZWJveC5ldS8K' | base64 -d`

- **HEX**
    - 16 chars only >> 0-9, a-f
    - Tool: `xxd`
    - `echo 'Hello' | xxd -p` >> Encode
    - Decode >> `echo 68747470733a2f2f7777772e6861636b746865626f782e65752f0a | xxd -p -r`

- **Caesar/Rot13**
    - shifts each letter by a fixed number in a alphabet
    - `rot13` >> *shifts each character 13 times forward.*

    - **Detection:**
        - in rot13, `http://www` becomes `uggc://jjj`, which still holds some resemblances

    - **Use:**
        - `echo https://www.hackthebox.eu/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'`
        - `tr 'A-Za-z' 'N-ZA-Mn-za-m'` >> 13-forwarded output

# Skills Assessment
1. Try to study the HTML code of the webpage, and identify used JavaScript code within it.
   What is the name of the JavaScript file being used?

   **Solved:**
   - J'ai utilise juste cette commande: `curl http://Server:PORT/`
   - J'ai analyse la reponse et j'ai trouve le drapeau >> `api.***.js`

2. Once you find the JavaScript code, try to run it to see if it does any interesting functions. Did you get something in return?

    **Solved:**
    - Pour resoudre ca, j'ai utilise cette commande: `curl http://Server:PORT/api.***.js`
    - Apres obtenir le code, j'ai utilise `jsconsole.com` comme interpreter
    - Voila, j'ai obtenu le drapeau

3. As you may have noticed, the JavaScript code is obfuscated. Try applying the skills you learned in this module
   to deobfuscate the code, and retrieve the 'flag' variable.

   **Solved:**
   - J'ai utilise UnPacker l'outil pour ouvrir le code:
   - Juste faites un copier-coller, Les Gars!
   - Alors, j'ai trouve le drapeau

4. Try to Analyze the deobfuscated JavaScript code, and understand its main functionality.
   Once you do, try to replicate what it's doing to get a secret key. What is the key?

   **Solved:**
   - Ce defi est interessant: j'ai trouve la demande pour server
   - J'ai trouve le fichier interessant, et param1=sample pour envoyer data avec POST
   - Ma commande: `curl http://Server:Port/***.php -X POST -d "serial=********"`
   - J'ai obtenu le hex code apres ca et c'etait la cle secrete!

5.  Once you have the secret key, try to decide it's encoding method, and decode it.
    Then send a 'POST' request to the same previous page with the decoded key as "key=DECODED_KEY". What is the flag you got?

    **Solved:**
    - J'ai compris que je dois faire la deobfuscation avec `HEX`: `xxd -p -r`
    - Apres ca, j'ai obtenu le drapeau
    - Et j'ai envoye la demande POST au serveur:
        - Ma commande: `curl http://Server:Port/***.php -X POST -d "serial=*****************"`
    - Apres ca, j'ai trouve le drapeau
    - Voila, c'est fini! Alors, Dansez!





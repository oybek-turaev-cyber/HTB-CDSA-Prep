## Lab Title: Fawn
- Date: 2025-08-02
- Duration: ~30 minutes

### Platform: HTB – Starting Point > Tier 0

### 1. Scenario Summary
- Learn how to connect to VM & use terminal >> `ping`, `nmap`, `ftp`

### 2. Findings
- FTP       >> File Transfer Protocol >> 20(data transfer), 21(commands)
    - `ftp -?`
- SFTP      >> FTP over SSH
- nmap      >> to find open ports/ services /versions
    - `nmap $ip -sV -p T:20` >> to find the version of the service
    - `nmap $ip -p- -T4` >> to scan faster with agressive mode >> `T4`
    - `nmap $ip -A` >> to find OS info
- curl
    - `curl ftp://anonymous@10.129.39.29` or `ftp 10.21.129.23` (and after this username & password)
    - `code 230` >> successful login

- ls, dir   >> to work with FTP Server files
- get       >> to download files from FTP server

### 3. Idea
- investigate the target >> know open ports >> connection via ftp >> interacting with ftp (download files)















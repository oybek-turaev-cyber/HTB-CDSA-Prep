## Lab Title: Explosion
- Date: 2025-08-02
- Duration: ~30 minutes

### Platform: HTB – Starting Point > Tier 0

### 1. Scenario Summary
- Learn how to work with RDP, XfreeRDP-x11 in Linux

### 2. Findings
- RDP       >> Remote Desktop Protocol >> `3389`
- CLI       >> Command Line Interface
- GUI       >> Graphical User Interface
- Telnet    >> without encryption >> remote access protocol >> 23
- nmap      >> enumeration
    - `nmap -Pn $ip -sV -p T:3389` to find the service info on this port
    - `ms-wbt-server` is running
- xfreerdp  >> tool used in Linux to connect to devices via RDP protocol
    - `xfreerdp /u:user_here /p:password /v:host /dynamic-resolution`
    - `administrator` was allowed user with blank password

### 3. Idea
- communication via RDP >> from Linux env >> with `xfreerdp` utility


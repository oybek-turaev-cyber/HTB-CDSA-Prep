## Lab Title: Meow
- Date: 2025-08-02
- Duration: ~30 minutes

### Platform: HTB – Starting Point > Tier 0

### 1. Scenario Summary
- Learn to work with Redis database >> to enumerate some info
- `redis-cli`, `nmap`

### 2. Findings
- Nmap          >> enumeration
    - `nmap -Pn $ip -p- -T3` >> disable host discovery, all ports, faster mode to request info
    - open port `6379` and service `redis`
- Redis         >> In-Memory Database
- `redis-cli`   >> utility used to communicate with Redis Server
    - `redis-cli -h 10.222.29.12 -p 6379`
        - `info` >> once connected to Redis Server to find info about statistics about Redis Server
        - current server version >> `5.0.7`
        - `select` to choose the certain database
        - `keys *` to retrieve all the keys from the database

### 3. Idea
- Redis >> in-memory database >> to connect to it >> retrieve info


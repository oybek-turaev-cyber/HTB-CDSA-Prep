## Lab Title: Sequel
- Date: 2025-08-04
- Duration: ~30 minutes

### Platform: HTB – Starting Point > Tier 1

### 1. Scenario Summary
- Learn how to work with MySQL Database >> Nmap for enumeration

### 2. Findings
- MySQL     >> port number: 3306 (default one for client-server connections)
- nmap      >> enumeration
    - `nmap $ip -A -sV -p T:3306`
    - MariaDB
    ```code
        3306/tcp open  mysql?
        | mysql-info:
        |   Protocol: 10
        |   Version: 5.5.5-10.3.27-MariaDB-0+deb10u1
        |   Thread ID: 127
        |   Capabilities flags: 63486
        |   Status: Autocommit
        |   Salt: v9U~>W{&Hv;`QXF4rbtB
        |_  Auth Plugin Name: mysql_native_password
    ```

- `mysql`       >> client-side commandline utility to connect to DB server
    - `mysql -h $ip -u root` >> to connect to host >> with root user >> MariaDB allows without password
    - Inside the SQL server:
        - `show databases;`
        - `use htb` >> use certain database
        - `show tables;`
        - `select * from config` >> all entries from `config` table of htb database

    - Flag: `7**************1a39e3d*****15d**` is obtained
### 3. Idea
- Identify the open port >> 3306 >> mysql >> identify what version it has >> root without password >> play with database server inside.

## Lab Title: MongoD
- Date: 2025-08-02
- Duration: ~30 minutes

### Platform: HTB – Starting Point > Tier 0

### 1. Scenario Summary
- Use `nmap`, and work with `MongoDB` to get some info

### 2. Findings
- nmap      >> enumeration
    - `nmap -Pn $ip -p- -T4` >> 2 tcp open ports
- MongoDB   >> MongoDB >> non-SQL database with default port number `27017`
- mongosh   >> mongo shell >> utility used to communicate with MongoDB Server from the client side
- mongo     >> older version of mongosh >> mongo shell
    - `mongo 10.29.29.29:27017`
    - `show dbs`  >> to show all databases in the MongoDB Server
    - `show collections` to list collections
    - `use specific_database_name` >> to use db
    - `db.flag.find()` >> `find()` function used to show content of the certain collection in MongoDB
        - `db.collection_name.find()`

### 3. Idea
- After enumeration with the host, identified that MongoDB is running with port 27017
- Then time to connect & check >> need to use mongo shell `mongosh or mongo` depends on server version
- Once connected to the MongoDB Server, time to find info: `show dbs`, `show collections` then `db.collection_name.find()` to see the content
- There different functions to use >> update, delete >> need to check mongo docs


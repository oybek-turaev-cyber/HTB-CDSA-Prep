- Search for process execution:
    - `index=sysmon EventCode=1 Image=*powershell.exe*`

- Detect lateral movement (PsExec):
    - `index=sysmon CommandLine=*psexec*`















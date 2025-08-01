- Command:
    - `Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | where { $_.Id -eq 4104 }`

- Check for suspicious scripts:
    - base64
    - IEX (Invoke-Expression)
    - DownloadString















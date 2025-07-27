$logfile = 'C:tmppoisoning.csv'
$requestHosts = @('CORP-TX-FILE-01','COPY-NY-DC-02') #False hostnames to request
$interval = 30 #The minimum number of seconds to wait between requests
$jitter = 30 #The maximum value for a random number of seconds to add to the interval
while($true){
    Start-Sleep ($interval + (Get-Random ($jitter + 1)))
    try {
        $ErrorActionPreference = 'stop'
        $request = Get-Random $requestHosts
        $ipAddr = (Resolve-DnsName -LlmnrNetbiosOnly -Name $request).IPAddress.tostring()
        $ErrorActionPreference = "continue"
        $event = [pscustomobject]@{
            date = Get-Date -format o
            host = $env:COMPUTERNAME
            request = $request
            attacker_ip = $ipAddr
            message = "LLMNR/NBT-NS spoofing by $ipAddr detected with $request request"
        }
        Write-Output $event.message
        $event | Export-Csv -Path $logfile -Append -NoTypeInformation
    } catch [System.Management.Automation.RuntimeException],
[System.ComponentModel.Win32Exception] {
    #Suppress output of timeout errors
    } finally {
        $ErrorActionPreference = "continue"
    }
}

# The following commands to log the event & create an event
#       New-EventLog -LogName Application -Source LLMNRDetection
#       Write-EventLog -LogName Application -Source LLMNRDetection -EventId 19001 -Message $msg -EntryType Warning

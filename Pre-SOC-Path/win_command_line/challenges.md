# Challenges

- *Challenge #1*
    - 1st Flag: `D0wn_the_rabbit_H0!3`

- *Challenge #2*
    - 2nd Flag: `Nice and Easy!`

- *Challenge #3*
    - 3rd Flag: `ACADEMY-ICL11`

- *Challenge #4*
    - 4th Flag: `101` >> `dir /A:H`

- *Challenge #5*
    - 5th Flag: `Digging in The nest` >> `for /r %f in (*) do type "%f"`

- *Challenge #6*
    - 6th Flag: `14` >> `net user`

- *Challenge #7*
    - 7th Flag: `htb-student` >> `systeminfo`

- *Challenge #8*
    - 8th Flag: `Modules_make_pwsh_run!` >> `get-module` >> `get-flag`

- *Challenge #9*
    - 9th Flag: `Rick` >> `get-aduser -filter *`

- *Challenge #10*
    - 10th Flag: `vmtoolsd.exe` >> `tasklist | sort /R`

- *Challenge #11*
    - 11th Flag: `justalocaladmin`
    - Command:
        - `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} |
          Where-Object { $_.Properties[5].Value -ne $null } |
          Group-Object { $_.Properties[5].Value } |
          Sort-Object Count -Descending |
          Select-Object Name, Count`
    - $_ >> represents each individual object
    - Properties[5] >> 6th element >> `TargetUserName`
    - Group-Object >> groups all events by `TargetUserName`
    - Sort-Object Count >> calculates failed logins for each user
    - Then we take only Name, Count


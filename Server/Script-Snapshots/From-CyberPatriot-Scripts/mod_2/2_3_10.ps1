# PowerShell script for configuring network access policies
# This script requires administrative privileges to run

# Network access: Do not allow anonymous enumeration of SAM accounts
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1

# Network access: Do not allow anonymous enumeration of SAM accounts and shares
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1

# Network access: Do not allow storage of passwords and credentials for network authentication
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableDomainCreds" -Value 1

# Network access: Let Everyone permissions apply to anonymous users
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -Value 0

# Network access: Named Pipes that can be accessed anonymously - Set to None
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "NullSessionPipes" -Value @("")

# Network access: Remotely accessible registry paths
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths" -Name "Machine" -Value @("System\CurrentControlSet\Control\ProductOptions","System\CurrentControlSet\Control\Server Applications","Software\Microsoft\Windows NT\CurrentVersion")

# Network access: Remotely accessible registry paths and sub-paths
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths" -Name "Machine" -Value @("System\CurrentControlSet\Control\Print\Printers","System\CurrentControlSet\Services\Eventlog","Software\Microsoft\OLAP Server","Software\Microsoft\Windows NT\CurrentVersion\Print","Software\Microsoft\Windows NT\CurrentVersion\Windows","System\CurrentControlSet\Control\ContentIndex","System\CurrentControlSet\Control\Terminal Server","System\CurrentControlSet\Control\Terminal Server\UserConfig","System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration","Software\Microsoft\Windows NT\CurrentVersion\Perflib","System\CurrentControlSet\Services\SysmonLog")

# Network access: Restrict anonymous access to Named Pipes and Shares
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Value 1

# Network access: Restrict clients allowed to make remote calls to SAM
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictremotesam" -Value "O:BAG:BAD:(A;;RC;;;BA)"

# Network access: Shares that can be accessed anonymously - Set to None
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "NullSessionShares" -Value 0

# Network access: Sharing and security model for local accounts
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ForceGuest" -Value 0

# Output the result of the operation
Write-Output "Network access policies have been configured."

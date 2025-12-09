# 1. Set 'Windows Firewall: Domain: Firewall state' to 'On'
Set-NetFirewallProfile -Profile Domain -Enabled True

# 2. Set 'Windows Firewall: Domain: Inbound connections' to 'Block'
Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block

# 3. Set 'Windows Firewall: Domain: Outbound connections' to 'Allow'
Set-NetFirewallProfile -Profile Domain -DefaultOutboundAction Allow

# 4. Set 'Windows Firewall: Domain: Settings: Display a notification' to 'No'
Set-NetFirewallProfile -Profile Domain -NotifyOnListen False

# 5. Set 'Windows Firewall: Domain: Logging: Name'
$LogFilePath = "%SystemRoot%\System32\logfiles\firewall\domainfw.log"
Set-NetFirewallProfile -Profile Domain -LogFileName $LogFilePath

# 6. Set 'Windows Firewall: Domain: Logging: Size limit (KB)' to '16,384 KB or greater'
Set-NetFirewallProfile -Profile Domain -LogMaxSizeKilobytes 16384

# 7. Set 'Windows Firewall: Domain: Logging: Log dropped packets' to 'Yes'
Set-NetFirewallProfile -Profile Domain -LogBlocked True

# 8. Set 'Windows Firewall: Domain: Logging: Log successful connections' to 'Yes'
Set-NetFirewallProfile -Profile Domain -LogAllowed True

# Output current settings
Get-NetFirewallProfile -Profile Domain | Select-Object Enabled, DefaultInboundAction, DefaultOutboundAction, NotifyOnListen, LogFileName, LogMaxSizeKilobytes, LogBlocked, LogAllowed

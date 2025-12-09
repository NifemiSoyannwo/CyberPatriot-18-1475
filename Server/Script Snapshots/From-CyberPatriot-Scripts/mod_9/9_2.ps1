# Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'
Set-NetFirewallProfile -Profile Private -Enabled True

# Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'
Set-NetFirewallProfile -Profile Private -DefaultInboundAction Block

# Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'
Set-NetFirewallProfile -Profile Private -DefaultOutboundAction Allow

# Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'
Set-NetFirewallProfile -Profile Private -NotifyOnListen False

# Ensure 'Windows Firewall: Private: Logging: Name' is set
$LogFilePath = "%SystemRoot%\System32\logfiles\firewall\privatefw.log"
Set-NetFirewallProfile -Profile Private -LogFileName $LogFilePath

# Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'
Set-NetFirewallProfile -Profile Private -LogMaxSizeKilobytes 16384

# Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'
Set-NetFirewallProfile -Profile Private -LogBlocked True

# Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'
Set-NetFirewallProfile -Profile Private -LogAllowed True

# Output the current settings for verification
Get-NetFirewallProfile -Profile Private | Select-Object Enabled, DefaultInboundAction, DefaultOutboundAction, NotifyOnListen, LogFileName, LogMaxSizeKilobytes, LogBlocked, LogAllowed

# Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'
Set-NetFirewallProfile -Profile Public -Enabled True

# Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'
Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block

# Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'
Set-NetFirewallProfile -Profile Public -DefaultOutboundAction Allow

# Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'
Set-NetFirewallProfile -Profile Public -NotifyOnListen False

# Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'
Set-NetFirewallProfile -Profile Public -AllowLocalFirewallRules False

# Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'
Set-NetFirewallProfile -Profile Public -AllowLocalIPsecRules False

# Ensure 'Windows Firewall: Public: Logging: Name' is set
$LogFilePath = "%SystemRoot%\System32\logfiles\firewall\publicfw.log"
Set-NetFirewallProfile -Profile Public -LogFileName $LogFilePath

# Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'
Set-NetFirewallProfile -Profile Public -LogMaxSizeKilobytes 16384

# Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'
Set-NetFirewallProfile -Profile Public -LogBlocked True

# Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'
Set-NetFirewallProfile -Profile Public -LogAllowed True

# Output the current settings for verification
Get-NetFirewallProfile -Profile Public | Select-Object Enabled, DefaultInboundAction, DefaultOutboundAction, NotifyOnListen, AllowLocalFirewallRules, AllowLocalIPsecRules, LogFileName, LogMaxSizeKilobytes, LogBlocked, LogAllowed

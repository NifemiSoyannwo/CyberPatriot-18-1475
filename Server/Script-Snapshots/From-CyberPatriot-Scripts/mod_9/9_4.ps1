# Part 1: Block all incoming connections, including those in the list of allowed apps
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -AllowInboundRules False

# Part 2: Configure Windows Defender Firewall to notify when it blocks a new app
Set-NetFirewallProfile -Profile Domain,Private,Public -NotifyOnListen True

Write-Host "Windows Defender Firewall is now configured to block all incoming connections and notify when a new app is blocked."

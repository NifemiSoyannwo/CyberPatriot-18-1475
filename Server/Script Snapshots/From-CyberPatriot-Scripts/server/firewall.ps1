Write-Output "Configuring Windows Firewall with inbound restrictions..."

# Enable firewall for all profiles
netsh advfirewall set allprofiles state on

# Block inbound traffic by default, allow outbound
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound

Write-Output "Windows Firewall configured with default inbound block policy."
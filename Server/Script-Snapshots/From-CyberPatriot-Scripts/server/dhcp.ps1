# Get all network interfaces on the machine
$interfaces = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }

foreach ($interface in $interfaces) {
    # Enable DHCP on the IPv4 address
    Set-NetIPInterface -InterfaceAlias $interface.Name -Dhcp Enabled

    # Optionally enable DHCP on IPv6 as well
    Set-NetIPInterface -InterfaceAlias $interface.Name -Dhcp Disabled # disable IPv6 if needed

    Write-Host "DHCP enabled for interface: $($interface.Name)"
}
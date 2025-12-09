Write-Host "Starting Windows Defender Firewall configuration..."

# 18.6.11.1 Ensure Windows Defender Firewall is enabled using netsh for compatibility
try {
    netsh advfirewall set allprofiles state on
    Write-Host "Windows Defender Firewall is enabled for all profiles." -ForegroundColor Green
} catch {
    Write-Host "Error enabling Windows Defender Firewall: $_" -ForegroundColor Red
}

# 18.6.11.2 Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is enabled
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NoNetBridge" -Value 1
    Write-Host "Network Bridge configuration is prohibited." -ForegroundColor Green
} catch {
    Write-Host "Error configuring Network Bridge: $_" -ForegroundColor Red
}

# 18.6.11.3 Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is enabled
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "ICSharing" -Value 0
    Write-Host "Internet Connection Sharing is prohibited." -ForegroundColor Green
} catch {
    Write-Host "Error configuring Internet Connection Sharing: $_" -ForegroundColor Red
}

# 18.6.11.4 Ensure 'Require domain users to elevate when setting a network's location' is enabled
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "RequireElevatedNetworkLocation" -Value 1
    Write-Host "Domain users will be required to elevate when setting a network's location." -ForegroundColor Green
} catch {
    Write-Host "Error requiring elevation for network location: $_" -ForegroundColor Red
}

# Output the current settings for verification
Write-Host "Verifying configuration..."

try {
    # Verifying network configuration settings
    $networkSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" | Select-Object NC_ShowSharedAccessUI, NoNetBridge, ICSharing, RequireElevatedNetworkLocation
    Write-Host "Network Configuration Settings:" -ForegroundColor Cyan
    $networkSettings | Format-Table -AutoSize
} catch {
    Write-Host "Error retrieving configuration settings: $_" -ForegroundColor Red
}

Write-Host "Script execution completed." -ForegroundColor Yellow
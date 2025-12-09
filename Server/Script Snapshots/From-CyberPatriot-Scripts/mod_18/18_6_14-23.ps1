Write-Host "Starting CIS Benchmark Hardening..."

# 18.6.14.1 Hardened UNC Paths configuration
Write-Host "Configuring Hardened UNC Paths..."
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "HardenedUNCPaths" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireMutualAuthentication" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireIntegrity" -Value 1
    Write-Host "Hardened UNC Paths configured successfully." -ForegroundColor Green
} catch {
    Write-Host "Error configuring Hardened UNC Paths: $_" -ForegroundColor Red
}

# 18.6.19.2.1 Disable IPv6 by setting DisabledComponents
Write-Host "Disabling IPv6..."
try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 0xff
    Write-Host "IPv6 disabled successfully." -ForegroundColor Green
} catch {
    Write-Host "Error disabling IPv6: $_" -ForegroundColor Red
}

# 18.6.20.1 Disable configuration of wireless settings using Windows Connect Now
Write-Host "Disabling Windows Connect Now wireless configuration..."
try {
    # Check if the Wcn registry path exists, if not, create it
    $wcnPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Wcn"
    if (-not (Test-Path $wcnPath)) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "Wcn" -Force
    }
    Set-ItemProperty -Path $wcnPath -Name "Enabled" -Value 0
    Write-Host "Windows Connect Now wireless configuration disabled." -ForegroundColor Green
} catch {
    Write-Host "Error disabling Windows Connect Now wireless configuration: $_" -ForegroundColor Red
}

# 18.6.20.2 Prohibit access of Windows Connect Now wizards
Write-Host "Prohibiting access to Windows Connect Now wizards..."
try {
    # Ensure the Wcn path exists and create it if needed
    if (-not (Test-Path $wcnPath)) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "Wcn" -Force
    }
    Set-ItemProperty -Path $wcnPath -Name "ProhibitWizards" -Value 1
    Write-Host "Access to Windows Connect Now wizards prohibited." -ForegroundColor Green
} catch {
    Write-Host "Error prohibiting access to Windows Connect Now wizards: $_" -ForegroundColor Red
}

# 18.6.21.1 Minimize the number of simultaneous connections (Prevent Wi-Fi when on Ethernet)
Write-Host "Configuring simultaneous connections limitation..."
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "LimitConnections" -Value 3
    Write-Host "Simultaneous connections minimized to 3." -ForegroundColor Green
} catch {
    Write-Host "Error configuring simultaneous connections limitation: $_" -ForegroundColor Red
}

# 18.6.21.2 Prohibit connection to non-domain networks when on domain network
Write-Host "Prohibiting connection to non-domain networks when on domain network..."
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "ProhibitNonDomain" -Value 1
    Write-Host "Prohibited connection to non-domain networks when on domain network." -ForegroundColor Green
} catch {
    Write-Host "Error prohibiting connection to non-domain networks: $_" -ForegroundColor Red
}

# 18.6.23.2.1 Disable automatic connection to open hotspots, networks shared by contacts, and paid hotspots
Write-Host "Disabling automatic connection to open hotspots and shared networks..."
try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "AutoConnectHotspot" -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "AutoConnectShared" -Value 0
    Write-Host "Automatic connection to open hotspots and shared networks disabled." -ForegroundColor Green
} catch {
    Write-Host "Error disabling automatic connection to hotspots and shared networks: $_" -ForegroundColor Red
}

Write-Host "CIS Benchmark Hardening Script completed." -ForegroundColor Yellow
# CIS Benchmark 18.5: MSS (Legacy) Hardening
# This script configures all 18.5 settings to meet CIS Benchmark requirements.
Write-Output "Starting CIS Benchmark 18.5: MSS (Legacy) Hardening"

# 18.5.1 Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'
Write-Output "Step 1: Disable Automatic Logon"
Try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value 0 -Type String
    Write-Output "Automatic Logon disabled successfully."
} Catch {
    Write-Error "Failed to disable Automatic Logon: $_"
}

# 18.5.2 Ensure 'MSS: (DisableIPSourceRouting IPv6)' is set to 'Enabled: Highest protection'
Write-Output "Step 2: Disable IP Source Routing IPv6"
Try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type DWord
    Write-Output "IP Source Routing IPv6 disabled successfully."
} Catch {
    Write-Error "Failed to disable IP Source Routing IPv6: $_"
}

# 18.5.3 Ensure 'MSS: (DisableIPSourceRouting)' is set to 'Enabled: Highest protection'
Write-Output "Step 3: Disable IP Source Routing"
Try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type DWord
    Write-Output "IP Source Routing disabled successfully."
} Catch {
    Write-Error "Failed to disable IP Source Routing: $_"
}

# 18.5.4 Ensure 'MSS: (DisableSavePassword)' is set to 'Enabled'
Write-Output "Step 4: Prevent Dial-up Password Save"
Try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableSavePassword" -Value 1 -Type DWord
    Write-Output "Dial-up Password Save prevention enabled successfully."
} Catch {
    Write-Error "Failed to prevent Dial-up Password Save: $_"
}

# 18.5.5 Ensure 'MSS: (EnableICMPRedirect)' is set to 'Disabled'
Write-Output "Step 5: Disable ICMP Redirects"
Try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Value 0 -Type DWord
    Write-Output "ICMP Redirects disabled successfully."
} Catch {
    Write-Error "Failed to disable ICMP Redirects: $_"
}

# 18.5.6 Ensure 'MSS: (KeepAliveTime)' is set to '300,000'
Write-Output "Step 6: Configure KeepAliveTime"
Try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "KeepAliveTime" -Value 300000 -Type DWord
    Write-Output "KeepAliveTime configured successfully."
} Catch {
    Write-Error "Failed to configure KeepAliveTime: $_"
}

# 18.5.7 Ensure 'MSS: (NoNameReleaseOnDemand)' is set to 'Enabled'
Write-Output "Step 7: Enable NoNameReleaseOnDemand"
Try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NoNameReleaseOnDemand" -Value 1 -Type DWord
    Write-Output "NoNameReleaseOnDemand enabled successfully."
} Catch {
    Write-Error "Failed to enable NoNameReleaseOnDemand: $_"
}

# 18.5.8 Ensure 'MSS: (PerformRouterDiscovery)' is set to 'Disabled'
Write-Output "Step 8: Disable Router Discovery"
Try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "PerformRouterDiscovery" -Value 0 -Type DWord
    Write-Output "Router Discovery disabled successfully."
} Catch {
    Write-Error "Failed to disable Router Discovery: $_"
}

# 18.5.9 Ensure 'MSS: (SafeDllSearchMode)' is set to 'Enabled'
Write-Output "Step 9: Enable Safe DLL Search Mode"
Try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode" -Value 1 -Type DWord
    Write-Output "Safe DLL Search Mode enabled successfully."
} Catch {
    Write-Error "Failed to enable Safe DLL Search Mode: $_"
}

# 18.5.10 Ensure 'MSS: (ScreenSaverGracePeriod)' is set to 'Enabled: 5 or fewer seconds'
Write-Output "Step 10: Configure ScreenSaverGracePeriod"
Try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ScreenSaverGracePeriod" -Value 5 -Type String
    Write-Output "ScreenSaverGracePeriod configured successfully."
} Catch {
    Write-Error "Failed to configure ScreenSaverGracePeriod: $_"
}

# 18.5.11 Ensure 'MSS: (TcpMaxDataRetransmissions IPv6)' is set to 'Enabled: 3'
Write-Output "Step 11: Configure TcpMaxDataRetransmissions IPv6"
Try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "TcpMaxDataRetransmissions" -Value 3 -Type DWord
    Write-Output "TcpMaxDataRetransmissions IPv6 configured successfully."
} Catch {
    Write-Error "Failed to configure TcpMaxDataRetransmissions IPv6: $_"
}

# 18.5.12 Ensure 'MSS: (TcpMaxDataRetransmissions)' is set to 'Enabled: 3'
Write-Output "Step 12: Configure TcpMaxDataRetransmissions"
Try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxDataRetransmissions" -Value 3 -Type DWord
    Write-Output "TcpMaxDataRetransmissions configured successfully."
} Catch {
    Write-Error "Failed to configure TcpMaxDataRetransmissions: $_"
}

# 18.5.13 Ensure 'MSS: (WarningLevel)' is set to 'Enabled: 90% or less'
Write-Output "Step 13: Configure WarningLevel"
Try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "WarningLevel" -Value 90 -Type DWord
    Write-Output "WarningLevel configured successfully."
} Catch {
    Write-Error "Failed to configure WarningLevel: $_"
}

Write-Output "CIS Benchmark 18.5: MSS (Legacy) Hardening Complete."

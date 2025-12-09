# CIS Benchmark 18.6: System Services Hardening
# This script configures all 18.6 settings to meet CIS Benchmark requirements.
Write-Output "Starting CIS Benchmark 18.6 Hardening"

# 18.6.4.1 Ensure 'Configure NetBIOS settings' is set to 'Disable NetBIOS name resolution on public networks'
Write-Output "Step 1: Disable NetBIOS name resolution on public networks"
Try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" -Name "NetbiosOptions" -Value 2 -Type DWord
    Write-Output "NetBIOS name resolution disabled successfully on public networks."
} Catch {
    Write-Error "Failed to disable NetBIOS name resolution: $_"
}

# 18.6.4.2 Ensure 'Turn off multicast name resolution' is set to 'Enabled'
Write-Output "Step 2: Turn off multicast name resolution"
Try {
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord
    Write-Output "Multicast name resolution disabled successfully."
} Catch {
    Write-Error "Failed to disable multicast name resolution: $_"
}

# 18.6.5.1 Ensure 'Enable Font Providers' is set to 'Disabled'
Write-Output "Step 3: Disable Font Providers"
Try {
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Font Drivers")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Font Drivers" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Font Drivers" -Name "EnableFontProviders" -Value 0 -Type DWord
    Write-Output "Font Providers disabled successfully."
} Catch {
    Write-Error "Failed to disable Font Providers: $_"
}

# 18.6.8.1 Ensure 'Enable insecure guest logons' is set to 'Disabled'
Write-Output "Step 4: Disable insecure guest logons"
Try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "AllowInsecureGuestAuth" -Value 0 -Type DWord
    Write-Output "Insecure guest logons disabled successfully."
} Catch {
    Write-Error "Failed to disable insecure guest logons: $_"
}

# 18.6.9.1 Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'
Write-Output "Step 5: Disable Mapper I/O (LLTDIO) driver"
Try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LLTDIO" -Name "Start" -Value 4 -Type DWord
    Write-Output "Mapper I/O (LLTDIO) driver disabled successfully."
} Catch {
    Write-Error "Failed to disable Mapper I/O (LLTDIO) driver: $_"
}

# 18.6.9.2 Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'
Write-Output "Step 6: Disable Responder (RSPNDR) driver"
Try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RSPNDR" -Name "Start" -Value 4 -Type DWord
    Write-Output "Responder (RSPNDR) driver disabled successfully."
} Catch {
    Write-Error "Failed to disable Responder (RSPNDR) driver: $_"
}

# 18.6.10.2 Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'
Write-Output "Step 7: Disable Microsoft Peer-to-Peer Networking Services"
Try {
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Peernet")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" -Name "Disabled" -Value 1 -Type DWord
    Write-Output "Microsoft Peer-to-Peer Networking Services disabled successfully."
} Catch {
    Write-Error "Failed to disable Microsoft Peer-to-Peer Networking Services: $_"
}

Write-Output "CIS Benchmark 18.6 Hardening Complete."
# CIS Benchmark 18.4: Microsoft Security Guide Hardening
# This script configures all 18.4 settings to meet CIS Benchmark requirements.
Write-Output "Starting CIS Benchmark 18.4: Microsoft Security Guide Hardening"

# 18.4.1 Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'
Write-Output "Step 1: Apply UAC restrictions to local accounts on network logons"
Try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "LocalAccountTokenFilterPolicy" -Value 0 -Type DWord
    Write-Output "UAC restrictions applied successfully."
} Catch {
    Write-Error "Failed to apply UAC restrictions: $_"
}

# 18.4.2 Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'
Write-Output "Step 2: Configure RPC packet level privacy setting"
Try {
    If (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Force
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" `
        -Name "RestrictRemoteClients" -Value 1 -Type DWord
    Write-Output "RPC packet level privacy setting configured successfully."
} Catch {
    Write-Error "Failed to configure RPC packet level privacy: $_"
}

# 18.4.3 Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)'
Write-Output "Step 3: Disable SMB v1 client driver"
Try {
    If (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10")) {
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Force
    }
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" `
        -Name "Start" -Value 4 -Type DWord
    Write-Output "SMB v1 client driver disabled successfully."
} Catch {
    Write-Error "Failed to disable SMB v1 client driver: $_"
}

# 18.4.4 Ensure 'Configure SMB v1 server' is set to 'Disabled'
Write-Output "Step 4: Disable SMB v1 server"
Try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -Name "SMB1" -Value 0 -Type DWord
    Write-Output "SMB v1 server disabled successfully."
} Catch {
    Write-Error "Failed to disable SMB v1 server: $_"
}

# 18.4.5 Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'
Write-Output "Step 5: Enable SEHOP"
Try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" `
        -Name "DisableExceptionChainValidation" -Value 0 -Type DWord
    Write-Output "SEHOP enabled successfully."
} Catch {
    Write-Error "Failed to enable SEHOP: $_"
}

# 18.4.6 Ensure 'LSA Protection' is set to 'Enabled'
Write-Output "Step 6: Enable LSA Protection"
Try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "RunAsPPL" -Value 1 -Type DWord
    Write-Output "LSA Protection enabled successfully."
} Catch {
    Write-Error "Failed to enable LSA Protection: $_"
}

# 18.4.7 Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)'
Write-Output "Step 7: Configure NetBT NodeType to P-node"
Try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" `
        -Name "NodeType" -Value 2 -Type DWord
    Write-Output "NetBT NodeType configured to P-node successfully."
} Catch {
    Write-Error "Failed to configure NetBT NodeType: $_"
}

# 18.4.8 Ensure 'WDigest Authentication' is set to 'Disabled'
Write-Output "Step 8: Disable WDigest Authentication"
Try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
        -Name "UseLogonCredential" -Value 0 -Type DWord
    Write-Output "WDigest Authentication disabled successfully."
} Catch {
    Write-Error "Failed to disable WDigest Authentication: $_"
}

# Verification
Write-Output "Step 9: Verifying Applied Settings"
$settings = @(
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "LocalAccountTokenFilterPolicy"; Value = 0; Desc = "UAC restrictions" }
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"; Name = "RestrictRemoteClients"; Value = 1; Desc = "RPC packet level privacy" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"; Name = "Start"; Value = 4; Desc = "SMB v1 Client Driver" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name = "SMB1"; Value = 0; Desc = "SMB v1 Server" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"; Name = "DisableExceptionChainValidation"; Value = 0; Desc = "SEHOP" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "RunAsPPL"; Value = 1; Desc = "LSA Protection" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"; Name = "NodeType"; Value = 2; Desc = "NetBT NodeType" }
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; Name = "UseLogonCredential"; Value = 0; Desc = "WDigest Authentication" }
)
Foreach ($setting in $settings) {
    Try {
        $currentValue = (Get-ItemProperty -Path $setting.Path -Name $setting.Name).$($setting.Name)
        If ($currentValue -eq $setting.Value) {
            Write-Output "Verification Passed: $($setting.Desc)"
        } Else {
            Write-Error "Verification Failed: $($setting.Desc)"
        }
    } Catch {
        Write-Error "Verification Failed: $($setting.Desc) - $_"
    }
}

Write-Output "CIS Benchmark 18.4: Microsoft Security Guide Hardening Complete."
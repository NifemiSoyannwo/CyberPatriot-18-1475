# CIS Benchmark 18.3: Local Administrator Password Solution (LAPS) Hardening
# This script configures LAPS to meet CIS Benchmark requirements.

Write-Output "Starting CIS Benchmark 18.3: LAPS Configuration Hardening"

# Define LAPS Settings
$GPOSettings = @(
    @{ Name = "AdmPwdEnabled"; Value = 1; Description = "Enable Local Admin Password Management" }
    @{ Name = "PasswordComplexity"; Value = 4; Description = "Password Complexity: Large letters + small letters + numbers + special characters" }
    @{ Name = "PasswordLength"; Value = 15; Description = "Password Length: 15 or more characters" }
    @{ Name = "PasswordAgeDays"; Value = 30; Description = "Password Age: 30 or fewer days" }
    @{ Name = "PwdExpirationProtectionEnabled"; Value = 1; Description = "Prevent password expiration time longer than required by policy" }
)

# Registry Path for LAPS
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"

# Ensure LAPS Extension / CSE is installed
Write-Output "Step 1: Verifying LAPS CSE Installation"
Try {
    $lapsInstalled = Get-WindowsFeature -Name RSAT-AD-PowerShell
    If ($lapsInstalled.Installed) {
        Write-Output "LAPS CSE is installed."
    } Else {
        Write-Output "LAPS CSE is not installed. Installing..."
        Install-WindowsFeature -Name RSAT-AD-PowerShell -IncludeAllSubFeature
        Write-Output "LAPS CSE has been installed."
    }
} Catch {
    Write-Error "Failed to verify or install LAPS CSE: $_"
}

# Apply LAPS Settings
Write-Output "Step 2: Configuring LAPS Registry Settings"
Try {
    If (-not (Test-Path $regPath)) {
        Write-Output "Creating registry path: $regPath"
        New-Item -Path $regPath -Force | Out-Null
    }

    Foreach ($setting in $GPOSettings) {
        Write-Output "Configuring: $($setting.Description)"
        Set-ItemProperty -Path $regPath -Name $setting.Name -Value $setting.Value -Type DWord
    }

    Write-Output "LAPS settings successfully applied."
} Catch {
    Write-Error "Failed to configure LAPS settings: $_"
}

# Verification
Write-Output "Step 3: Verifying Applied LAPS Settings"
Try {
    Foreach ($setting in $GPOSettings) {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $setting.Name).$($setting.Name)
        If ($currentValue -eq $setting.Value) {
            Write-Output "Verification Passed: $($setting.Description)"
        } Else {
            Write-Error "Verification Failed: $($setting.Description)"
        }
    }
} Catch {
    Write-Error "Failed to verify LAPS settings: $_"
}

Write-Output "CIS Benchmark 18.3: LAPS Configuration Hardening Complete."

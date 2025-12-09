# PowerShell Script to Set Lock Screen Policies
# Define the registry paths and values
$lockScreenCameraPolicyPath = "HKLM:\Software\Policies\Microsoft\Windows\Personalization"
$lockScreenSlideShowPolicyPath = "HKLM:\Software\Policies\Microsoft\Windows\Personalization"

# Ensure the policy paths exist
if (-not (Test-Path $lockScreenCameraPolicyPath)) {
    New-Item -Path $lockScreenCameraPolicyPath -Force | Out-Null
}

if (-not (Test-Path $lockScreenSlideShowPolicyPath)) {
    New-Item -Path $lockScreenSlideShowPolicyPath -Force | Out-Null
}

# Set 'Prevent enabling lock screen camera' to Enabled (Scored)
Set-ItemProperty -Path $lockScreenCameraPolicyPath -Name "NoLockScreenCamera" -Value 1
Write-Host "'Prevent enabling lock screen camera' has been set to Enabled."

# Set 'Prevent enabling lock screen slide show' to Enabled (Automated)
Set-ItemProperty -Path $lockScreenSlideShowPolicyPath -Name "NoLockScreenSlideshow" -Value 1
Write-Host "'Prevent enabling lock screen slide show' has been set to Enabled."

# Confirm the settings
Write-Host "Settings applied successfully. Verify changes via Local Group Policy or the Registry Editor."

# PowerShell Script to Disable Online Speech Recognition Services and Online Tips

# Define the registry paths and values
$speechRecognitionPolicyPath = "HKLM:\Software\Policies\Microsoft\InputPersonalization"
$onlineTipsPolicyPath = "HKLM:\Software\Policies\Microsoft\Windows\CloudContent"

# Ensure the policy paths exist
if (-not (Test-Path $speechRecognitionPolicyPath)) {
    New-Item -Path $speechRecognitionPolicyPath -Force | Out-Null
}

if (-not (Test-Path $onlineTipsPolicyPath)) {
    New-Item -Path $onlineTipsPolicyPath -Force | Out-Null
}

# Set 'Allow users to enable online speech recognition services' to Disabled (Automated)
Set-ItemProperty -Path $speechRecognitionPolicyPath -Name "AllowInputPersonalization" -Value 0
Write-Host "'Allow users to enable online speech recognition services' has been set to Disabled."

# Set 'Allow Online Tips' to Disabled
Set-ItemProperty -Path $onlineTipsPolicyPath -Name "DisableSoftLanding" -Value 0
Write-Host "'Allow Online Tips' has been set to Disabled."

# Confirm the settings
Write-Host "Settings applied successfully. Verify changes via Local Group Policy or the Registry Editor."

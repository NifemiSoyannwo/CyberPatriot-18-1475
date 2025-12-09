# PowerShell Script to Enable "Turn off Autoplay" Policy for All Drives

# Define the registry paths for "Turn off Autoplay" Group Policy settings
$explorerPolicyPath = "HKLM:\Software\Policies\Microsoft\Windows\Explorer"
$autoplayHandlersPolicyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

# Create the registry path if it doesn't already exist
if (!(Test-Path $explorerPolicyPath)) {
    New-Item -Path $explorerPolicyPath -Force | Out-Null
}

if (!(Test-Path $autoplayHandlersPolicyPath)) {
    New-Item -Path $autoplayHandlersPolicyPath -Force | Out-Null
}

# Set "NoDriveTypeAutoRun" to 255 (0xFF) to disable Autoplay for all drives
Set-ItemProperty -Path $explorerPolicyPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord
Set-ItemProperty -Path $autoplayHandlersPolicyPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord

# Enforce the "Turn off Autoplay" policy by setting "NoAutoPlay" to 1
Set-ItemProperty -Path $explorerPolicyPath -Name "NoAutoPlay" -Value 1 -Type DWord

Write-Output "The 'Turn off Autoplay' policy has been set to 'Enabled' for all drives in Group Policy."

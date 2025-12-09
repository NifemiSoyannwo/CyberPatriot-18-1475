# PowerShell script for configuring Microsoft network client policies
# This script requires administrative privileges to run

# Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1

# Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -Value 1

# Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnablePlainTextPassword" -Value 0

# Output the result of the operation
Write-Output "Microsoft network client policies have been configured."

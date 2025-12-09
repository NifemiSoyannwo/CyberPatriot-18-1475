# PowerShell script for configuring domain member policies
# This script requires administrative privileges to run

# Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireSignOrSeal" -Value 1

# Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "SealSecureChannel" -Value 1

# Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "SignSecureChannel" -Value 1

# Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "DisablePasswordChange" -Value 0

# Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "MaximumPasswordAge" -Value 30

# Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireStrongKey" -Value 1

# Output the result of the operation
Write-Output "Domain member policies have been configured."

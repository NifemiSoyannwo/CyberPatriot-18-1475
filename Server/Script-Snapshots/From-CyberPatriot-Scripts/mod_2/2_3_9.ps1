# PowerShell script for configuring Microsoft network server policies
# This script requires administrative privileges to run

# Set 'Amount of idle time required before suspending session' to 15 minutes
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "AutoDisconnect" -Value 15

# Enable 'Microsoft network server: Digitally sign communications (always)'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RequireSecuritySignature" -Value 1

# Enable 'Microsoft network server: Digitally sign communications (if client agrees)'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "EnableSecuritySignature" -Value 1

# Enable 'Microsoft network server: Disconnect clients when logon hours expire'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "enableforcedlogoff" -Value 1

# Set 'Microsoft network server: Server SPN target name validation level' to 'Accept if provided by client'
# Note: Value 0 = Accept if provided by client, 1 = Required from client
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "SMBServerNameHardeningLevel" -Value 0

# Output the result of the operation
Write-Output "Microsoft network server policies have been configured."

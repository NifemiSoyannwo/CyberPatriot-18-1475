# PowerShell script to configure audit settings
# This script requires administrative privileges to run

# Disable 'Shut down system immediately if unable to log security audits'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "CrashOnAuditFail" -Value 0

# Output the result of the operation
Write-Output "Audit settings have been configured."

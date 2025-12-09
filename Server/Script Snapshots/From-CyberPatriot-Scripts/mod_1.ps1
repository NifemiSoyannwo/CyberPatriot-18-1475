# PowerShell script to update Password Policy and Account Lockout Policy
# This script requires administrative privileges to run

# Export the current security settings to a temporary file
$securityTemplate = "$env:temp\secpol.cfg"
secedit /export /cfg $securityTemplate

# Read the security settings into a variable
$securitySettings = Get-Content $securityTemplate

# Modify the Password Policy settings
$securitySettings = $securitySettings -replace "PasswordHistorySize = .+", "PasswordHistorySize = 24" # Enforce password history
$securitySettings = $securitySettings -replace "MaximumPasswordAge = .+", "MaximumPasswordAge = 90" # Maximum password age
$securitySettings = $securitySettings -replace "MinimumPasswordAge = .+", "MinimumPasswordAge = 1" # Minimum password age
$securitySettings = $securitySettings -replace "MinimumPasswordLength = .+", "MinimumPasswordLength = 14" # Minimum password length
$securitySettings = $securitySettings -replace "PasswordComplexity = .+", "PasswordComplexity = 1" # Password must meet complexity requirements
$securitySettings = $securitySettings -replace "ClearTextPassword = .+", "ClearTextPassword = 0" # Store passwords using reversible encryption

# Modify the Account Lockout Policy settings
$securitySettings = $securitySettings -replace "LockoutBadCount = .+", "LockoutBadCount = 5" # Account lockout threshold
$securitySettings = $securitySettings -replace "LockoutDuration = .+", "LockoutDuration = 15" # Account lockout duration (minutes)
$securitySettings = $securitySettings -replace "ResetLockoutCount = .+", "ResetLockoutCount = 15" # Reset account lockout counter after (minutes)

# Write the updated settings back to the temporary file
$securitySettings | Set-Content $securityTemplate

# Import the updated settings
secedit /configure /db $env:windir\security\local.sdb /cfg $securityTemplate /areas SECURITYPOLICY

# Clean up the temporary file
Remove-Item $securityTemplate

# Output the result of the operation
Write-Output "Security settings have been updated. Please check the scesrv.log for details."

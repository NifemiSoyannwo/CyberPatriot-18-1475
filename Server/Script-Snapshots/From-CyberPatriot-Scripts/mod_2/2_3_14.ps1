# PowerShell script to set 'System cryptography: Force strong key protection for user keys stored on the computer'
# This script requires administrative privileges to run

# Define the registry path
$regPathCryptography = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography"

# Check if the registry path exists; if not, create it
if (-not (Test-Path $regPathCryptography)) {
    New-Item -Path $regPathCryptography -Force | Out-Null
}

# Set the value to ensure strong key protection (2 = User is prompted when the key is first used)
Set-ItemProperty -Path $regPathCryptography -Name "ForceKeyProtection" -Value 1

# Output the result of the operation
Write-Output "'System cryptography: Force strong key protection for user keys stored on the computer' has been configured."

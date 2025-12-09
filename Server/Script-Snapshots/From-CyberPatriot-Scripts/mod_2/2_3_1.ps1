# PowerShell script for configuring various account policies
# This script requires administrative privileges to run

# Block Microsoft accounts
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoConnectedUser" -Value 3

# Disable Guest account (Using net user command)
& net user Guest /active:no

# Limit local account use of blank passwords to console logon only
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1

# Rename administrator account (Using Rename-LocalUser cmdlet)
Try {
    Rename-LocalUser -Name "Administrator" -NewName "theAdmin"
} Catch {
    Write-Warning "Could not rename the Administrator account. Error: $_"
}

# Rename guest account (Using Rename-LocalUser cmdlet)
Try {
    Rename-LocalUser -Name "Guest" -NewName "theGuest"
} Catch {
    Write-Warning "Could not rename the Guest account. Error: $_"
}

# Output the result of the operation
Write-Output "Security options have been configured."

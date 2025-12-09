# PowerShell script for configuring User Account Control policies
# This script requires administrative privileges to run

# User Account Control: Admin Approval Mode for the Built-in Administrator account
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Value 1

# User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2

# User Account Control: Behavior of the elevation prompt for standard users
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value 0

# User Account Control: Detect application installations and prompt for elevation
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableInstallerDetection" -Value 1

# User Account Control: Only elevate UIAccess applications that are installed in secure locations
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableSecureUIAPaths" -Value 1

# User Account Control: Run all administrators in Admin Approval Mode
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1

# User Account Control: Switch to the secure desktop when prompting for elevation
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1

# User Account Control: Virtualize file and registry write failures to per-user locations
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization" -Value 1

# Output the result of the operation
Write-Output "User Account Control policies have been configured."

# PowerShell script for configuring system object policies
# This script requires administrative privileges to run

# System objects: Require case insensitivity for non-Windows subsystems
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" -Name "ObCaseInsensitive" -Value 1

# System objects: Strengthen default permissions of internal system objects (e.g., Symbolic Links)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -Value 1

# Output the result of the operation
Write-Output "System object policies have been configured."

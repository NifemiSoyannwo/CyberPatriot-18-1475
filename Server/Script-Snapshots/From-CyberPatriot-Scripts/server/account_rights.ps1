Write-Output "Configuring User Account Policies and Rights Assignments..."

# Disable Guest Account
Disable-LocalUser -Name "Guest"

# Set UAC (User Access Control) to enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1

# Restrict network logon to Administrators and Authenticated Users
$secpolPath = "C:\secpol.cfg"
secedit /export /cfg $secpolPath
$secpolContent = Get-Content -Path $secpolPath
$secpolContent = $secpolContent -replace 'SeNetworkLogonRight = .*', 'SeNetworkLogonRight = Administrators, Authenticated Users'
$secpolContent = $secpolContent -replace 'SeInteractiveLogonRight = .*', 'SeInteractiveLogonRight = Administrators'
$secpolContent | Set-Content -Path $secpolPath
secedit /configure /db secedit.sdb /cfg $secpolPath /overwrite
Write-Output "User Account Policies and Rights Assignments applied."

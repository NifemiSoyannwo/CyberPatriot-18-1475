Write-Output "Disabling unnecessary services and managing server roles..."

# Disable Remote Registry
Stop-Service -Name RemoteRegistry -Force
Set-Service -Name RemoteRegistry -StartupType Disabled

# Disable Print Spooler (if printing is not required)
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled

# Remove unused Windows roles/features (customize as needed)
Uninstall-WindowsFeature -Name Web-Server, Web-WebServer, Fax -ErrorAction SilentlyContinue

Write-Output "Service and Role Management settings applied."

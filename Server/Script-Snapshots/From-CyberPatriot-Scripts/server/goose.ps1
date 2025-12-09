# Ensure script is run as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Output "Please run this script as Administrator."
    exit
}

# Function to safely set registry properties
function Set-RegistryProperty {
    param (
        [string]$Path,
        [string]$Name,
        [Object]$Value
    )
    if (Test-Path $Path) {
        try {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -ErrorAction Stop
            Write-Output "Successfully set $Name at $Path."
        } catch {
            Write-Output ("Failed to set {0} at {1}. Error: {2}" -f $Name, $Path, $_)
        }
    } else {
        Write-Output "Registry path not found: $Path"
    }
}

# Function to safely configure services
function Configure-Service {
    param (
        [string]$ServiceName,
        [string]$StartupType,
        [bool]$StartService = $false
    )
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        try {
            Set-Service -Name $ServiceName -StartupType $StartupType -ErrorAction Stop
            Write-Output "Set $ServiceName startup type to $StartupType."
            if ($StartService) {
                Start-Service -Name $ServiceName -ErrorAction Stop
                Write-Output "Started $ServiceName."
            }
        } catch {
            Write-Output ("Failed to configure {0}. Error: {1}" -f $ServiceName, $_)
        }
    } else {
        Write-Output "Service not found: $ServiceName"
    }
}

# Password Policies
secedit /configure /db secedit.sdb /cfg "$env:windir\security\templates\basicwk.inf" /areas SECURITYPOLICY
net accounts /minpwlen:10 /minpwage:1 /maxpwage:30
net accounts /uniquepw:5

# Configure Password Complexity and Encryption
Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "FIPSAlgorithmPolicy" -Value 1
Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1
Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ClearTextPassword" -Value 0

# Require CTRL+ALT+DEL for login
Set-RegistryProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value 0

# Audit Credential Validation
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

# Prevent Users from Installing Printer Drivers
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "PointAndPrint_Restrictions" -Value 1

# CD-ROM access restricted to locally logged-on users only
Set-RegistryProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AllocateCDRoms" -Value 1

# System not allowed to be shutdown without logon
Set-RegistryProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Value 0

# Disable Print Driver Downloads over HTTP
Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -Value 1

# Autoplay disabled for all drives
Set-RegistryProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255

# Enable Shell protocol protected mode
Set-RegistryProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "EnableShellProtocolProtectedMode" -Value 1

# Enable Protected Event Logging
Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "SCENoProtectedEventLogging" -Value 0

# Disable Plug and Play service
Configure-Service -ServiceName "PlugPlay" -StartupType "Disabled"

# Configure Windows Defender Firewall
Configure-Service -ServiceName "MpsSvc" -StartupType "Automatic" -StartService $true

# Disable Print Spooler service
Configure-Service -ServiceName "Spooler" -StartupType "Disabled"

# Ensure Event Log service is set to automatic
Configure-Service -ServiceName "EventLog" -StartupType "Automatic" -StartService $true

# Enable Windows Defender SmartScreen
Set-RegistryProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "RequireAdmin"

# Show security prompt for Windows Installer scripts from the web
Set-RegistryProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 1

# Enable Windows Defender Antivirus
try {
    Set-MpPreference -DisableRealtimeMonitoring $false
    Write-Output "Windows Defender Antivirus enabled."
} catch {
    Write-Output ("Failed to enable Windows Defender Antivirus. Error: {0}" -f $_)
}

# Prevent Remote Shell Connections
Set-RegistryProperty -Path "HKLM:\Software\Microsoft\Powershell\1\ShellIds\Microsoft.PowerShell" -Name "DisableRemoteShell" -Value 1

Write-Output "GOOSE image has ran successfully!"
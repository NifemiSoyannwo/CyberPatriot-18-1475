# PowerShell script for configuring device policies
# This script requires administrative privileges to run

# Path for 'Devices: Allowed to format and eject removable media'
$allocateDASDPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Check if the registry path exists, if so, set the policy
if (Test-Path $allocateDASDPath) {
    Set-ItemProperty -Path $allocateDASDPath -Name "AllocateDASD" -Value 2
    Write-Output "Policy for 'Devices: Allowed to format and eject removable media' has been configured."
} else {
    Write-Warning "'AllocateDASD' path does not exist or is not accessible."
}

# Enable 'Devices: Prevent users from installing printer drivers'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" -Name "AddPrinterDrivers" -Value 1
Write-Output "Policy for 'Devices: Prevent users from installing printer drivers' has been enabled."

# Module 19: Administrative Templates (User) - CIS Benchmark v2.0.0 Compliance
# This script applies security policies as per CIS recommendations for Windows 10/11
# Administrative privileges are required to run this script

# --------------------------
# 19.1.3.1 Enable Screen Saver
# --------------------------
Write-Output "Enforcing: Enable Screen Saver"
$screenSaverPath = "HKCU:\Control Panel\Desktop"
if (Test-Path $screenSaverPath) {
    Set-ItemProperty -Path $screenSaverPath -Name "ScreenSaveActive" -Value 1
    Write-Output "Screen Saver Enabled."
} else {
    Write-Output "Path $screenSaverPath not found."
}

# --------------------------
# 19.1.3.2 Password Protect the Screen Saver
# --------------------------
Write-Output "Enforcing: Password Protect the Screen Saver"
if (Test-Path $screenSaverPath) {
    Set-ItemProperty -Path $screenSaverPath -Name "ScreenSaverIsSecure" -Value 1
    Write-Output "Password protection for Screen Saver Enabled."
} else {
    Write-Output "Path $screenSaverPath not found."
}

# --------------------------
# 19.1.3.3 Screen Saver Timeout
# --------------------------
Write-Output "Enforcing: Screen Saver Timeout to 900 seconds"
if (Test-Path $screenSaverPath) {
    Set-ItemProperty -Path $screenSaverPath -Name "ScreenSaveTimeOut" -Value 900
    Write-Output "Screen Saver Timeout set to 900 seconds."
} else {
    Write-Output "Path $screenSaverPath not found."
}

# --------------------------
# 19.5.1.1 Turn off toast notifications on the lock screen
# --------------------------
Write-Output "Enforcing: Turn off toast notifications on the lock screen"
$notificationsPath = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
if (!(Test-Path $notificationsPath)) {
    New-Item -Path $notificationsPath -Force | Out-Null
}
Set-ItemProperty -Path $notificationsPath -Name "NoToastApplicationNotification" -Value 1
Write-Output "Toast notifications on the lock screen disabled."

# --------------------------
# 19.6.6.1.1 Turn off Help Experience Improvement Program
# --------------------------
Write-Output "Enforcing: Turn off Help Experience Improvement Program"
$helpExperiencePath = "HKCU:\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0"
if (!(Test-Path $helpExperiencePath)) {
    New-Item -Path $helpExperiencePath -Force | Out-Null
}
Set-ItemProperty -Path $helpExperiencePath -Name "NoImplicitFeedback" -Value 1
Write-Output "Help Experience Improvement Program disabled."

# --------------------------
# 19.7.4.1 Do not preserve zone information in file attachments
# --------------------------
Write-Output "Enforcing: Do not preserve zone information in file attachments"
$attachmentsPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"
if (!(Test-Path $attachmentsPath)) {
    New-Item -Path $attachmentsPath -Force | Out-Null
}
Set-ItemProperty -Path $attachmentsPath -Name "SaveZoneInformation" -Value 2
Write-Output "Zone information will not be preserved in file attachments."

# --------------------------
# 19.7.4.2 Notify antivirus programs when opening attachments
# --------------------------
Write-Output "Enforcing: Notify antivirus programs when opening attachments"
if (!(Test-Path $attachmentsPath)) {
    New-Item -Path $attachmentsPath -Force | Out-Null
}
Set-ItemProperty -Path $attachmentsPath -Name "ScanWithAntiVirus" -Value 1
Write-Output "Antivirus notification enabled for file attachments."

# --------------------------
# 19.7.7.1 Configure Windows spotlight on lock screen
# --------------------------
Write-Output "Enforcing: Disable Windows Spotlight on lock screen"
$spotlightPath = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
if (!(Test-Path $spotlightPath)) {
    New-Item -Path $spotlightPath -Force | Out-Null
}
Set-ItemProperty -Path $spotlightPath -Name "ConfigureWindowsSpotlight" -Value 2
Write-Output "Windows Spotlight on lock screen disabled."

# --------------------------
# 19.7.7.2 Do not suggest third-party content in Windows spotlight
# --------------------------
Write-Output "Enforcing: Disable third-party content in Windows Spotlight"
if (!(Test-Path $spotlightPath)) {
    New-Item -Path $spotlightPath -Force | Out-Null
}
Set-ItemProperty -Path $spotlightPath -Name "DisableThirdPartySuggestions" -Value 1
Write-Output "Third-party suggestions in Windows Spotlight disabled."

# --------------------------
# Script Complete
# --------------------------
Write-Output "Module 19: Administrative Templates (User) hardening complete. Please review the output for any errors."

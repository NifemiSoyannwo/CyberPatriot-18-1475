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

Write-Output "---------------------------------------------------------------------"
Write-Output "---------------------------------------------------------------------"
Write-Output "Module 19_1_3 scripts have been ran successfully! (hopefully, right?)"
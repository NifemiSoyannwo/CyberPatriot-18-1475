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

Write-Output "------------------------------------------------"
Write-Output "module 19_5 have been ran successfully"

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


Write-Output "------------------------------------------------------------"
Write-Output "both module 19_7_4_1 and 19_7_4_1 have been ran successfully"
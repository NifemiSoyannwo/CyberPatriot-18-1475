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

Write-Output "------------------------------------------------"
Write-Output "module 19_6 have been ran successfully"
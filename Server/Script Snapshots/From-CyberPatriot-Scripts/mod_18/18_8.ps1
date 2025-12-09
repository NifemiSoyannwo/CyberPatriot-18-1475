Write-Host "Starting CIS Benchmark 18.8.1.1 Hardening..."

# Ensure the registry path exists for the setting
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
if (-not (Test-Path $regPath)) {
    Write-Host "Creating missing registry path: $regPath"
    New-Item -Path $regPath -Force
}

# Set 'Turn off notifications network usage' to 'Enabled'
Write-Host "Setting 'Turn off notifications network usage' to Enabled..."
try {
    Set-ItemProperty -Path $regPath -Name "DisableNetworkUsageNotification" -Value 1
    Write-Host "'Turn off notifications network usage' set to Enabled." -ForegroundColor Green
} catch {
    Write-Host "Error setting 'Turn off notifications network usage': $_" -ForegroundColor Red
}

Write-Host "CIS Benchmark 18.8.1.1 Hardening Script completed." -ForegroundColor Yellow
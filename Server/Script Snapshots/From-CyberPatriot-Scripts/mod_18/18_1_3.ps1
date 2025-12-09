# CIS Benchmark 18.1.3 - Disable 'Allow Online Tips'
# Ensure 'Allow Online Tips' is set to 'Disabled'

Write-Output "Applying CIS Benchmark 18.1.3: Disabling 'Allow Online Tips'"

Try {
    # Registry path for Allow Online Tips
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    $regName = "DisableSoftLanding"
    $regValue = 1

    # Check if the registry path exists, if not, create it
    If (-not (Test-Path $regPath)) {
        Write-Output "Registry path not found. Creating registry path: $regPath"
        New-Item -Path $regPath -Force | Out-Null
    }

    # Set the registry value
    Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Type DWord
    Write-Output "'Allow Online Tips' successfully disabled."
} 
Catch {
    Write-Error "Failed to disable 'Allow Online Tips': $_"
}

# Verify the change
Try {
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName).$regName
    If ($currentValue -eq $regValue) {
        Write-Output "Verification Passed: 'Allow Online Tips' is disabled."
    } Else {
        Write-Error "Verification Failed: 'Allow Online Tips' is not disabled."
    }
} 
Catch {
    Write-Error "Failed to verify 'Allow Online Tips' setting: $_"
}

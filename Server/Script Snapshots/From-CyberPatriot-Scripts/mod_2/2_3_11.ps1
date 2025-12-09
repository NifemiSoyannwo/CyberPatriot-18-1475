# PowerShell script for configuring network security policies
# This script requires administrative privileges to run

# Network security: Allow Local System to use computer identity for NTLM
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "UseMachineId" -Value 1

# Network security: Allow LocalSystem NULL session fallback
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AllowNullSessionFallback" -Value 0

# Network Security: Allow PKU2U authentication requests to this computer to use online identities
$regPathPku2u = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u"
if (-not (Test-Path $regPathPku2u)) {
    New-Item -Path $regPathPku2u -Force | Out-Null
    New-ItemProperty -Path $regPathPku2u -Name "AllowOnlineID" -Value 0 -PropertyType "DWORD"
} else {
    Set-ItemProperty -Path $regPathPku2u -Name "AllowOnlineID" -Value 0
}

# Network security: Configure encryption types allowed for Kerberos
$regPathKerberosParameters = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
if (-not (Test-Path $regPathKerberosParameters)) {
    New-Item -Path $regPathKerberosParameters -Force | Out-Null
    New-ItemProperty -Path $regPathKerberosParameters -Name "SupportedEncryptionTypes" -Value 0x7ffffffc -PropertyType "DWORD"
} else {
    Set-ItemProperty -Path $regPathKerberosParameters -Name "SupportedEncryptionTypes" -Value 0x7ffffffc
}

# Network security: Do not store LAN Manager hash value on next password change
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1

# Network security: LAN Manager authentication level
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5

# Network security: LDAP client signing requirements
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" -Name "LDAPClientIntegrity" -Value 1

# Network security: Minimum session security for NTLM SSP based (including secure RPC) clients
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinClientSec" -Value 0x20080000

# Network security: Minimum session security for NTLM SSP based (including secure RPC) servers
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinServerSec" -Value 0x20080000

# Output the result of the operation
Write-Output "Network security policies have been configured."

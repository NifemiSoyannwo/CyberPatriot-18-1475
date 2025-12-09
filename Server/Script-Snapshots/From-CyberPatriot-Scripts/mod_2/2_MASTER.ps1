# --------
# 2_3_1
# --------
# PowerShell script for configuring various account policies
# This script requires administrative privileges to run

# Block Microsoft accounts
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoConnectedUser" -Value 3

# Disable Guest account (Using net user command)
& net user Guest /active:no

# Limit local account use of blank passwords to console logon only
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1

# Rename administrator account (Using Rename-LocalUser cmdlet)
Try {
    Rename-LocalUser -Name "Administrator" -NewName "theAdmin"
} Catch {
    Write-Warning "Could not rename the Administrator account. Error: $_"
}

# Rename guest account (Using Rename-LocalUser cmdlet)
Try {
    Rename-LocalUser -Name "Guest" -NewName "theGuest"
} Catch {
    Write-Warning "Could not rename the Guest account. Error: $_"
}

# Output the result of the operation
Write-Output "Security options have been configured."
Write-Output "---------------------------------------"

# --------
# 2_3_2
# --------
# PowerShell script to configure audit settings
# This script requires administrative privileges to run

# Disable 'Shut down system immediately if unable to log security audits'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "CrashOnAuditFail" -Value 0

# Output the result of the operation
Write-Output "Audit settings have been configured."
Write-Output "------------------------------------"


# --------
# 2_3_4
# --------
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
Write-Output "-------------------------------------------------------------------------------------"

# --------
# 2_3_6
# --------
# PowerShell script for configuring domain member policies
# This script requires administrative privileges to run

# Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireSignOrSeal" -Value 1

# Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "SealSecureChannel" -Value 1

# Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "SignSecureChannel" -Value 1

# Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "DisablePasswordChange" -Value 0

# Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "MaximumPasswordAge" -Value 30

# Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireStrongKey" -Value 1

# Output the result of the operation
Write-Output "Domain member policies have been configured."
Write-Output "--------------------------------------------"

# --------
# 2_3_7
# --------
# PowerShell script for configuring interactive logon policies
# This script requires administrative privileges to run

# Interactive logon: Do not require CTRL+ALT+DEL - Set to Disabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value 0

# Interactive logon: Don't display last signed-in - Set to Enabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value 1

# Interactive logon: Machine account lockout threshold - Set to 10 invalid logon attempts
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MaxDevicePasswordFailedAttempts" -Value 10

# Interactive logon: Machine inactivity limit - Set to 900 seconds
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Value 900

# Interactive logon: Message text for users attempting to log on
# Replace 'Your message text' with your actual message
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText" -Value "Your message text"

# Interactive logon: Message title for users attempting to log on
# Replace 'Your message title' with your actual title
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeCaption" -Value "Your message title"

# Interactive logon: Number of previous logons to cache - Set to 4 logons
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value 4

# Interactive logon: Prompt user to change password before expiration - Set between 5 and 14 days
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "PasswordExpiryWarning" -Value 14

# Interactive logon: Smart card removal behavior - Set to 'Lock Workstation'
# Value 0 = No Action, 1 = Lock Workstation, 2 = Force Logoff, 3 = Disconnect if a Remote Desktop Services session
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ScRemoveOption" -Value 1

# Output the result of the operation
Write-Output "Interactive logon policies have been configured."
Write-Output "------------------------------------------------"

# --------
# 2_3_8
# --------
# PowerShell script for configuring Microsoft network client policies
# This script requires administrative privileges to run

# Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1

# Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -Value 1

# Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnablePlainTextPassword" -Value 0

# Output the result of the operation
Write-Output "Microsoft network client policies have been configured."
Write-Output "-------------------------------------------------------"

# --------
# 2_3_9
# --------
# PowerShell script for configuring Microsoft network server policies
# This script requires administrative privileges to run

# Set 'Amount of idle time required before suspending session' to 15 minutes
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "AutoDisconnect" -Value 15

# Enable 'Microsoft network server: Digitally sign communications (always)'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RequireSecuritySignature" -Value 1

# Enable 'Microsoft network server: Digitally sign communications (if client agrees)'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "EnableSecuritySignature" -Value 1

# Enable 'Microsoft network server: Disconnect clients when logon hours expire'
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "enableforcedlogoff" -Value 1

# Set 'Microsoft network server: Server SPN target name validation level' to 'Accept if provided by client'
# Note: Value 0 = Accept if provided by client, 1 = Required from client
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "SMBServerNameHardeningLevel" -Value 0

# Output the result of the operation
Write-Output "Microsoft network server policies have been configured."
Write-Output "-------------------------------------------------------"


# --------
# 2_3_10
# --------
# PowerShell script for configuring network access policies
# This script requires administrative privileges to run

# Network access: Do not allow anonymous enumeration of SAM accounts
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1

# Network access: Do not allow anonymous enumeration of SAM accounts and shares
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1

# Network access: Do not allow storage of passwords and credentials for network authentication
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableDomainCreds" -Value 1

# Network access: Let Everyone permissions apply to anonymous users
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -Value 0

# Network access: Named Pipes that can be accessed anonymously - Set to None
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "NullSessionPipes" -Value @("")

# Network access: Remotely accessible registry paths
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths" -Name "Machine" -Value @("System\CurrentControlSet\Control\ProductOptions","System\CurrentControlSet\Control\Server Applications","Software\Microsoft\Windows NT\CurrentVersion")

# Network access: Remotely accessible registry paths and sub-paths
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths" -Name "Machine" -Value @("System\CurrentControlSet\Control\Print\Printers","System\CurrentControlSet\Services\Eventlog","Software\Microsoft\OLAP Server","Software\Microsoft\Windows NT\CurrentVersion\Print","Software\Microsoft\Windows NT\CurrentVersion\Windows","System\CurrentControlSet\Control\ContentIndex","System\CurrentControlSet\Control\Terminal Server","System\CurrentControlSet\Control\Terminal Server\UserConfig","System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration","Software\Microsoft\Windows NT\CurrentVersion\Perflib","System\CurrentControlSet\Services\SysmonLog")

# Network access: Restrict anonymous access to Named Pipes and Shares
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Value 1

# Network access: Restrict clients allowed to make remote calls to SAM
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictremotesam" -Value "O:BAG:BAD:(A;;RC;;;BA)"

# Network access: Shares that can be accessed anonymously - Set to None
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "NullSessionShares" -Value 0

# Network access: Sharing and security model for local accounts
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ForceGuest" -Value 0

# Output the result of the operation
Write-Output "Network access policies have been configured."
Write-Output "---------------------------------------------"

# --------
# 2_3_11
# --------
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
Write-Output "-----------------------------------------------"

# --------
# 2_3_14
# --------
# PowerShell script to set 'System cryptography: Force strong key protection for user keys stored on the computer'
# This script requires administrative privileges to run

# Define the registry path
$regPathCryptography = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography"

# Check if the registry path exists; if not, create it
if (-not (Test-Path $regPathCryptography)) {
    New-Item -Path $regPathCryptography -Force | Out-Null
}

# Set the value to ensure strong key protection (2 = User is prompted when the key is first used)
Set-ItemProperty -Path $regPathCryptography -Name "ForceKeyProtection" -Value 1

# Output the result of the operation
Write-Output "'System cryptography: Force strong key protection for user keys stored on the computer' has been configured."
Write-Output "------------------------------------------------------------------------------------------------------------"

# --------
# 2_3_15
# --------
# PowerShell script for configuring system object policies
# This script requires administrative privileges to run

# System objects: Require case insensitivity for non-Windows subsystems
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" -Name "ObCaseInsensitive" -Value 1

# System objects: Strengthen default permissions of internal system objects (e.g., Symbolic Links)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -Value 1

# Output the result of the operation
Write-Output "System object policies have been configured."
Write-Output "--------------------------------------------"

# --------
# 2_3_17
# --------
# PowerShell script for configuring User Account Control policies
# This script requires administrative privileges to run

# User Account Control: Admin Approval Mode for the Built-in Administrator account
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Value 1

# User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2

# User Account Control: Behavior of the elevation prompt for standard users
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value 0

# User Account Control: Detect application installations and prompt for elevation
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableInstallerDetection" -Value 1

# User Account Control: Only elevate UIAccess applications that are installed in secure locations
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableSecureUIAPaths" -Value 1

# User Account Control: Run all administrators in Admin Approval Mode
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1

# User Account Control: Switch to the secure desktop when prompting for elevation
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1

# User Account Control: Virtualize file and registry write failures to per-user locations
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization" -Value 1

# Output the result of the operation
Write-Output "User Account Control policies have been configured."
Write-Output "---------------------------------------------------"
Write-Output "---------------------------------------------------"
Write-Output "---------------------------------------------------"
Write-Output "WHOLE MODULE 2 HAVE BEEN SCRIPTED SUCCCESSFULLY!"
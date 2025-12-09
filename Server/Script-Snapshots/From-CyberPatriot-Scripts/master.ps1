<#
================================================
CyberPatriot WINDOWS Master Script
Authors: Manan and Sithranjan
Team: 17-1002, Grey Hats from Frisco High School
================================================
#>

Write-Output "
  WELCOME TO WINDOWS MASTER SCRIPT FOR CYBERPATRIOT
   ____ ____  _______   __  _   _    _  _____ ____  
  / ___|  _ \| ____\ \ / / | | | |  / \|_   _/ ___| 
 | |  _| |_) |  _|  \ V /  | |_| | / _ \ | | \___ \ 
 | |_| |  _ <| |___  | |   |  _  |/ ___ \| |  ___) |
  \____|_| \_\_____| |_|   |_| |_/_/   \_\_| |____/ 
                                                    
"

$runMasterScript = Read-Host "
Everything will be stored in the MasterScript.log file after the script is completed.
The scripts are gonna run in this sequence: 
1) ALL Module 1 Scripts
2) ALL Module 2 Scripts
3) ALL Module 5 Scripts
4) ALL Module 9 Scripts
5) ALL Module 18 Scripts
6) ALL Module 19 Scripts
7) OTHER Windows Hardening Scripts
8) Windows 11 CIS v3.0
9) Server 2019 CIS v3.0.1
10) Server Related Scripts
11) Secure.bat BATCH Script

Enter (y/n) to continue the master script!
"

if ($runMasterScript -match "^[yY]$") {
        # --------------------------------
    # 1. Global Variables and Settings
    # --------------------------------
    # Set execution policies, log file path, and other global settings
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
    $LogFile = "./MasterScript.log"
    $FolderPath = "C:\CyberPatriot_Semis_Script"

    # Function to log messages
    function LogMessage {
        param ([string]$Message)
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "$Timestamp : $Message" | Out-File -Append -FilePath $LogFile
    }

    LogMessage "Starting CyberPatriot Master Script..."

    # --------------------------
    # 2. Module Execution Logic
    # --------------------------
    # Sequentially execute all the modules

    $runModule1Script = Read-Host "Do you wanna run all Module 1 scripts? (y/n): "

    if ($runModule1Script -match "^[yY]$") { 
        # === Module 1 Script ===
        LogMessage "Configuring Module 1..."
        # --------
        # 1_*
        # --------
        # Export the current security settings to a temporary file
        $securityTemplate = "$env:temp\secpol.cfg"
        secedit /export /cfg $securityTemplate

        # Read the security settings into a variable
        $securitySettings = Get-Content $securityTemplate

        # Modify the Password Policy settings
        $securitySettings = $securitySettings -replace "PasswordHistorySize = .+", "PasswordHistorySize = 24" # Enforce password history
        $securitySettings = $securitySettings -replace "MaximumPasswordAge = .+", "MaximumPasswordAge = 90" # Maximum password age
        $securitySettings = $securitySettings -replace "MinimumPasswordAge = .+", "MinimumPasswordAge = 1" # Minimum password age
        $securitySettings = $securitySettings -replace "MinimumPasswordLength = .+", "MinimumPasswordLength = 14" # Minimum password length
        $securitySettings = $securitySettings -replace "PasswordComplexity = .+", "PasswordComplexity = 1" # Password must meet complexity requirements
        $securitySettings = $securitySettings -replace "ClearTextPassword = .+", "ClearTextPassword = 0" # Store passwords using reversible encryption

        # Modify the Account Lockout Policy settings
        $securitySettings = $securitySettings -replace "LockoutBadCount = .+", "LockoutBadCount = 5" # Account lockout threshold
        $securitySettings = $securitySettings -replace "LockoutDuration = .+", "LockoutDuration = 15" # Account lockout duration (minutes)
        $securitySettings = $securitySettings -replace "ResetLockoutCount = .+", "ResetLockoutCount = 15" # Reset account lockout counter after (minutes)

        # Write the updated settings back to the temporary file
        $securitySettings | Set-Content $securityTemplate

        # Import the updated settings
        secedit /configure /db $env:windir\security\local.sdb /cfg $securityTemplate /areas SECURITYPOLICY

        # Clean up the temporary file
        Remove-Item $securityTemplate

        # Output the result of the operation
        Write-Output "Security settings have been updated. Please check the scesrv.log for details."
        LogMessage "Security settings have been updated. Please check the scesrv.log for details."

        LogMessage "MODULE 1 CONFIGURATION COMPLETED"
        LogMessage "-----------------------------------------------------------------------------"
        Write-Output "-----------------------------------------------------------------------------------------------------------"

    } else {
        Write-Output "Skipped Module 1 Scripts!"
    }


    $runModule2Script = Read-Host "Do you wanna run all Module 2 scripts? (y/n): "
    if ($runModule2Script -match "^[yY]$") { 

        # === Module 2 Scripts ===
        LogMessage "Configuring Module 2..."
        # --------
        # 2_3_1
        # --------
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
        LogMessage "2_3_1 - Security options have been configured. "

        # --------
        # 2_3_2
        # --------
        # Disable 'Shut down system immediately if unable to log security audits'
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "CrashOnAuditFail" -Value 0
        # Output the result of the operation
        Write-Output "Audit settings have been configured."
        Write-Output "------------------------------------"
        LogMessage "2_3_2 - Audit settings have been configured."

        # --------
        # 2_3_4
        # --------
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
        LogMessage "2_3_4 - Policy for 'Devices: Prevent users from installing printer drivers' has been enabled."

        # --------
        # 2_3_6
        # --------
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
        LogMessage "2_3_6 - Domain member policies have been configured."

        # --------
        # 2_3_7
        # --------
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
        LogMessage "2_3_7 - Interactive logon policies have been configured."

        # --------
        # 2_3_8
        # --------
        # Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1
        # Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -Value 1
        # Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnablePlainTextPassword" -Value 0
        # Output the result of the operation
        Write-Output "Microsoft network client policies have been configured."
        Write-Output "-------------------------------------------------------"
        LogMessage "2_3_8 - Microsoft network client policies have been configured."

        # --------
        # 2_3_9
        # --------
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
        LogMessage "2_3_9 - Microsoft network server policies have been configured."

        # --------
        # 2_3_10
        # --------
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
        LogMessage "2_3_10 - Network access policies have been configured."

        # --------
        # 2_3_11
        # --------
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
        LogMessage "2_3_11 - Network security policies have been configured."

        # --------
        # 2_3_14
        # --------
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
        LogMessage "2_3_14 - 'System cryptography: Force strong key protection for user keys stored on the computer' has been configured."

        # --------
        # 2_3_15
        # --------
        # System objects: Require case insensitivity for non-Windows subsystems
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" -Name "ObCaseInsensitive" -Value 1
        # System objects: Strengthen default permissions of internal system objects (e.g., Symbolic Links)
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -Value 1
        # Output the result of the operation
        Write-Output "System object policies have been configured."
        Write-Output "--------------------------------------------"
        LogMessage "2_3_15 - System object policies have been configured."

        # --------
        # 2_3_17
        # --------
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
        LogMessage "2_3_17 - User Account Control policies have been configured."

        LogMessage "MODULE 2 CONFIGURATION COMPLETED"
        LogMessage "-----------------------------------------------------------------------------"
        Write-Output "-----------------------------------------------------------------------------------------------------------"

    } else {
        Write-Output "Skipped Module 2 Scripts!"
    }

    $runModule5Script = Read-Host "Do you wanna run all Module 5 scripts? (y/n): "
    if ($runModule5Script -match "^[yY]$") { 

        # === Module 5 Script ===
        LogMessage "Configuring Module 5..."
        # --------
        # 5_*
        # --------
        # Define a list of services to be stopped and disabled
        $servicesToDisable = @(
            'BTAGService',
            'bthserv',
            'Browser',
            'MapsBroker',
            'lfsvc',
            'IISADMIN',
            'irmon',
            'SharedAccess',
            'lltdsvc',
            'LxssManager',
            'FTPSVC',
            'MSiSCSI',
            'sshd',
            'PNRPsvc',
            'p2psvc',
            'p2pimsvc',
            'PNRPAutoReg',
            'Spooler',
            'wercplsupport',
            'RasAuto',
            'SessionEnv',
            'TermService',
            'UmRdpService',
            'RpcLocator',
            'RemoteRegistry',
            'RemoteAccess',
            'LanmanServer',
            'simptcp',
            'SNMP',
            'sacsvr',
            'SSDPSRV',
            'upnphost',
            'WMSvc',
            'WerSvc',
            'Wecsvc',
            'WMPNetworkSvc',
            'icssvc',
            'WpnService',
            'PushToInstall',
            'WinRM',
            'W3SVC',
            'XboxGipSvc',
            'XblAuthManager',
            'XblGameSave',
            'XboxNetApiSvc'
        )

        # Loop through each service, stop it, and set it to 'Disabled'
        foreach ($service in $servicesToDisable) {
            # Stop the service
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue

            # Set the service to 'Disabled'
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
        }

        # Display a message indicating the completion of the script
        Write-Host "Services have been stopped and set to 'Disabled'."
        LogMessage "Services have been stopped and set to 'Disabled'."

        LogMessage "MODULE 5 CONFIGURATION COMPLETED"
        LogMessage "-----------------------------------------------------------------------------"
        Write-Output "-----------------------------------------------------------------------------------------------------------"

    } else {
        Write-Output "Skipped Module 5 Scripts!"
    }

    $runModule9Script = Read-Host "Do you wanna run all Module 9 scripts? (y/n): "
    if ($runModule9Script -match "^[yY]$") { 

        # === Module 9 Scripts ===
        LogMessage "Configuring Module 9..."

        # --------
        # 9_1
        # --------
        # 1. Set 'Windows Firewall: Domain: Firewall state' to 'On'
        Set-NetFirewallProfile -Profile Domain -Enabled True

        # 2. Set 'Windows Firewall: Domain: Inbound connections' to 'Block'
        Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block

        # 3. Set 'Windows Firewall: Domain: Outbound connections' to 'Allow'
        Set-NetFirewallProfile -Profile Domain -DefaultOutboundAction Allow

        # 4. Set 'Windows Firewall: Domain: Settings: Display a notification' to 'No'
        Set-NetFirewallProfile -Profile Domain -NotifyOnListen False

        # 5. Set 'Windows Firewall: Domain: Logging: Name'
        $LogFilePath = "%SystemRoot%\System32\logfiles\firewall\domainfw.log"
        Set-NetFirewallProfile -Profile Domain -LogFileName $LogFilePath

        # 6. Set 'Windows Firewall: Domain: Logging: Size limit (KB)' to '16,384 KB or greater'
        Set-NetFirewallProfile -Profile Domain -LogMaxSizeKilobytes 16384

        # 7. Set 'Windows Firewall: Domain: Logging: Log dropped packets' to 'Yes'
        Set-NetFirewallProfile -Profile Domain -LogBlocked True

        # 8. Set 'Windows Firewall: Domain: Logging: Log successful connections' to 'Yes'
        Set-NetFirewallProfile -Profile Domain -LogAllowed True

        # Output current settings
        Get-NetFirewallProfile -Profile Domain | Select-Object Enabled, DefaultInboundAction, DefaultOutboundAction, NotifyOnListen, LogFileName, LogMaxSizeKilobytes, LogBlocked, LogAllowed

        Write-Output "9_1 - Domain Profile Settings Confugured"
        LogMessage "9_1 - Domain Profile Settings Confugured"

        # --------
        # 9_2
        # --------
        # Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'
        Set-NetFirewallProfile -Profile Private -Enabled True

        # Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'
        Set-NetFirewallProfile -Profile Private -DefaultInboundAction Block

        # Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'
        Set-NetFirewallProfile -Profile Private -DefaultOutboundAction Allow

        # Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'
        Set-NetFirewallProfile -Profile Private -NotifyOnListen False

        # Ensure 'Windows Firewall: Private: Logging: Name' is set
        $LogFilePath = "%SystemRoot%\System32\logfiles\firewall\privatefw.log"
        Set-NetFirewallProfile -Profile Private -LogFileName $LogFilePath

        # Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'
        Set-NetFirewallProfile -Profile Private -LogMaxSizeKilobytes 16384

        # Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'
        Set-NetFirewallProfile -Profile Private -LogBlocked True

        # Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'
        Set-NetFirewallProfile -Profile Private -LogAllowed True

        # Output the current settings for verification
        Get-NetFirewallProfile -Profile Private | Select-Object Enabled, DefaultInboundAction, DefaultOutboundAction, NotifyOnListen, LogFileName, LogMaxSizeKilobytes, LogBlocked, LogAllowed

        Write-Output "9_2 - Private Profile Settings Confugured"
        LogMessage "9_2 - Public Profile Settings Confugured"

        # --------
        # 9_3
        # --------
        # Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'
        Set-NetFirewallProfile -Profile Public -Enabled True

        # Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'
        Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block

        # Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'
        Set-NetFirewallProfile -Profile Public -DefaultOutboundAction Allow

        # Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'
        Set-NetFirewallProfile -Profile Public -NotifyOnListen False

        # Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'
        Set-NetFirewallProfile -Profile Public -AllowLocalFirewallRules False

        # Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'
        Set-NetFirewallProfile -Profile Public -AllowLocalIPsecRules False

        # Ensure 'Windows Firewall: Public: Logging: Name' is set
        $LogFilePath = "%SystemRoot%\System32\logfiles\firewall\publicfw.log"
        Set-NetFirewallProfile -Profile Public -LogFileName $LogFilePath

        # Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'
        Set-NetFirewallProfile -Profile Public -LogMaxSizeKilobytes 16384

        # Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'
        Set-NetFirewallProfile -Profile Public -LogBlocked True

        # Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'
        Set-NetFirewallProfile -Profile Public -LogAllowed True

        # Output the current settings for verification
        Get-NetFirewallProfile -Profile Public | Select-Object Enabled, DefaultInboundAction, DefaultOutboundAction, NotifyOnListen, AllowLocalFirewallRules, AllowLocalIPsecRules, LogFileName, LogMaxSizeKilobytes, LogBlocked, LogAllowed

        Write-Output "9_3 - Public Profile Settings Confugured"
        LogMessage "9_3 - Public Profile Settings Confugured"

        # --------
        # 9_4
        # --------
        # Part 1: Block all incoming connections, including those in the list of allowed apps
        Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -AllowInboundRules False

        # Part 2: Configure Windows Defender Firewall to notify when it blocks a new app
        Set-NetFirewallProfile -Profile Domain,Private,Public -NotifyOnListen True

        Write-Host "Windows Defender Firewall is now configured to block all incoming connections and notify when a new app is blocked."
        LogMessage "Windows Defender Firewall is now configured to block all incoming connections and notify when a new app is blocked."

        LogMessage "MODULE 9 CONFIGURATION COMPLETED"
        LogMessage "-----------------------------------------------------------------------------"
        Write-Output "-----------------------------------------------------------------------------------------------------------"

    } else {
        Write-Output "Skipped Module 9 Scripts!"
    }

    $runModule18Script = Read-Host "Do you wanna run all Module 18 scripts? (y/n): "
    if ($runModule18Script -match "^[yY]$") { 

        # === Module 18 Scripts ===
        LogMessage "Configuring Module 18..."
        # --------
        # 18_1_1
        # --------
        # PowerShell Script to Set Lock Screen Policies
        # Define the registry paths and values
        $lockScreenCameraPolicyPath = "HKLM:\Software\Policies\Microsoft\Windows\Personalization"
        $lockScreenSlideShowPolicyPath = "HKLM:\Software\Policies\Microsoft\Windows\Personalization"

        # Ensure the policy paths exist
        if (-not (Test-Path $lockScreenCameraPolicyPath)) {
            New-Item -Path $lockScreenCameraPolicyPath -Force | Out-Null
        }

        if (-not (Test-Path $lockScreenSlideShowPolicyPath)) {
            New-Item -Path $lockScreenSlideShowPolicyPath -Force | Out-Null
        }

        # Set 'Prevent enabling lock screen camera' to Enabled (Scored)
        Set-ItemProperty -Path $lockScreenCameraPolicyPath -Name "NoLockScreenCamera" -Value 1
        Write-Host "'Prevent enabling lock screen camera' has been set to Enabled."
        LogMessage "'Prevent enabling lock screen camera' has been set to Enabled."

        # Set 'Prevent enabling lock screen slide show' to Enabled (Automated)
        Set-ItemProperty -Path $lockScreenSlideShowPolicyPath -Name "NoLockScreenSlideshow" -Value 1
        LogMessage "'Prevent enabling lock screen slide show' has been set to Enabled."
        LogMessage "'Prevent enabling lock screen slide show' has been set to Enabled."

        # Confirm the settings
        Write-Host "Settings applied successfully. Verify changes via Local Group Policy or the Registry Editor."
        LogMessage "Settings applied successfully. Verify changes via Local Group Policy or the Registry Editor."

        # --------
        # 18_1_2
        # --------
        # PowerShell Script to Disable Online Speech Recognition Services and Online Tips
        # Define the registry paths and values
        $speechRecognitionPolicyPath = "HKLM:\Software\Policies\Microsoft\InputPersonalization"
        $onlineTipsPolicyPath = "HKLM:\Software\Policies\Microsoft\Windows\CloudContent"

        # Ensure the policy paths exist
        if (-not (Test-Path $speechRecognitionPolicyPath)) {
            New-Item -Path $speechRecognitionPolicyPath -Force | Out-Null
        }

        if (-not (Test-Path $onlineTipsPolicyPath)) {
            New-Item -Path $onlineTipsPolicyPath -Force | Out-Null
        }

        # Set 'Allow users to enable online speech recognition services' to Disabled (Automated)
        Set-ItemProperty -Path $speechRecognitionPolicyPath -Name "AllowInputPersonalization" -Value 0
        Write-Host "'Allow users to enable online speech recognition services' has been set to Disabled."
        LogMessage "'Allow users to enable online speech recognition services' has been set to Disabled."

        # Set 'Allow Online Tips' to Disabled
        Set-ItemProperty -Path $onlineTipsPolicyPath -Name "DisableSoftLanding" -Value 0
        Write-Host "'Allow Online Tips' has been set to Disabled."
        LogMessage "'Allow Online Tips' has been set to Disabled."

        # Confirm the settings
        Write-Host "Settings applied successfully. Verify changes via Local Group Policy or the Registry Editor."
        LogMessage "Settings applied successfully. Verify changes via Local Group Policy or the Registry Editor."

        LogMessage "MODULE 18 CONFIGURATION COMPLETED"
        LogMessage "-----------------------------------------------------------------------------"
        Write-Output "-----------------------------------------------------------------------------------------------------------"

        # --------
        # 18_1_3
        # --------
        Write-Output "Applying CIS Benchmark 18.1.3: Disabling 'Allow Online Tips'"
        LogMessage "Applying CIS Benchmark 18.1.3: Disabling 'Allow Online Tips'"

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
            LogMessage "'Allow Online Tips' successfully disabled."
        } 
        Catch {
            Write-Error "Failed to disable 'Allow Online Tips': $_"
            LogMessage "Failed to disable 'Allow Online Tips': $_"
        }

        # Verify the change
        Try {
            $currentValue = (Get-ItemProperty -Path $regPath -Name $regName).$regName
            If ($currentValue -eq $regValue) {
                Write-Output "Verification Passed: 'Allow Online Tips' is disabled."
                LogMessage "Verification Passed: 'Allow Online Tips' is disabled."
            } Else {
                Write-Error "Verification Failed: 'Allow Online Tips' is not disabled."
                LogMessage "Verification Failed: 'Allow Online Tips' is not disabled."
            }
        } 
        Catch {
            Write-Error "Failed to verify 'Allow Online Tips' setting: $_"
            LogMessage "Failed to verify 'Allow Online Tips' setting: $_"
        }

        # --------
        # 18_3
        # --------
        Write-Output "Starting CIS Benchmark 18.3: LAPS Configuration Hardening"
        LogMessage "Starting CIS Benchmark 18.3: LAPS Configuration Hardening"

        # Define LAPS Settings
        $GPOSettings = @(
            @{ Name = "AdmPwdEnabled"; Value = 1; Description = "Enable Local Admin Password Management" }
            @{ Name = "PasswordComplexity"; Value = 4; Description = "Password Complexity: Large letters + small letters + numbers + special characters" }
            @{ Name = "PasswordLength"; Value = 15; Description = "Password Length: 15 or more characters" }
            @{ Name = "PasswordAgeDays"; Value = 30; Description = "Password Age: 30 or fewer days" }
            @{ Name = "PwdExpirationProtectionEnabled"; Value = 1; Description = "Prevent password expiration time longer than required by policy" }
        )

        # Registry Path for LAPS
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"

        # Ensure LAPS Extension / CSE is installed
        Write-Output "Step 1: Verifying LAPS CSE Installation"
        Try {
            $lapsInstalled = Get-WindowsFeature -Name RSAT-AD-PowerShell
            If ($lapsInstalled.Installed) {
                Write-Output "LAPS CSE is installed."
                LogMessage "LAPS CSE is installed."
            } Else {
                Write-Output "LAPS CSE is not installed. Installing..."
                Install-WindowsFeature -Name RSAT-AD-PowerShell -IncludeAllSubFeature
                Write-Output "LAPS CSE has been installed."
                LogMessage "LAPS CSE has been installed."
            }
        } Catch {
            Write-Error "Failed to verify or install LAPS CSE: $_"
            LogMessage "Failed to verify or install LAPS CSE: $_"
        }

        # Apply LAPS Settings
        Write-Output "Step 2: Configuring LAPS Registry Settings"
        Try {
            If (-not (Test-Path $regPath)) {
                Write-Output "Creating registry path: $regPath"
                New-Item -Path $regPath -Force | Out-Null
            }

            Foreach ($setting in $GPOSettings) {
                Write-Output "Configuring: $($setting.Description)"
                Set-ItemProperty -Path $regPath -Name $setting.Name -Value $setting.Value -Type DWord
            }

            Write-Output "LAPS settings successfully applied."
            LogMessage "LAPS settings successfully applied."
        } Catch {
            Write-Error "Failed to configure LAPS settings: $_"
            LogMessage "Failed to configure LAPS settings: $_"
        }

        # Verification
        Write-Output "Step 3: Verifying Applied LAPS Settings"
        Try {
            Foreach ($setting in $GPOSettings) {
                $currentValue = (Get-ItemProperty -Path $regPath -Name $setting.Name).$($setting.Name)
                If ($currentValue -eq $setting.Value) {
                    Write-Output "Verification Passed: $($setting.Description)"
                    LogMessage "Verification Passed: $($setting.Description)"
                } Else {
                    Write-Error "Verification Failed: $($setting.Description)"
                    LogMessage "Verification Failed: $($setting.Description)"
                }
            }
        } Catch {
            Write-Error "Failed to verify LAPS settings: $_"
            LogMessage "Failed to verify LAPS settings: $_"
        }

        Write-Output "CIS Benchmark 18.3: LAPS Configuration Hardening Complete."
        LogMessage "CIS Benchmark 18.3: LAPS Configuration Hardening Complete."

        
        # --------
        # 18_4
        # --------
        Write-Output "Starting CIS Benchmark 18.4: Microsoft Security Guide Hardening"
        LogMessage "Starting CIS Benchmark 18.4: Microsoft Security Guide Hardening"

        # 18.4.1 Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'
        Write-Output "Step 1: Apply UAC restrictions to local accounts on network logons"
        Try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
                -Name "LocalAccountTokenFilterPolicy" -Value 0 -Type DWord
            Write-Output "UAC restrictions applied successfully."
            LogMessage "UAC restrictions applied successfully."
        } Catch {
            Write-Error "Failed to apply UAC restrictions: $_"
            LogMessage "Failed to apply UAC restrictions: $_"
        }

        # 18.4.2 Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'
        Write-Output "Step 2: Configure RPC packet level privacy setting"
        Try {
            If (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Force
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" `
                -Name "RestrictRemoteClients" -Value 1 -Type DWord
            Write-Output "RPC packet level privacy setting configured successfully."
            LogMessage "RPC packet level privacy setting configured successfully."
        } Catch {
            Write-Error "Failed to configure RPC packet level privacy: $_"
            LogMessage "Failed to configure RPC packet level privacy: $_"
        }

        # 18.4.3 Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)'
        Write-Output "Step 3: Disable SMB v1 client driver"
        Try {
            If (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10")) {
                New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Force
            }
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" `
                -Name "Start" -Value 4 -Type DWord
            Write-Output "SMB v1 client driver disabled successfully."
            LogMessage "SMB v1 client driver disabled successfully."
        } Catch {
            Write-Error "Failed to disable SMB v1 client driver: $_"
            WLogMessage "Failed to disable SMB v1 client driver: $_"
        }

        # 18.4.4 Ensure 'Configure SMB v1 server' is set to 'Disabled'
        Write-Output "Step 4: Disable SMB v1 server"
        Try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
                -Name "SMB1" -Value 0 -Type DWord
            Write-Output "SMB v1 server disabled successfully."
            LogMessage "SMB v1 server disabled successfully."
        } Catch {
            Write-Error "Failed to disable SMB v1 server: $_"
            LogMessage "Failed to disable SMB v1 server: $_"
        }

        # 18.4.5 Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'
        Write-Output "Step 5: Enable SEHOP"
        Try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" `
                -Name "DisableExceptionChainValidation" -Value 0 -Type DWord
            Write-Output "SEHOP enabled successfully."
            LogMessage "SEHOP enabled successfully."
        } Catch {
            Write-Error "Failed to enable SEHOP: $_"
            LogMessage "Failed to enable SEHOP: $_"
        }

        # 18.4.6 Ensure 'LSA Protection' is set to 'Enabled'
        Write-Output "Step 6: Enable LSA Protection"
        Try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
                -Name "RunAsPPL" -Value 1 -Type DWord
            Write-Output "LSA Protection enabled successfully."
            LogMessage "LSA Protection enabled successfully."
        } Catch {
            Write-Error "Failed to enable LSA Protection: $_"
            LogMessage "Failed to enable LSA Protection: $_"
        }

        # 18.4.7 Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)'
        Write-Output "Step 7: Configure NetBT NodeType to P-node"
        Try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" `
                -Name "NodeType" -Value 2 -Type DWord
            Write-Output "NetBT NodeType configured to P-node successfully."
            LogMessage "NetBT NodeType configured to P-node successfully."
        } Catch {
            Write-Error "Failed to configure NetBT NodeType: $_"
            LogMessage "Failed to configure NetBT NodeType: $_"
        }

        # 18.4.8 Ensure 'WDigest Authentication' is set to 'Disabled'
        Write-Output "Step 8: Disable WDigest Authentication"
        Try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
                -Name "UseLogonCredential" -Value 0 -Type DWord
            Write-Output "WDigest Authentication disabled successfully."
            LogMessage "WDigest Authentication disabled successfully."
        } Catch {
            Write-Error "Failed to disable WDigest Authentication: $_"
            LogMessage "Failed to disable WDigest Authentication: $_"
        }

        # Verification
        Write-Output "Step 9: Verifying Applied Settings"
        $settings = @(
            @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "LocalAccountTokenFilterPolicy"; Value = 0; Desc = "UAC restrictions" }
            @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"; Name = "RestrictRemoteClients"; Value = 1; Desc = "RPC packet level privacy" }
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"; Name = "Start"; Value = 4; Desc = "SMB v1 Client Driver" }
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name = "SMB1"; Value = 0; Desc = "SMB v1 Server" }
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"; Name = "DisableExceptionChainValidation"; Value = 0; Desc = "SEHOP" }
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "RunAsPPL"; Value = 1; Desc = "LSA Protection" }
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"; Name = "NodeType"; Value = 2; Desc = "NetBT NodeType" }
            @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; Name = "UseLogonCredential"; Value = 0; Desc = "WDigest Authentication" }
        )
        Foreach ($setting in $settings) {
            Try {
                $currentValue = (Get-ItemProperty -Path $setting.Path -Name $setting.Name).$($setting.Name)
                If ($currentValue -eq $setting.Value) {
                    Write-Output "Verification Passed: $($setting.Desc)"
                    LogMessage "Verification Passed: $($setting.Desc)"
                } Else {
                    Write-Error "Verification Failed: $($setting.Desc)"
                    LogMessage "Verification Failed: $($setting.Desc)"
                }
            } Catch {
                Write-Error "Verification Failed: $($setting.Desc) - $_"
                LogMessage "Verification Failed: $($setting.Desc) - $_"
            }
        }

        Write-Output "CIS Benchmark 18.4: Microsoft Security Guide Hardening Complete."
        LogMessage "CIS Benchmark 18.4: Microsoft Security Guide Hardening Complete."


        # --------
        # 18_5
        # --------
        Write-Output "Starting CIS Benchmark 18.5: MSS (Legacy) Hardening"

        # 18.5.1 Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'
        Write-Output "Step 1: Disable Automatic Logon"
        Try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value 0 -Type String
            Write-Output "Automatic Logon disabled successfully."
        } Catch {
            Write-Error "Failed to disable Automatic Logon: $_"
            LogMessage "Failed to disable Automatic Logon: $_"
        }

        # 18.5.2 Ensure 'MSS: (DisableIPSourceRouting IPv6)' is set to 'Enabled: Highest protection'
        Write-Output "Step 2: Disable IP Source Routing IPv6"
        Try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type DWord
            Write-Output "IP Source Routing IPv6 disabled successfully."
        } Catch {
            Write-Error "Failed to disable IP Source Routing IPv6: $_"
            LogMessage "Failed to disable IP Source Routing IPv6: $_"
        }

        # 18.5.3 Ensure 'MSS: (DisableIPSourceRouting)' is set to 'Enabled: Highest protection'
        Write-Output "Step 3: Disable IP Source Routing"
        Try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type DWord
            Write-Output "IP Source Routing disabled successfully."
        } Catch {
            Write-Error "Failed to disable IP Source Routing: $_"
            LogMessage "Failed to disable IP Source Routing: $_"
        }

        # 18.5.4 Ensure 'MSS: (DisableSavePassword)' is set to 'Enabled'
        Write-Output "Step 4: Prevent Dial-up Password Save"
        Try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableSavePassword" -Value 1 -Type DWord
            Write-Output "Dial-up Password Save prevention enabled successfully."
        } Catch {
            Write-Error "Failed to prevent Dial-up Password Save: $_"
            LogMessage "Failed to prevent Dial-up Password Save: $_"
        }

        # 18.5.5 Ensure 'MSS: (EnableICMPRedirect)' is set to 'Disabled'
        Write-Output "Step 5: Disable ICMP Redirects"
        Try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Value 0 -Type DWord
            Write-Output "ICMP Redirects disabled successfully."
        } Catch {
            Write-Error "Failed to disable ICMP Redirects: $_"
            WLogMessage "Failed to disable ICMP Redirects: $_"
        }

        # 18.5.6 Ensure 'MSS: (KeepAliveTime)' is set to '300,000'
        Write-Output "Step 6: Configure KeepAliveTime"
        Try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "KeepAliveTime" -Value 300000 -Type DWord
            Write-Output "KeepAliveTime configured successfully."
        } Catch {
            Write-Error "Failed to configure KeepAliveTime: $_"
            LogMessage "Failed to configure KeepAliveTime: $_"
        }

        # 18.5.7 Ensure 'MSS: (NoNameReleaseOnDemand)' is set to 'Enabled'
        Write-Output "Step 7: Enable NoNameReleaseOnDemand"
        Try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NoNameReleaseOnDemand" -Value 1 -Type DWord
            Write-Output "NoNameReleaseOnDemand enabled successfully."
        } Catch {
            Write-Error "Failed to enable NoNameReleaseOnDemand: $_"
            LogMessage "Failed to enable NoNameReleaseOnDemand: $_"
        }

        # 18.5.8 Ensure 'MSS: (PerformRouterDiscovery)' is set to 'Disabled'
        Write-Output "Step 8: Disable Router Discovery"
        Try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "PerformRouterDiscovery" -Value 0 -Type DWord
            Write-Output "Router Discovery disabled successfully."
        } Catch {
            Write-Error "Failed to disable Router Discovery: $_"
            LogMessage "Failed to disable Router Discovery: $_"
        }

        # 18.5.9 Ensure 'MSS: (SafeDllSearchMode)' is set to 'Enabled'
        Write-Output "Step 9: Enable Safe DLL Search Mode"
        Try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode" -Value 1 -Type DWord
            Write-Output "Safe DLL Search Mode enabled successfully."
        } Catch {
            Write-Error "Failed to enable Safe DLL Search Mode: $_"
            LogMessage "Failed to enable Safe DLL Search Mode: $_"
        }

        # 18.5.10 Ensure 'MSS: (ScreenSaverGracePeriod)' is set to 'Enabled: 5 or fewer seconds'
        Write-Output "Step 10: Configure ScreenSaverGracePeriod"
        Try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ScreenSaverGracePeriod" -Value 5 -Type String
            Write-Output "ScreenSaverGracePeriod configured successfully."
        } Catch {
            Write-Error "Failed to configure ScreenSaverGracePeriod: $_"
            LogMessage "Failed to configure ScreenSaverGracePeriod: $_"
        }

        # 18.5.11 Ensure 'MSS: (TcpMaxDataRetransmissions IPv6)' is set to 'Enabled: 3'
        Write-Output "Step 11: Configure TcpMaxDataRetransmissions IPv6"
        Try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "TcpMaxDataRetransmissions" -Value 3 -Type DWord
            Write-Output "TcpMaxDataRetransmissions IPv6 configured successfully."
        } Catch {
            Write-Error "Failed to configure TcpMaxDataRetransmissions IPv6: $_"
            LogMessage "Failed to configure TcpMaxDataRetransmissions IPv6: $_"
        }

        # 18.5.12 Ensure 'MSS: (TcpMaxDataRetransmissions)' is set to 'Enabled: 3'
        Write-Output "Step 12: Configure TcpMaxDataRetransmissions"
        Try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxDataRetransmissions" -Value 3 -Type DWord
            Write-Output "TcpMaxDataRetransmissions configured successfully."
        } Catch {
            Write-Error "Failed to configure TcpMaxDataRetransmissions: $_"
            LogMessage "Failed to configure TcpMaxDataRetransmissions: $_"
        }

        # 18.5.13 Ensure 'MSS: (WarningLevel)' is set to 'Enabled: 90% or less'
        Write-Output "Step 13: Configure WarningLevel"
        Try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "WarningLevel" -Value 90 -Type DWord
            Write-Output "WarningLevel configured successfully."
        } Catch {
            Write-Error "Failed to configure WarningLevel: $_"
            LogMessage "Failed to configure WarningLevel: $_"
        }

        Write-Output "CIS Benchmark 18.5: MSS (Legacy) Hardening Complete."
        LogMessage "CIS Benchmark 18.5: MSS (Legacy) Hardening Complete."

        
        # ---------
        # 18_6_4-10
        # ---------
        Write-Output "Starting CIS Benchmark 18.6 Hardening"

        # 18.6.4.1 Ensure 'Configure NetBIOS settings' is set to 'Disable NetBIOS name resolution on public networks'
        Write-Output "Step 1: Disable NetBIOS name resolution on public networks"
        Try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" -Name "NetbiosOptions" -Value 2 -Type DWord
            Write-Output "NetBIOS name resolution disabled successfully on public networks."
        } Catch {
            Write-Error "Failed to disable NetBIOS name resolution: $_"
        }

        # 18.6.4.2 Ensure 'Turn off multicast name resolution' is set to 'Enabled'
        Write-Output "Step 2: Turn off multicast name resolution"
        Try {
            If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord
            Write-Output "Multicast name resolution disabled successfully."
        } Catch {
            Write-Error "Failed to disable multicast name resolution: $_"
        }

        # 18.6.5.1 Ensure 'Enable Font Providers' is set to 'Disabled'
        Write-Output "Step 3: Disable Font Providers"
        Try {
            If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Font Drivers")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Font Drivers" -Force | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Font Drivers" -Name "EnableFontProviders" -Value 0 -Type DWord
            Write-Output "Font Providers disabled successfully."
        } Catch {
            Write-Error "Failed to disable Font Providers: $_"
        }

        # 18.6.8.1 Ensure 'Enable insecure guest logons' is set to 'Disabled'
        Write-Output "Step 4: Disable insecure guest logons"
        Try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "AllowInsecureGuestAuth" -Value 0 -Type DWord
            Write-Output "Insecure guest logons disabled successfully."
        } Catch {
            Write-Error "Failed to disable insecure guest logons: $_"
        }

        # 18.6.9.1 Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'
        Write-Output "Step 5: Disable Mapper I/O (LLTDIO) driver"
        Try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LLTDIO" -Name "Start" -Value 4 -Type DWord
            Write-Output "Mapper I/O (LLTDIO) driver disabled successfully."
        } Catch {
            Write-Error "Failed to disable Mapper I/O (LLTDIO) driver: $_"
        }

        # 18.6.9.2 Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'
        Write-Output "Step 6: Disable Responder (RSPNDR) driver"
        Try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RSPNDR" -Name "Start" -Value 4 -Type DWord
            Write-Output "Responder (RSPNDR) driver disabled successfully."
        } Catch {
            Write-Error "Failed to disable Responder (RSPNDR) driver: $_"
        }

        # 18.6.10.2 Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'
        Write-Output "Step 7: Disable Microsoft Peer-to-Peer Networking Services"
        Try {
            If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Peernet")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" -Force | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" -Name "Disabled" -Value 1 -Type DWord
            Write-Output "Microsoft Peer-to-Peer Networking Services disabled successfully."
        } Catch {
            Write-Error "Failed to disable Microsoft Peer-to-Peer Networking Services: $_"
        }

        Write-Output "CIS Benchmark 18.6 Hardening Complete."
        LogMessage "CIS Benchmark 18.6 Hardening Complete."

        # --------
        # 18_6_11
        # --------
        Write-Host "Starting Windows Defender Firewall configuration..."

        # 18.6.11.1 Ensure Windows Defender Firewall is enabled using netsh for compatibility
        try {
            netsh advfirewall set allprofiles state on
            Write-Host "Windows Defender Firewall is enabled for all profiles." -ForegroundColor Green
        } catch {
            Write-Host "Error enabling Windows Defender Firewall: $_" -ForegroundColor Red
        }

        # 18.6.11.2 Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is enabled
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -Value 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NoNetBridge" -Value 1
            Write-Host "Network Bridge configuration is prohibited." -ForegroundColor Green
        } catch {
            Write-Host "Error configuring Network Bridge: $_" -ForegroundColor Red
        }

        # 18.6.11.3 Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is enabled
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "ICSharing" -Value 0
            Write-Host "Internet Connection Sharing is prohibited." -ForegroundColor Green
        } catch {
            Write-Host "Error configuring Internet Connection Sharing: $_" -ForegroundColor Red
        }

        # 18.6.11.4 Ensure 'Require domain users to elevate when setting a network's location' is enabled
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "RequireElevatedNetworkLocation" -Value 1
            Write-Host "Domain users will be required to elevate when setting a network's location." -ForegroundColor Green
        } catch {
            Write-Host "Error requiring elevation for network location: $_" -ForegroundColor Red
        }

        # Output the current settings for verification
        Write-Host "Verifying configuration..."

        try {
            # Verifying network configuration settings
            $networkSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" | Select-Object NC_ShowSharedAccessUI, NoNetBridge, ICSharing, RequireElevatedNetworkLocation
            Write-Host "Network Configuration Settings:" -ForegroundColor Cyan
            $networkSettings | Format-Table -AutoSize
        } catch {
            Write-Host "Error retrieving configuration settings: $_" -ForegroundColor Red
        }

        Write-Host "Script execution completed." -ForegroundColor Yellow
        LogMessage "Script execution completed." 

        # ----------
        # 18_6_14-23
        # ----------
        Write-Host "Starting CIS Benchmark Hardening..."

        # 18.6.14.1 Hardened UNC Paths configuration
        Write-Host "Configuring Hardened UNC Paths..."
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "HardenedUNCPaths" -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireMutualAuthentication" -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireIntegrity" -Value 1
            Write-Host "Hardened UNC Paths configured successfully." -ForegroundColor Green
        } catch {
            Write-Host "Error configuring Hardened UNC Paths: $_" -ForegroundColor Red
        }

        # 18.6.19.2.1 Disable IPv6 by setting DisabledComponents
        Write-Host "Disabling IPv6..."
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 0xff
            Write-Host "IPv6 disabled successfully." -ForegroundColor Green
        } catch {
            Write-Host "Error disabling IPv6: $_" -ForegroundColor Red
        }

        # 18.6.20.1 Disable configuration of wireless settings using Windows Connect Now
        Write-Host "Disabling Windows Connect Now wireless configuration..."
        try {
            # Check if the Wcn registry path exists, if not, create it
            $wcnPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Wcn"
            if (-not (Test-Path $wcnPath)) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "Wcn" -Force
            }
            Set-ItemProperty -Path $wcnPath -Name "Enabled" -Value 0
            Write-Host "Windows Connect Now wireless configuration disabled." -ForegroundColor Green
        } catch {
            Write-Host "Error disabling Windows Connect Now wireless configuration: $_" -ForegroundColor Red
        }

        # 18.6.20.2 Prohibit access of Windows Connect Now wizards
        Write-Host "Prohibiting access to Windows Connect Now wizards..."
        try {
            # Ensure the Wcn path exists and create it if needed
            if (-not (Test-Path $wcnPath)) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "Wcn" -Force
            }
            Set-ItemProperty -Path $wcnPath -Name "ProhibitWizards" -Value 1
            Write-Host "Access to Windows Connect Now wizards prohibited." -ForegroundColor Green
        } catch {
            Write-Host "Error prohibiting access to Windows Connect Now wizards: $_" -ForegroundColor Red
        }

        # 18.6.21.1 Minimize the number of simultaneous connections (Prevent Wi-Fi when on Ethernet)
        Write-Host "Configuring simultaneous connections limitation..."
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "LimitConnections" -Value 3
            Write-Host "Simultaneous connections minimized to 3." -ForegroundColor Green
        } catch {
            Write-Host "Error configuring simultaneous connections limitation: $_" -ForegroundColor Red
        }

        # 18.6.21.2 Prohibit connection to non-domain networks when on domain network
        Write-Host "Prohibiting connection to non-domain networks when on domain network..."
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "ProhibitNonDomain" -Value 1
            Write-Host "Prohibited connection to non-domain networks when on domain network." -ForegroundColor Green
        } catch {
            Write-Host "Error prohibiting connection to non-domain networks: $_" -ForegroundColor Red
        }

        # 18.6.23.2.1 Disable automatic connection to open hotspots, networks shared by contacts, and paid hotspots
        Write-Host "Disabling automatic connection to open hotspots and shared networks..."
        try {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "AutoConnectHotspot" -Value 0
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "AutoConnectShared" -Value 0
            Write-Host "Automatic connection to open hotspots and shared networks disabled." -ForegroundColor Green
        } catch {
            Write-Host "Error disabling automatic connection to hotspots and shared networks: $_" -ForegroundColor Red
        }

        Write-Host "CIS Benchmark Hardening Script completed." -ForegroundColor Yellow
        LogMessage "CIS Benchmark Hardening Script completed." 


        # ------
        # 18_7
        # ------
        Write-Host "Starting CIS Benchmark 18.7 Printers Hardening..."

        # Function to create registry path if it doesn't exist
        function Ensure-RegistryPath {
            param (
                [string]$Path
            )
            if (-not (Test-Path $Path)) {
                Write-Host "Creating missing registry path: $Path"
                New-Item -Path $Path -Force
            }
        }

        # 18.7.1 Disable "Allow Print Spooler to accept client connections"
        Write-Host "Disabling Print Spooler client connections..."
        try {
            Set-Service -Name "Spooler" -StartupType Disabled
            Stop-Service -Name "Spooler" -Force
            Write-Host "Print Spooler client connections disabled." -ForegroundColor Green
        } catch {
            Write-Host "Error disabling Print Spooler client connections: $_" -ForegroundColor Red
        }

        # 18.7.2 Enable "Configure Redirection Guard"
        Write-Host "Enabling Redirection Guard..."
        $redirectionGuardPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
        Ensure-RegistryPath -Path $redirectionGuardPath
        try {
            Set-ItemProperty -Path $redirectionGuardPath -Name "RedirectionGuard" -Value 1
            Write-Host "Redirection Guard enabled." -ForegroundColor Green
        } catch {
            Write-Host "Error enabling Redirection Guard: $_" -ForegroundColor Red
        }

        # 18.7.3 Enable "Configure RPC connection settings: Protocol to use for outgoing RPC connections"
        Write-Host "Enabling RPC over TCP for outgoing RPC connections..."
        $rpcPath = "HKLM:\SOFTWARE\Policies\Microsoft\RPC"
        Ensure-RegistryPath -Path $rpcPath
        try {
            Set-ItemProperty -Path $rpcPath -Name "UseRpcOverTcp" -Value 1
            Write-Host "RPC over TCP for outgoing connections enabled." -ForegroundColor Green
        } catch {
            Write-Host "Error enabling RPC over TCP: $_" -ForegroundColor Red
        }

        # 18.7.4 Enable "Configure RPC connection settings: Use authentication for outgoing RPC connections"
        Write-Host "Enabling authentication for outgoing RPC connections..."
        try {
            Set-ItemProperty -Path $rpcPath -Name "AuthenticationRequired" -Value 1
            Write-Host "Authentication for outgoing RPC connections enabled." -ForegroundColor Green
        } catch {
            Write-Host "Error enabling authentication for outgoing RPC connections: $_" -ForegroundColor Red
        }

        # 18.7.5 Enable "Configure RPC listener settings: Protocols to allow for incoming RPC connections"
        Write-Host "Enabling RPC over TCP for incoming RPC connections..."
        try {
            Set-ItemProperty -Path $rpcPath -Name "AllowTcp" -Value 1
            Write-Host "RPC over TCP for incoming RPC connections enabled." -ForegroundColor Green
        } catch {
            Write-Host "Error enabling RPC over TCP for incoming connections: $_" -ForegroundColor Red
        }

        # 18.7.6 Enable "Configure RPC listener settings: Authentication protocol to use for incoming RPC connections"
        Write-Host "Enabling Negotiate for authentication of incoming RPC connections..."
        try {
            Set-ItemProperty -Path $rpcPath -Name "AuthenticationProtocol" -Value "Negotiate"
            Write-Host "Negotiate authentication for incoming RPC connections enabled." -ForegroundColor Green
        } catch {
            Write-Host "Error enabling Negotiate authentication for incoming RPC connections: $_" -ForegroundColor Red
        }

        # 18.7.7 Enable "Configure RPC over TCP port"
        Write-Host "Setting RPC over TCP port to 0..."
        try {
            Set-ItemProperty -Path $rpcPath -Name "TcpPort" -Value 0
            Write-Host "RPC over TCP port set to 0." -ForegroundColor Green
        } catch {
            Write-Host "Error setting RPC over TCP port: $_" -ForegroundColor Red
        }

        # 18.7.8 Enable "Limit print driver installation to Administrators"
        Write-Host "Limiting print driver installation to Administrators..."
        $printerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
        Ensure-RegistryPath -Path $printerPath
        try {
            Set-ItemProperty -Path $printerPath -Name "LimitDriverInstallationToAdmins" -Value 1
            Write-Host "Print driver installation limited to Administrators." -ForegroundColor Green
        } catch {
            Write-Host "Error limiting print driver installation: $_" -ForegroundColor Red
        }

        # 18.7.9 Enable "Manage processing of Queue-specific files"
        Write-Host "Limiting Queue-specific files to Color profiles..."
        try {
            Set-ItemProperty -Path $printerPath -Name "LimitQueueSpecificFiles" -Value "ColorProfiles"
            Write-Host "Queue-specific files limited to Color profiles." -ForegroundColor Green
        } catch {
            Write-Host "Error limiting Queue-specific files: $_" -ForegroundColor Red
        }

        # 18.7.10 Enable "Point and Print Restrictions: When installing drivers for a new connection"
        Write-Host "Enabling warning and elevation prompt for new driver installation..."
        try {
            Set-ItemProperty -Path $printerPath -Name "PointAndPrintNewDriverWarning" -Value 1
            Write-Host "Warning and elevation prompt for new driver installation enabled." -ForegroundColor Green
        } catch {
            Write-Host "Error enabling warning for new driver installation: $_" -ForegroundColor Red
        }

        # 18.7.11 Enable "Point and Print Restrictions: When updating drivers for an existing connection"
        Write-Host "Enabling warning and elevation prompt for updating drivers..."
        try {
            Set-ItemProperty -Path $printerPath -Name "PointAndPrintUpdateDriverWarning" -Value 1
            Write-Host "Warning and elevation prompt for updating drivers enabled." -ForegroundColor Green
        } catch {
            Write-Host "Error enabling warning for updating drivers: $_" -ForegroundColor Red
        }

        Write-Host "CIS Benchmark 18.7 Printers Hardening Script completed." -ForegroundColor Yellow
        LogMessage "CIS Benchmark 18.7 Printers Hardening Script completed." 

        # ------
        # 18_8
        # ------
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
        LogMessage "CIS Benchmark 18.8.1.1 Hardening Script completed." 


    } else {
        Write-Output "Skipped Module 18 Scripts!"
    }

    $runModule19Script = Read-Host "Do you wanna run all Module 19 scripts? (y/n): "
    if ($runModule18Script -match "^[yY]$") {

        # === Module 19 Scripts ===
        LogMessage "Configuring Module 19..."

        ## --------------------------
        # 19.1.3.1 Enable Screen Saver
        # --------------------------
        Write-Output "Enforcing: Enable Screen Saver"
        $screenSaverPath = "HKCU:\Control Panel\Desktop"
        if (Test-Path $screenSaverPath) {
            Set-ItemProperty -Path $screenSaverPath -Name "ScreenSaveActive" -Value 1
            Write-Output "Screen Saver Enabled."
            LogMessage "Screen Saver Enabled."
        } else {
            Write-Output "Path $screenSaverPath not found."
            LogMessage "Path $screenSaverPath not found."
        }

        # --------------------------
        # 19.1.3.2 Password Protect the Screen Saver
        # --------------------------
        Write-Output "Enforcing: Password Protect the Screen Saver"
        if (Test-Path $screenSaverPath) {
            Set-ItemProperty -Path $screenSaverPath -Name "ScreenSaverIsSecure" -Value 1
            Write-Output "Password protection for Screen Saver Enabled."
            LogMessage "Password protection for Screen Saver Enabled."
        } else {
            Write-Output "Path $screenSaverPath not found."
            LogMessage "Path $screenSaverPath not found."
        }

        # --------------------------
        # 19.1.3.3 Screen Saver Timeout
        # --------------------------
        Write-Output "Enforcing: Screen Saver Timeout to 900 seconds"
        if (Test-Path $screenSaverPath) {
            Set-ItemProperty -Path $screenSaverPath -Name "ScreenSaveTimeOut" -Value 900
            Write-Output "Screen Saver Timeout set to 900 seconds."
            LogMessage "Screen Saver Timeout set to 900 seconds."
        } else {
            Write-Output "Path $screenSaverPath not found."
            LogMessage "Path $screenSaverPath not found."
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
        LogMessage "Toast notifications on the lock screen disabled."

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
        LogMessage "Help Experience Improvement Program disabled."

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
        LogMessage "Zone information will not be preserved in file attachments."

        # --------------------------
        # 19.7.4.2 Notify antivirus programs when opening attachments
        # --------------------------
        Write-Output "Enforcing: Notify antivirus programs when opening attachments"
        if (!(Test-Path $attachmentsPath)) {
            New-Item -Path $attachmentsPath -Force | Out-Null
        }
        Set-ItemProperty -Path $attachmentsPath -Name "ScanWithAntiVirus" -Value 1
        Write-Output "Antivirus notification enabled for file attachments."
        LogMessage "Antivirus notification enabled for file attachments."

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
        LogMessage "Windows Spotlight on lock screen disabled."

        # --------------------------
        # 19.7.7.2 Do not suggest third-party content in Windows spotlight
        # --------------------------
        Write-Output "Enforcing: Disable third-party content in Windows Spotlight"
        if (!(Test-Path $spotlightPath)) {
            New-Item -Path $spotlightPath -Force | Out-Null
        }
        Set-ItemProperty -Path $spotlightPath -Name "DisableThirdPartySuggestions" -Value 1
        Write-Output "Third-party suggestions in Windows Spotlight disabled."
        LogMessage "Third-party suggestions in Windows Spotlight disabled."

        LogMessage "MODULE 19 CONFIGURATION COMPLETED"
        LogMessage "-----------------------------------------------------------------------------"
        Write-Output "-----------------------------------------------------------------------------------------------------------"
    } else {
        Write-Output "Skipped Module 19 Scripts!"
    }

    # -------------------------------------
    # 3. System Hardening Scripts Execution
    # -------------------------------------
    
    $runHardeningScripts = Read-Host "Do you wanna run other windows hardening scripts? (y/n): "
    if ($runHardeningScripts -match "^[yY]$") { 

        # === User Right Assignment ===
        # Define the path to the security template
        $templatePath = "./yes.inf"

        # Check if the template file exists
        if (Test-Path $templatePath) {
            # Apply the security template
            secedit /configure /db secedit.sdb /cfg $templatePath /areas USER_RIGHTS /quiet
            
            # Output the result of the operation
            Write-Output "User rights assignment has been updated according to the template."
            LogMessage "User rights assignment has been updated according to the template."
        } else {
            Write-Error "The specified template file was not found."
            LogMessage "The specified template file was not found."
        }

        # === Auditing ===
        # Set all audit policy subcategories to log both success and failure
        $auditSubcategories = auditpol /get /category:* /r | ConvertFrom-Csv -Delimiter "," | Where-Object { $_."Subcategory" -ne "" } | Select-Object -ExpandProperty "Subcategory GUID"

        foreach ($subcategory in $auditSubcategories) {
            auditpol /set /subcategory:$subcategory /success:enable /failure:enable
        }

        # Output the result of the operation
        Write-Output "All audit policies have been updated to audit both success and failure."
        LogMessage "All audit policies have been updated to audit both success and failure."

        # === Autoplay ===
        # Define the registry paths for "Turn off Autoplay" Group Policy settings
        $explorerPolicyPath = "HKLM:\Software\Policies\Microsoft\Windows\Explorer"
        $autoplayHandlersPolicyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

        # Create the registry path if it doesn't already exist
        if (!(Test-Path $explorerPolicyPath)) {
            New-Item -Path $explorerPolicyPath -Force | Out-Null
        }

        if (!(Test-Path $autoplayHandlersPolicyPath)) {
            New-Item -Path $autoplayHandlersPolicyPath -Force | Out-Null
        }

        # Set "NoDriveTypeAutoRun" to 255 (0xFF) to disable Autoplay for all drives
        Set-ItemProperty -Path $explorerPolicyPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord
        Set-ItemProperty -Path $autoplayHandlersPolicyPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord

        # Enforce the "Turn off Autoplay" policy by setting "NoAutoPlay" to 1
        Set-ItemProperty -Path $explorerPolicyPath -Name "NoAutoPlay" -Value 1 -Type DWord

        Write-Output "The 'Turn off Autoplay' policy has been set to 'Enabled' for all drives in Group Policy."
        LogMessage "The 'Turn off Autoplay' policy has been set to 'Enabled' for all drives in Group Policy."

        # === Password Changer ===
        # Loop until the user types "done"
        Write-Output "Now running Password Changer"
        do {
            # Prompt for the username
            $username = Read-Host "Enter the username (or type 'done' to finish)"

            # Check if the user wants to exit
            if ($username -ne "done") {
                try {
                    # Set the user's password
                    $password = ConvertTo-SecureString "CyberPatriot@2024" -AsPlainText -Force
                    Set-LocalUser -Name $username -Password $password

                    # Confirm success
                    Write-Host "Password for user '$username' has been successfully set to 'CyberPatriot@2024'." -ForegroundColor Green
                } catch {
                    # Handle errors (e.g., user not found)
                    Write-Host "Error: Unable to set password for user '$username'. Please ensure the username is correct." -ForegroundColor Red
                }
            }
        } while ($username -ne "done")

        Write-Host "Script completed. No more changes made. PASSWORD = 'CyberPatriot@2024'" -ForegroundColor Yellow
        LogMessage "Script completed. No more changes made. PASSWORD = 'CyberPatriot@2024'" 

    } else {
        Write-Output "Skipped other windows hardening scripts!"
    }

    # -----------------------------------------------------------------------------------------------
    # 4. CIS Windows 11 v3.0 (Github Scripts ~@TheTechBeast8)
    #    https://github.com/TheTechBeast8/HardeningAudit/tree/main/
    # -----------------------------------------------------------------------------------------------
    $runCIS_w11_Scripts = Read-Host "Do you wanna run all the Windows 11 deployment scripts? (y/n to confirm)"
    if ($runCIS_w11_Scripts -match "^[yY]$") {
        LogMessage "Running all the devolopemt scripts one by one..."

        #Script Paths
        $bitlocker = "./CIS-Win11-v3.0/Deployment/Bitlocker.ps1"
        $L1 = "./CIS-Win11-v3.0/Deployment/L1.ps1"
        $L1_Bitlocker = "./CIS-Win11-v3.0/Deployment/L1+Bitlocker.ps1"
        $L2 = "./CIS-Win11-v3.0/Deployment/L2.ps1"
        $L2_Bitlocker = "./CIS-Win11-v3.0/Deployment/L2+Bitlocker.ps1"

        #Execution
        Write-Output "Running Bitlocker..."
        try {
            & $bitlocker
            LogMessage "Bitlocker Ran Successfully!"
        } catch {
            LogMessage "Error running the script: $_"
            Write-Output "Error running the script: $_"
        }

        Write-Output "Running L1..."
        try {
            & $L1
            LogMessage "Bitlocker Ran Successfully!"
        } catch {
            LogMessage "Error running the script: $_"
            Write-Output "Error running the script: $_"
        }

        Write-Output "Running L1+Bitlocker..."
        try {
            & $L1_Bitlocker
            LogMessage "Bitlocker Ran Successfully!"
        } catch {
            LogMessage "Error running the script: $_"
            Write-Output "Error running the script: $_"
        }

        Write-Output "Running L2..."
        try {
            & $L2
            LogMessage "Bitlocker Ran Successfully!"
        } catch {
            LogMessage "Error running the script: $_"
            Write-Output "Error running the script: $_"
        }

        Write-Output "Running L2+Bitlocker..."
        try {
            & $L2_Bitlocker
            LogMessage "Bitlocker Ran Successfully!"
        } catch {
            LogMessage "Error running the script: $_"
            Write-Output "Error running the script: $_"
        }

        Write-Output "All Deployment scripts ran successfully!"      
        LogMessage "All Deployment scripts ran successfully!"
    }

    # -----------------------------------------------------------------------------------------------
    # 5. CIS Server 2019 v3.0 (Github Scripts ~@TheTechBeast8)
    #    https://github.com/TheTechBeast8/HardeningAudit/tree/main/
    # -----------------------------------------------------------------------------------------------
    $runCIS_serv19_Scripts = Read-Host "Do you wanna run all the Server 2019 deployment scripts? (y/n to confirm)"
    if ($runCIS_serv19_Scripts -match "^[yY]$") {
        LogMessage "Running all the devolopemt scripts one by one..."

        #Script Paths
        $L1_DC = "./CIS-serv2019-v3.0.1/Deployment/L1_DC.ps1"
        $L1_MC = "./CIS-serv2019-v3.0.1/Deployment/L1_MS.ps1"
        $L2_DC = "./CIS-serv2019-v3.0.1/Deployment/L2_DC.ps1"
        $L2_MC = "./CIS-serv2019-v3.0.1/Deployment/L2_MC.ps1"
        $NG_DC = "./CIS-serv2019-v3.0.1/Deployment/NG_DC.ps1"
        $NG_MC = "./CIS-serv2019-v3.0.1/Deployment/NG_MS.ps1"

        #Execution
        Write-Output "Running L1_DC..."
        try {
            & $L1_DC
            LogMessage "L1_DC Ran Successfully!"
        } catch {
            LogMessage "Error running the script: $_"
            Write-Output "Error running the script: $_" -ForegroundColor Red
        }

        Write-Output "Running L1_MC..."
        try {
            & $L1_MC
            LogMessage "L1_MC Ran Successfully!"
        } catch {
            LogMessage "Error running the script: $_"
            Write-Output "Error running the script: $_" -ForegroundColor Red
        }

        Write-Output "Running L2_DC..."
        try {
            & $L1_DC
            LogMessage "L2_DC Ran Successfully!"
        } catch {
            LogMessage "Error running the script: $_"
            Write-Output "Error running the script: $_" -ForegroundColor Red
        }

        Write-Output "Running L1_MC..."
        try {
            & $L1_MC
            LogMessage "L1_MC Ran Successfully!"
        } catch {
            LogMessage "Error running the script: $_"
            Write-Output "Error running the script: $_" -ForegroundColor Red
        }

        Write-Output "Running NG_DC..."
        try {
            & $NG_DC
            LogMessage "NG_DC Ran Successfully!"
        } catch {
            LogMessage "Error running the script: $_"
            Write-Output "Error running the script: $_" -ForegroundColor Red
        }

        Write-Output "Running NG_MC..."
        try {
            & $NG_MC
            LogMessage "NG_MC Ran Successfully!"
        } catch {
            LogMessage "Error running the script: $_"
            Write-Output "Error running the script: $_" -ForegroundColor Red
        }

        Write-Output "All Deployment scripts ran successfully!"      
        LogMessage "All Deployment scripts ran successfully!"
    }

    # -----------------------------------------------------------------------------------------------
    # 6. Windows Server Related Hardening (But can also be ran on normal windows image for hardening)
    # -----------------------------------------------------------------------------------------------

    # === Windows Server Goose Script ===
    $runGoose= Read-Host "Do you want to run the GOOSE script? (y/n to confirm)"
    if ($runGoose -match "^[yY]$") {
        # Function to safely set registry properties
    function Set-RegistryProperty {
        param (
            [string]$Path,
            [string]$Name,
            [Object]$Value
        )
        if (Test-Path $Path) {
            try {
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -ErrorAction Stop
                Write-Output "Successfully set $Name at $Path."
            } catch {
                Write-Output ("Failed to set {0} at {1}. Error: {2}" -f $Name, $Path, $_)
            }
        } else {
            Write-Output "Registry path not found: $Path"
        }
    }

    # Function to safely configure services
    function Configure-Service {
        param (
            [string]$ServiceName,
            [string]$StartupType,
            [bool]$StartService = $false
        )
        if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
            try {
                Set-Service -Name $ServiceName -StartupType $StartupType -ErrorAction Stop
                Write-Output "Set $ServiceName startup type to $StartupType."
                if ($StartService) {
                    Start-Service -Name $ServiceName -ErrorAction Stop
                    Write-Output "Started $ServiceName."
                }
            } catch {
                Write-Output ("Failed to configure {0}. Error: {1}" -f $ServiceName, $_)
            }
        } else {
            Write-Output "Service not found: $ServiceName"
        }
    }

    # Password Policies
    secedit /configure /db secedit.sdb /cfg "$env:windir\security\templates\basicwk.inf" /areas SECURITYPOLICY
    net accounts /minpwlen:10 /minpwage:1 /maxpwage:30
    net accounts /uniquepw:5

    # Configure Password Complexity and Encryption
    Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "FIPSAlgorithmPolicy" -Value 1
    Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1
    Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ClearTextPassword" -Value 0

    # Require CTRL+ALT+DEL for login
    Set-RegistryProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value 0

    # Audit Credential Validation
    auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

    # Prevent Users from Installing Printer Drivers
    Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "PointAndPrint_Restrictions" -Value 1

    # CD-ROM access restricted to locally logged-on users only
    Set-RegistryProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AllocateCDRoms" -Value 1

    # System not allowed to be shutdown without logon
    Set-RegistryProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Value 0

    # Disable Print Driver Downloads over HTTP
    Set-RegistryProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -Value 1

    # Autoplay disabled for all drives
    Set-RegistryProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255

    # Enable Shell protocol protected mode
    Set-RegistryProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "EnableShellProtocolProtectedMode" -Value 1

    # Enable Protected Event Logging
    Set-RegistryProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "SCENoProtectedEventLogging" -Value 0

    # Disable Plug and Play service
    Configure-Service -ServiceName "PlugPlay" -StartupType "Disabled"

    # Configure Windows Defender Firewall
    Configure-Service -ServiceName "MpsSvc" -StartupType "Automatic" -StartService $true

    # Disable Print Spooler service
    Configure-Service -ServiceName "Spooler" -StartupType "Disabled"

    # Ensure Event Log service is set to automatic
    Configure-Service -ServiceName "EventLog" -StartupType "Automatic" -StartService $true

    # Enable Windows Defender SmartScreen
    Set-RegistryProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "RequireAdmin"

    # Show security prompt for Windows Installer scripts from the web
    Set-RegistryProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 1

    # Enable Windows Defender Antivirus
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Write-Output "Windows Defender Antivirus enabled."
    } catch {
        Write-Output ("Failed to enable Windows Defender Antivirus. Error: {0}" -f $_)
    }

    # Prevent Remote Shell Connections
    Set-RegistryProperty -Path "HKLM:\Software\Microsoft\Powershell\1\ShellIds\Microsoft.PowerShell" -Name "DisableRemoteShell" -Value 1

    Write-Output "GOOSE script has ran successfully!"
    LogMessage "GOOSE script has ran successfully!"
        
    } else {
        Write-Host "The GOOSE script was not run."
        LogMessage "The GOOSE script was not run."
    }

    # === Other Server Scripts ===
    $runServerScripts = Read-Host "Do you want to run the other server scripts? (y/n to confirm)"

    if ($runServerScripts -match "^[yY]$") {
        Write-Output "Configuring User Account Policies and Rights Assignments..."

        # Disable Guest Account
        Disable-LocalUser -Name "Guest"

        # Set UAC (User Access Control) to enabled
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1

        # Restrict network logon to Administrators and Authenticated Users
        $secpolPath = "C:\secpol.cfg"
        secedit /export /cfg $secpolPath
        $secpolContent = Get-Content -Path $secpolPath
        $secpolContent = $secpolContent -replace 'SeNetworkLogonRight = .*', 'SeNetworkLogonRight = Administrators, Authenticated Users'
        $secpolContent = $secpolContent -replace 'SeInteractiveLogonRight = .*', 'SeInteractiveLogonRight = Administrators'
        $secpolContent | Set-Content -Path $secpolPath
        secedit /configure /db secedit.sdb /cfg $secpolPath /overwrite
        Write-Output "User Account Policies and Rights Assignments applied."

        #AUDIT EVENT
        Write-Output "Configuring Auditing Policies and Event Logging..."

        # Enable auditing for key categories
        auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable
        auditpol /set /subcategory:"Account Management" /success:enable /failure:enable
        auditpol /set /subcategory:"Logon/Logoff" /success:enable /failure:enable
        auditpol /set /subcategory:"Policy Change" /success:enable /failure:enable
        auditpol /set /subcategory:"Privilege Use" /success:enable

        # Set Event Log maximum sizes
        wevtutil sl Security /ms:20480
        wevtutil sl System /ms:20480
        wevtutil sl Application /ms:20480

        Write-Output "Auditing and Event Logging configured."

        #FIREWALL
        Write-Output "Configuring Windows Firewall with inbound restrictions..."

        # Enable firewall for all profiles
        netsh advfirewall set allprofiles state on

        # Block inbound traffic by default, allow outbound
        netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound

        Write-Output "Windows Firewall configured with default inbound block policy."

        #NETWORK
        Write-Output "Applying Network Security and Access Controls..."

        # Disable anonymous SID/Name translation
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1

        # Restrict anonymous access to SAM accounts and shares
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -Value 0

        # Configure Microsoft Network Client and Server to always digitally sign communications
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1

        Write-Output "Network Security and Access Controls applied."

        #PASSWORD
        # Enforce Password History - 5
        net accounts /uniquepw:5

        # Maximum Password Age - 60 days
        net accounts /maxpwage:60

        # Minimum Password Age - 10 days
        net accounts /minpwage:10

        # Minimum Password Length - 10 characters
        net accounts /minpwlen:10

        # Password Must Meet Complexity Requirements - Enabled
        secedit /export /cfg C:\Windows\Temp\secpol.cfg /quiet
        (Get-Content C:\Windows\Temp\secpol.cfg).replace("PasswordComplexity = 0", "PasswordComplexity = 1") | Set-Content C:\Windows\Temp\secpol.cfg
        secedit /configure /db C:\Windows\Security\Database\secedit.sdb /cfg C:\Windows\Temp\secpol.cfg /quiet

        # Store Passwords Using Reversible Encryption - Disabled
        (Get-Content C:\Windows\Temp\secpol.cfg).replace("ClearTextPassword = 1", "ClearTextPassword = 0") | Set-Content C:\Windows\Temp\secpol.cfg
        secedit /configure /db C:\Windows\Security\Database\secedit.sdb /cfg C:\Windows\Temp\secpol.cfg /quiet

        # Limit local use of blank passwords to console logon only
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f

        Write-Output "Password complexities have been successfully iplemented!"

        #SECURITY
        Write-Output "Applying Additional Security Enhancements..."

        # Set the system to use NTLMv2 only and disable LM hashes
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "LmCompatibilityLevel" -Value 5

        # Configure UAC and disable Remote Assistance
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0

        Write-Output "Additional security settings applied."

        #SERVICE ROLES
        Write-Output "Disabling unnecessary services and managing server roles..."

        # Disable Remote Registry
        Stop-Service -Name RemoteRegistry -Force
        Set-Service -Name RemoteRegistry -StartupType Disabled

        # Disable Print Spooler (if printing is not required)
        Stop-Service -Name Spooler -Force
        Set-Service -Name Spooler -StartupType Disabled

        # Remove unused Windows roles/features (customize as needed)
        Uninstall-WindowsFeature -Name Web-Server, Web-WebServer, Fax -ErrorAction SilentlyContinue

        Write-Output "Service and Role Management settings applied."

        #DHCP
        # Get all network interfaces on the machine
        $interfaces = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }

        foreach ($interface in $interfaces) {
            # Enable DHCP on the IPv4 address
            Set-NetIPInterface -InterfaceAlias $interface.Name -Dhcp Enabled

            # Optionally enable DHCP on IPv6 as well
            Set-NetIPInterface -InterfaceAlias $interface.Name -Dhcp Disabled # disable IPv6 if needed

            Write-Host "DHCP enabled for interface: $($interface.Name)"
            LogFileName "DHCP enabled for interface: $($interface.Name)"
        }


        Write-Host "All the SERVER scripts have been executed successfully."
        LogMessage "All the SERVER scripts have been executed successfully."
    } else {
        Write-Host "Skipped the execution of server scripts!."
        LogMessage "Skipped the execution of server scripts!."
    }

    $runSecure = Read-Host "Do you want to run secure.bat with admin privileges? (y/n to confirm)"

    if ($runSecure -match "^[yY]$") {
        #Start server service bcz that is a dependency to run secure.bat
        Set-Service -Name LanmanServer -StartupType Automatic
        Start-Service -Name LanmanServer


        # Path to the batch file
        $batchFilePath = "$FolderPath\lgpo\secure.bat"
        
        # Check if the file exists
        if (Test-Path $batchFilePath) {
            # Command to run the batch file with admin privileges
            Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$batchFilePath`"" -Verb RunAs
            Write-Host "secure.bat executed with admin privileges."
        } else {
            Write-Host "Error: $batchFilePath not found."
        }
    } else {
        Write-Host "secure.bat was not executed."
    }

    Write-Output "-----------------------------------------------------------------------------------------------------------"
    LogMessage "-----------------------------------------------------------------------------------------------------------"

    Write-Output "
  _____ _   _    _    _   _ _  __ __   _____  _   _ 
 |_   _| | | |  / \  | \ | | |/ / \ \ / / _ \| | | |
   | | | |_| | / _ \ |  \| | ' /   \ V / | | | | | |
   | | |  _  |/ ___ \| |\  | . \    | || |_| | |_| |
   |_| |_| |_/_/   \_\_| \_|_|\_\   |_| \___/ \___/ 

   THE MASTER SCRIPT RAN SUCCESSFULLY!
   PLEASE CHECKOUT THE 'MasterScript.log' FILE AND CHECK FOR ANY ERRORS IN POWERSHELL!
   "

} else {
    Write-Output "The script didn't run!"
}
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

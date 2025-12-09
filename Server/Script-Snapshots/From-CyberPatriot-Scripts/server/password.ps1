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
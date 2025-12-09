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

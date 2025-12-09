# PowerShell script to set all audit policies to audit success and failure
# This script requires administrative privileges to run

# Set all audit policy subcategories to log both success and failure
$auditSubcategories = auditpol /get /category:* /r | ConvertFrom-Csv -Delimiter "," | Where-Object { $_."Subcategory" -ne "" } | Select-Object -ExpandProperty "Subcategory GUID"

foreach ($subcategory in $auditSubcategories) {
    auditpol /set /subcategory:$subcategory /success:enable /failure:enable
}

# Output the result of the operation
Write-Output "All audit policies have been updated to audit both success and failure."

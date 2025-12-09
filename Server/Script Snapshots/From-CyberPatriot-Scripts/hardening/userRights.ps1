# PowerShell script to apply a security template to change user rights assignment
# This script requires administrative privileges to run

# Define the path to the security template
$templatePath = "C:\CyberPatriot_Semis_Scrips"

# Check if the template file exists
if (Test-Path $templatePath) {
    # Apply the security template
    secedit /configure /db secedit.sdb /cfg $templatePath /areas USER_RIGHTS /quiet
    
    # Output the result of the operation
    Write-Output "User rights assignment has been updated according to the template."
} else {
    Write-Error "The specified template file was not found."
}

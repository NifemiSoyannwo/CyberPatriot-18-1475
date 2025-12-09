# PowerShell script to set user passwords in Windows 10 for CyberPatriot

# Loop until the user types "done"
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

Write-Host "Script completed. No more changes made." -ForegroundColor Yellow
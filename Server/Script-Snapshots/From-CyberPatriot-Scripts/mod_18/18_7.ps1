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
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

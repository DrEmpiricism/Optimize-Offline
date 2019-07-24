
# List of scheduled tasks to disable.
$TaskList = @(
    "AitAgent",
    "AnalyzeSystem",
    "Automatic App Update",
    "Background Synchronization",
    "BackgroundUploadTask",
    "BackupTask",
    "BthSQM",
    "Cellular",
    "CleanupOfflineContent",
    "Consolidator",
    "CreateObjectTask",
    "DmClient",
    "DmClientOnScenarioDownload",
    "ExploitGuard MDM policy Refresh",
    "FamilySafetyMonitor",
    "FamilySafetyMonitorToastTask",
    "FamilySafetyRefreshTask",
    "FODCleanupTask",
    "GatherNetworkInfo",
    "KernelCeipTask",
    "LoginCheck",
    "Logon Synchronization",
    "MapsToastTask",
    "MapsUpdateTask",
    "Microsoft Compatibility Appraiser",
    "Microsoft-Windows-DiskDiagnosticDataCollector",
    "Notifications",
    "Pre-staged app cleanup",
    "ProgramDataUpdater",
    "Proxy",
    "QueueReporting",
    "Registration",
    "ResPriStaticDbSync",
    "Scheduled",
    "SpeechModelDownloadTask",
    "Secure-Boot-Update",
    "sih",
    "SmartScreenSpecific",
    "Sqm-Tasks",
    "StartupAppTask",
    "TelTask",
    "UpdateLibrary",
    "Uploader",
    "UsbCeip",
    "WiFiTask",
    "WindowsActionDialog",
    "Windows Defender Cache Maintenance",
    "Windows Defender Cleanup",
    "Windows Defender Scheduled Scan",
    "Windows Defender Verification",
    "WinSAT",
    "WsSwapAssessmentTask",
    "XblGameSaveTask",
    "XblGameSaveTaskLogon"
)

# List of services to disable.
# More detail located at http://www.blackviper.com/service-configurations/black-vipers-windows-10-service-configurations/
$ServiceList = @(
    "AJRouter",
    "ALG",
    "AppReadiness",
    "AppVClient",
    "bthserv",
    "CDPSvc",
    "ClickToRunSvc",
    "CscService",
    "diagnosticshub.standardcollector.service",
    "diagsvc",
    "Diagtrack",
    "dmwappushservice",
    "DoSvc",
    "DsSvc",
    "DusmSvc",
    "FrameServer",
    "HomeGroupListener",
    "HomeGroupProvider",
    "HvHost",
    "icssvc",
    "iphlpsvc",
    "irmon",
    "lfsvc",
    "MapsBroker",
    "MessagingService",
    "MSiSCSI",
    "NfsClnt",
    "OneSyncSvc",
    "PcaSvc",
    "PeerDistSvc",
    "PhoneSvc",
    "RemoteAccess",
    "RemoteRegistry",
    "RetailDemo",
    "RpcLocator",
    "SCardSvr",
    "ScDeviceEnum",
    "SCPolicySvc",
    "SecurityHealthService",
    "SEMgrSvc",
    "Sense",
    "SensorDataService",
    "SensorService",
    "SensrSvc",
    "SessionEnv",
    "SgrmBroker",
    "SharedAccess",
    "shpamsvc",
    "SmsRouter",
    "SNMPTRAP",
    "SSDPSRV",
    "SysMain",
    "TabletInputService",
    "TermSvc",
    "tzautoupdate",
    "UevAgentService",
    "UmRdpService",
    "upnphost",
    "vmicguestinterface",
    "vmicheartbeat",
    "vmickvpexchange",
    "vmicrdv",
    "vmicshutdown",
    "vmictimesync",
    "vmicvmsession",
    "vmicvss",
    "WalletService",
    "WbioSrvc",
    "WdNisSvc",
    "wercplsupport",
    "WerSvc",
    "WFDSConSvc",
    "WinDefend",
    "WinHttpAutoProxySvc",
    "WinRM",
    "wisvc",
    "WMPNetworkSvc",
    "WpcMonSvc",
    "WwanSvc",
    "xbgm",
    "XblAuthManager",
    "XblGameSave",
    "XboxGipSvc",
    "XboxNetApiSvc"
)

Function Set-Privacy
{
    [CmdletBinding()]
    Param ()

    Clear-Host
    Write-Host "Setting Additional Privacy Restrictions..." -NoNewline -ForegroundColor Cyan

    # Disables all scheduled tasks listed in the TaskList that are found to be present on the system.
    Get-ScheduledTask | Where-Object TaskName -In $TaskList | Where-Object State -NE Disabled | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null

    # Saves the original startup type of all services listed in the ServicesList that are found to be present on the system.
    $ServicesDefault = @{ }
    Get-Service | Where-Object Name -In $ServiceList | ForEach-Object { $ServicesDefault.Add($_.Name, $_.StartType) }
    $ServicesDefault | Out-File -FilePath .\ServicesDefault.log -Force
    # Stops and disables all services listed in the ServicesList that are found to be present on the system.
    Get-Service | Where-Object Name -In $ServiceList | Where-Object { $_.StartType -ne 'Disabled' } | Set-Service -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null

    # Disables Autologgers
    Set-AutologgerConfig -Name AutoLogger-Diagtrack-Listener -Start 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" -Name "Start" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" -Name "Start" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" -Name "Start" -Value 0 -Type DWord

    # Modifies the firewall rules and adds additional outbound blocks for Windows Apps, CompatTelRunner, DiagTrack and SmartScreen.
    Get-NetFirewallRule | Where-Object Group -Like "*@{*" | Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null
    Get-NetFirewallRule | Where-Object Group -EQ "DiagTrack" | Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null
    Get-NetFirewallRule | Where-Object DisplayGroup -EQ "Delivery Optimization" | Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null
    Get-NetFirewallRule | Where-Object DisplayGroup -Like "Windows Media Player Network Sharing Service*" | Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "Block DiagTrack" -Action Block -Description "Prevent DiagTrack Outbound Traffic." -Direction Outbound -Name "DiagTrack" -Profile Any -Service DiagTrack -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "Block Compatability Telemetry Runner" -Action Block -Description "Prevent CompatTelRunner Outbound Traffic." -Direction Outbound -Name "Compatability Telemetry Runner" -Profile Any -Program "%SystemDrive%\Windows\System32\CompatTelRunner.exe" -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "Block SmartScreen" -Action Block -Description "Prevent SmartScreen Outbound Traffic." -Direction Outbound -Name "SmartScreen" -Profile Any -Program "%SystemDrive%\Windows\System32\smartscreen.exe" -ErrorAction SilentlyContinue | Out-Null

    # Disables Swapfile.sys which can improve SSD performance.
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "SwapfileControl" -Value 0 -Type DWord | Out-Null

    # Removes leftover DiagTrack and Windows Defender logs.
    Remove-Item -Path "$Env:SystemRoot\System32\LogFiles\WMI\AutoLogger-Diagtrack-Listener.etl" -Force -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "$Env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" -Force -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "$Env:ProgramData\Microsoft\Diagnosis\ETLLogs\*" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "$Env:ProgramData\Microsoft\Diagnosis\*.rbs" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "$Env:ProgramData\Microsoft\Windows Defender\Scans\*" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null

    # Clears the DNS Cache
    Clear-DnsClientCache

    Write-Host "[Complete]" -ForegroundColor Cyan
}
Set-Privacy

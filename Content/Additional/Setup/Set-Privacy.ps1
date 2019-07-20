
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

    $ErrorActionPreference = 'SilentlyContinue'; $WarningPreference = 'SilentlyContinue'; $ProgressPreference = 'SilentlyContinue'; Clear-Host

    # Disables all scheduled tasks listed in the TaskList that are found to be present on the system.
    Get-ScheduledTask | Where-Object TaskName -In $TaskList | Disable-ScheduledTask

    # Stops and disables all services listed in the ServicesList that are found to be present on the system.
    Get-Service | Where-Object Name -In $ServiceList | Stop-Service -Force -PassThru | Set-Service -StartupType Disabled

    # Disables Diagtrack autologging
    Set-AutologgerConfig -Name "AutoLogger-Diagtrack-Listener" -Start 0

    # Modifies the firewall rules and adds additional blocks for CompatTelRunner, DiagTrack and SmartScreen.
    Get-NetFirewallRule | Where-Object Group -Like "*@{*" | Remove-NetFirewallRule
    Get-NetFirewallRule | Where-Object Group -EQ "DiagTrack" | Remove-NetFirewallRule
    Get-NetFirewallRule | Where-Object DisplayGroup -EQ "Delivery Optimization" | Remove-NetFirewallRule
    Get-NetFirewallRule | Where-Object DisplayGroup -Like "Windows Media Player Network Sharing Service*" | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName "Block DiagTrack" -Action Block -Description "Block the DiagTrack Telemetry Service" -Direction Outbound -Name "Block DiagTrack" -Profile Any -Service DiagTrack
    New-NetFirewallRule -DisplayName "Compatability Telemetry Runner Inbound" -Action Block -Description "Prevent CompatTelRunner Inbound Traffic." -Direction Inbound -Name "Compatability Telemetry Runner" -Profile Any -Program "%SystemDrive%\Windows\System32\CompatTelRunner.exe"
    New-NetFirewallRule -DisplayName "Compatability Telemetry Runner Outbound" -Action Block -Description "Prevent CompatTelRunner Outbound Traffic." -Direction Outbound -Name "Compatability Telemetry Runner" -Profile Any -Program "%SystemDrive%\Windows\System32\CompatTelRunner.exe"
    New-NetFirewallRule -DisplayName "SmartScreen Inbound" -Action Block -Description "Prevent SmartScreen Inbound Traffic." -Direction Inbound -Name "SmartScreen" -Profile Any -Program "%SystemDrive%\Windows\System32\smartscreen.exe"
    New-NetFirewallRule -DisplayName "SmartScreen Outbound" -Action Block -Description "Prevent SmartScreen Outbound Traffic." -Direction Outbound -Name "SmartScreen" -Profile Any -Program "%SystemDrive%\Windows\System32\smartscreen.exe"

    # Removes CompatTelRunner, as Windows will automatically re-enable it and remove its firewall rule during certain updates or scans.
    If (Test-Path -Path "$Env:SystemRoot\System32\CompatTelRunner.exe")
    {
        Start-Process -FilePath TAKEOWN -ArgumentList ("/F $Env:SystemRoot\System32\CompatTelRunner.exe /A") -WindowStyle Hidden -Wait
        Start-Process -FilePath ICACLS -ArgumentList ("$Env:SystemRoot\System32\CompatTelRunner.exe /GRANT:R *S-1-5-32-544:F /C") -WindowStyle Hidden -Wait
        Stop-Process -Name CompatTelRunner -Force
        Remove-Item -Path "$Env:SystemRoot\System32\CompatTelRunner.exe" -Force
    }

    # Disables Swapfile.sys which can improve SSD performance.
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "SwapfileControl" -Value 0 -Type DWord

    # Disables automatic system restore and removes any current restore points.
    Disable-ComputerRestore -Drive $Env:SystemDrive
    Start-Process -FilePath VSSADMIN -ArgumentList ('Delete Shadows /For:$Env:SystemDrive /Quiet') -WindowStyle Hidden -Wait

    # Removes leftover DiagTrack and Windows Defender logs.
    Remove-Item -Path "$Env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" -Force
    Remove-Item -Path "$Env:ProgramData\Microsoft\Diagnosis\ETLLogs\*" -Recurse -Force
    Remove-Item -Path "$Env:ProgramData\Microsoft\Diagnosis\*.rbs" -Recurse -Force
    Remove-Item -Path "$Env:ProgramData\Microsoft\Windows Defender\Scans\*" -Recurse -Force

    # Clears the DNS Cache
    Clear-DnsClientCache
}
Set-Privacy

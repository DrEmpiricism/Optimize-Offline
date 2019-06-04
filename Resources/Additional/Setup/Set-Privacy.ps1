# Scheduled tasks to disable. These further disable Microsoft telemetry, intrusive and potentially exploitable access.
$Tasks = @("AitAgent", "AnalyzeSystem", "Automatic App Update", "Background Synchronization", "BackgroundUploadTask", "BackupTask", "BthSQM", "Cellular", "CleanupOfflineContent", "Consolidator",
    "CreateObjectTask", "DmClient", "DmClientOnScenarioDownload", "ExploitGuard MDM policy Refresh", "FamilySafetyMonitor", "FamilySafetyMonitorToastTask", "FamilySafetyRefreshTask", "FODCleanupTask", 
    "GatherNetworkInfo", "KernelCeipTask", "LoginCheck", "Logon Synchronization", "MapsToastTask", "MapsUpdateTask", "Microsoft Compatibility Appraiser", "Microsoft-Windows-DiskDiagnosticDataCollector",
    "Notifications", "Pre-staged app cleanup", "ProgramDataUpdater", "Proxy", "QueueReporting", "Registration", "ResPriStaticDbSync", "Scheduled", "SpeechModelDownloadTask", "Secure-Boot-Update", "sih",
    "SmartScreenSpecific", "Sqm-Tasks", "StartupAppTask", "TelTask", "UpdateLibrary", "Uploader", "UsbCeip", "WiFiTask", "WindowsActionDialog", "Windows Defender Cache Maintenance", "Windows Defender Cleanup", 
    "Windows Defender Scheduled Scan", "Windows Defender Verification", "WinSAT", "WsSwapAssessmentTask", "XblGameSaveTask", "XblGameSaveTaskLogon")
# Services to disable. These further disable Microsoft telemetry, intrusive and potentially exploitable access.
$Services = @("bthserv", "ClickToRunSvc", "Diagtrack", "diagsvc", "diagnosticshub.standardcollector.service", "dmwappushservice", "DoSvc", "DsSvc", "DusmSvc", "HomeGroupListener", "HomeGroupProvider", "lfsvc", 
    "icssvc", "MessagingService", "OneSyncSvc", "PcaSvc", "PhoneSvc", "RemoteRegistry", "RetailDemo", "SecurityHealthService", "Sense", "SessionEnv", "shpamsvc", "SysMain", "TabletInputService", "TermSvc", 
    "UmRdpService", "WalletService", "WbioSrvc", "WdNisSvc", "WerSvc", "wercplsupport", "WinDefend", "wisvc", "WMPNetworkSvc", "WpcMonSvc", "XblAuthManager", "XblGameSave", "XboxNetApiSvc", "XboxGipSvc", "xbgm")

Function Set-Privacy
{
    [CmdletBinding()]
    Param ()
	
    Clear-Host
    Write-Host "Applying privacy settings..." -ForegroundColor Cyan
    # Gets the tasks from the array above and disables them.
    Get-ScheduledTask -TaskName $Tasks -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
    # Gets the services from the array above, stops them and then disables them.
    Get-Service -Name $Services -ErrorAction SilentlyContinue | Stop-Service -Force -PassThru -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    # Disables Diagtrack autologging
    Set-AutologgerConfig -Name "AutoLogger-Diagtrack-Listener" -Start 0 -ErrorAction SilentlyContinue | Out-Null
    # Modifies the firewall rules and adds additional blocks for CpmpatTelRunner, DiagTrack and SmartScreen.
    Get-NetFirewallRule | Where-Object Group -Like "*@{*" | Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null
    Get-NetFirewallRule | Where-Object Group -EQ "DiagTrack" | Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null
    Get-NetFirewallRule | Where-Object DisplayGroup -EQ "Delivery Optimization" | Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null
    Get-NetFirewallRule | Where-Object DisplayGroup -Like "Windows Media Player Network Sharing Service*" | Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "Block DiagTrack" -Action Block -Description "Block the DiagTrack Telemetry Service" -Direction Outbound -Name "Block DiagTrack" -Profile Any -Service DiagTrack -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "Compatability Telemetry Runner Inbound" -Action Block -Description "Prevent CompatTelRunner Inbound Traffic." -Direction Inbound -Name "Compatability Telemetry Runner" -Profile Any -Program "%SystemDrive%\Windows\System32\CompatTelRunner.exe" -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "Compatability Telemetry Runner Outbound" -Action Block -Description "Prevent CompatTelRunner Outbound Traffic." -Direction Outbound -Name "Compatability Telemetry Runner" -Profile Any -Program "%SystemDrive%\Windows\System32\CompatTelRunner.exe" -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "SmartScreen Inbound" -Action Block -Description "Prevent SmartScreen Inbound Traffic." -Direction Inbound -Name "SmartScreen" -Profile Any -Program "%SystemDrive%\Windows\System32\smartscreen.exe" -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "SmartScreen Outbound" -Action Block -Description "Prevent SmartScreen Outbound Traffic." -Direction Outbound -Name "SmartScreen" -Profile Any -Program "%SystemDrive%\Windows\System32\smartscreen.exe" -ErrorAction SilentlyContinue | Out-Null
    # Removes CompatTelRunner, as Windows will automatically re-enable it and remove its firewall rule during certain updates or scans.
    If (Test-Path -Path "$Env:SystemRoot\System32\CompatTelRunner.exe")
    {
        Start-Process -FilePath TAKEOWN -ArgumentList ("/F $Env:SystemRoot\System32\CompatTelRunner.exe /A") -WindowStyle Hidden -Wait
        Start-Process -FilePath ICACLS -ArgumentList ("$Env:SystemRoot\System32\CompatTelRunner.exe /GRANT:R *S-1-5-32-544:F /C") -WindowStyle Hidden -Wait
        Stop-Process -Name CompatTelRunner -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$Env:SystemRoot\System32\CompatTelRunner.exe" -Force | Out-Null
    }
    # Disables Swapfile.sys which can improve SSD performance.
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "SwapfileControl" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    # Disables automatic system restore and removes any current restore points.
    Disable-ComputerRestore -Drive $Env:SystemDrive -ErrorAction SilentlyContinue
    Start-Process -FilePath VSSADMIN -ArgumentList ('Delete Shadows /For:$Env:SystemDrive /Quiet') -WindowStyle Hidden -Wait
    # Stops the DNSCache and removes leftover DiagTrack and Windows Defender logs. 
    Stop-Service -Name Dnscache -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "$Env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" -Force -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "$Env:ProgramData\Microsoft\Diagnosis\ETLLogs\*" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "$Env:ProgramData\Microsoft\Diagnosis\*.rbs" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "$Env:ProgramData\Microsoft\Windows Defender\Scans\*" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
    # Clears and restarts the DNSCache
    Clear-DnsClientCache -ErrorAction SilentlyContinue | Out-Null
    Start-Service -Name Dnscache -ErrorAction SilentlyContinue | Out-Null
}
Set-Privacy

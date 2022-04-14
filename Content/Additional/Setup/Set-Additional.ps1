Function Set-Additional
{
    [CmdletBinding()]
    Param ()

    Begin
    {
        # Assign the default preferences to their own variables so we can restore then once the function completes.
        $DefaultErrorActionPreference = $ErrorActionPreference
        $DefaultProgressPreference = $ProgressPreference
        $ErrorActionPreference = 'SilentlyContinue'
        $ProgressPreference = 'SilentlyContinue'
    }
    Process
    {
        # Set the PowerShell Execution Policy for the CurrentUser and LocalMachine to RemoteSigned. This is more lenient than the default setting (Restricted) but more secure than Bypass and Unrestricted.
        If ((Get-ExecutionPolicy -Scope CurrentUser) -ne 'RemoteSigned') { Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Confirm:$false }
        If ((Get-ExecutionPolicy -Scope LocalMachine) -ne 'RemoteSigned') { Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Confirm:$false }

        # Get the current build number for the Windows version.
        $Build = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber

        If (Test-Path -Path .\ScheduledTasks.json)
        {
            $ScheduledTasksJson = Get-Content -Path .\ScheduledTasks.json | ConvertFrom-Json

            # Before stopping and disabling any Scheduled Task, export their default values as a JSON file. This way we can revert any change back to default if required.
            Get-ScheduledTask | Select-Object -Property TaskName, Description, TaskPath, State | ForEach-Object -Process { [PSCustomObject] @{ TaskName = $PSItem.TaskName; Description = $PSItem.Description; TaskPath = $PSItem.TaskPath; State = $PSItem.State; SetState = 'Disabled' } } | ConvertTo-Json | Out-File -FilePath .\DefaultScheduledTasks.json

            # Disable any Scheduled Tasks that have a SetState value of 'Disabled' in the ScheduledTasks.json file.
            Get-ScheduledTask | Where-Object { $PSItem.TaskName -in $ScheduledTasksJson.TaskName -and $ScheduledTasksJson.SetState -eq 'Disabled' -and $PSItem.State -ne 'Disabled' } | Disable-ScheduledTask | Out-Null
        }

        If (Test-Path -Path .\Services.json)
        {
            $ServicesJson = Get-Content -Path .\Services.json | ConvertFrom-Json

            # Before stopping and disabling any Service, export their default values as a JSON file. This way we can revert any change back to default if required.
            Get-Service | Select-Object -Property Name, DisplayName, ServiceName, Status, StartType | Foreach-Object -Process { [PSCustomObject]@{ Name = $PSItem.Name; Description = $PSItem.DisplayName; ServiceName = $PSItem.ServiceName; Status = $PSItem.Status; StartType = $PSItem.StartType; SetStatus = 'Disabled' } } | ConvertTo-Json | Out-File -FilePath .\DefaultServices.json

            # Disable any Services that have a SetState value of 'Disabled' in the Services.json file.
            Get-Service | Where-Object { $PSItem.Name -in $ServicesJson.Name -and $ServicesJson.SetStatus -eq 'Disabled' -and $PSItem.StartType -ne 'Disabled' } | Stop-Service -Force -NoWait -PassThru | Set-Service -StartupType Disabled | Out-Null

            # If the Delivery Optimization service has a SetState value of 'Disabled' in the Services.json file, set the delivery optimization download mode to bypass.
            # https://getadmx.com/?Category=Windows_10_2016&Policy=Microsoft.Policies.DeliveryOptimization::DownloadMode
            If (($ServicesJson | Where-Object { $PSItem.Name -eq 'DoSvc' -and $PSItem.SetStatus -eq 'Disabled' }) -and (Get-Service -Name DoSvc).Status -eq 'Stopped')
            {
                Set-DODownloadMode -DownloadMode 100
            }
        }

        # Disable additional per-user Services through the registry.
        Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services" | Where-Object -Property Name -Like *CDPUserSvc* | Set-ItemProperty -Name Start -Value 4 -Force -PassThru | Set-ItemProperty -Name UserServiceFlags -Value 0 -Force
        Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services" | Where-Object -Property Name -Like *OneSyncSvc* | Set-ItemProperty -Name Start -Value 4 -Force -PassThru | Set-ItemProperty -Name UserServiceFlags -Value 0 -Force
        Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services" | Where-Object -Property Name -Like *PimIndexMaintenanceSvc* | Set-ItemProperty -Name Start -Value 4 -Force -PassThru | Set-ItemProperty -Name UserServiceFlags -Value 0 -Force
        Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services" | Where-Object -Property Name -Like *UnistoreSvc* | Set-ItemProperty -Name Start -Value 4 -Force -PassThru | Set-ItemProperty -Name UserServiceFlags -Value 0 -Force
        Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services" | Where-Object -Property Name -Like *UserDataSvc* | Set-ItemProperty -Name Start -Value 4 -Force -PassThru | Set-ItemProperty -Name UserServiceFlags -Value 0 -Force
        Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services" | Where-Object -Property Name -Like *RetailDemo* | Set-ItemProperty -Name Start -Value 4 -Force -PassThru | Set-ItemProperty -Name UserServiceFlags -Value 0 -Force
        Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services" | Where-Object -Property Name -Like *WpnUserService* | Set-ItemProperty -Name Start -Value 4 -Force -PassThru | Set-ItemProperty -Name UserServiceFlags -Value 0 -Force

        # Stop DiagLog Event Trace sessions.
        Get-EtwTraceSession -Name DiagLog | Stop-EtwTraceSession

        # Turn off Autologger and SQMLogger sessions after the next restart.
        Get-AutologgerConfig -Name AutoLogger-Diagtrack-Listener, SQMLogger | Set-AutologgerConfig -Start 0

        # Create a hashtable for our registry files that will be exported for editing.
        $RegFile = @{
            LoggerDefault1 = Join-Path -Path $Env:TEMP -ChildPath LoggerDefault1.reg
            LoggerDefault2 = Join-Path -Path $Env:TEMP -ChildPath LoggerDefault2.reg
            LoggerDefault3 = Join-Path -Path $Env:TEMP -ChildPath LoggerDefault3.reg
            LoggerEdited   = Join-Path -Path $Env:TEMP -ChildPath LoggerEdited.reg
        }

        # Export the AutoLogger and SQMLogger registry settings.
        Start-Process -FilePath REGEDIT -ArgumentList ('/E "{0}" "{1}"' -f $RegFile.LoggerDefault1, "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener") -WindowStyle Hidden -Wait
        Start-Process -FilePath REGEDIT -ArgumentList ('/E "{0}" "{1}"' -f $RegFile.LoggerDefault2, "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener") -WindowStyle Hidden -Wait
        Start-Process -FilePath REGEDIT -ArgumentList ('/E "{0}" "{1}"' -f $RegFile.LoggerDefault3, "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SQMLogger") -WindowStyle Hidden -Wait

        # Change the Autologger and SQMLogger start-up registry property values to disable their corresponding running services.
        Select-String -Path $RegFile.LoggerDefault1 -Pattern 'Windows\sRegistry', '\[HKEY', 'Enabled' | ForEach-Object -Process { $PSItem.Line.Replace('"Enabled"=dword:00000001', '"Enabled"=dword:00000000') } | Out-File -FilePath $RegFile.LoggerEdited -Encoding Unicode -Force
        Select-String -Path $RegFile.LoggerDefault2 -Pattern '\[HKEY', 'Enabled' | ForEach-Object -Process { $PSItem.Line.Replace('"Enabled"=dword:00000001', '"Enabled"=dword:00000000') } | Out-File -FilePath $RegFile.LoggerEdited -Encoding Unicode -Append -Force
        Select-String -Path $RegFile.LoggerDefault3 -Pattern '\[HKEY', 'Enabled' | ForEach-Object -Process { $PSItem.Line.Replace('"Enabled"=dword:00000001', '"Enabled"=dword:00000000') } | Out-File -FilePath $RegFile.LoggerEdited -Encoding Unicode -Append -Force

        # Import the edited registry file.
        Start-Process -FilePath REGEDIT -ArgumentList ('/S "{0}"' -f $RegFile.LoggerEdited) -WindowStyle Hidden -Wait
        $RegFile.Values | Remove-Item -Force

        # Disable automatic Event Tracker Logs from Services that can use them as telemetry.
        @('AITEventLog', 'AutoLogger-Diagtrack-Listener', 'DiagLog', 'EventLog-Microsoft-RMS-MSIPC-Debug', 'EventLog-Microsoft-Windows-WorkFolders-WHC', 'FamilySafetyAOT', 'LwtNetLog', 'Microsoft-Windows-Setup', 'NBSMBLOGGER', 'PEAuthLog', 'RdrLog', 'ReadyBoot', 'SetupPlatform', 'SQMLogger', 'TCPIPLOGGER', 'Tpm', 'WdiContextLog') | ForEach-Object -Process { Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\WMI\AutoLogger\$($PSItem)" -Name Start -Value 4 -Force }

        # Remove any Event Tracker Logs and Security Health (Windows Defender) scan files.
        @("$Env:SystemRoot\System32\LogFiles\WMI\AutoLogger-Diagtrack-Listener.etl", "$Env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\*.etl", "$Env:ProgramData\Microsoft\Diagnosis\ETLLogs\ShutdownLogger\*.etl", "$Env:ProgramData\Microsoft\Diagnosis\*.rbs", "$Env:ProgramData\Microsoft\Windows Defender\Scans\*") | Remove-Item -Recurse -Force

        # Block the background telemetry for DiagTrack, Delivery Optimization, Windows Media Player, Windows Error Reporting, CompatTelRunner, SmartScreen and ContentDelivery by editing their default firewall rules.
        Get-NetFirewallRule | Where-Object Group -Like "*@{*" | Remove-NetFirewallRule | Out-Null
        Get-NetFirewallRule | Where-Object Group -EQ "DiagTrack" | Remove-NetFirewallRule | Out-Null
        Get-NetFirewallRule | Where-Object DisplayGroup -EQ "Delivery Optimization" | Remove-NetFirewallRule | Out-Null
        Get-NetFirewallRule | Where-Object DisplayGroup -Like "Windows Media Player Network Sharing Service*" | Remove-NetFirewallRule | Out-Null
        New-NetFirewallRule -DisplayName "Diagnostics Tracking and Telemetry (DiagTrack)" -Description "Outbound rule to block Diagnostics Tracking." -Action Block -Direction Outbound -Profile Any -InterfaceType Any -Program "%SystemDrive%\Windows\System32\svchost.exe" -Service DiagTrack -Protocol TCP -RemotePort 80, 443 -Enabled True | Out-Null
        New-NetFirewallRule -DisplayName "Windows Error Reporting Services (WerSvc)" -Description "Outbound rule to block Windows Error Reporting." -Action Block -Direction Outbound -Profile Any -InterfaceType Any -Program "%SystemDrive%\Windows\System32\svchost.exe" -Service WerSvc -Protocol TCP -RemotePort 80, 443 -Enabled True | Out-Null
        New-NetFirewallRule -DisplayName "Compatability Telemetry Runner (CompatTelRunner-In)" -Description "Inbound rule to block Compatability Telemetry Runner." -Action Block -Direction Inbound -Profile Any -InterfaceType Any -Program "%SystemDrive%\Windows\System32\CompatTelRunner.exe" -Enabled True | Out-Null
        New-NetFirewallRule -DisplayName "Compatability Telemetry Runner (CompatTelRunner-Out)" -Description "Outbound rule to block Compatability Telemetry Runner." -Action Block -Direction Outbound -Profile Any -InterfaceType Any -Program "%SystemDrive%\Windows\System32\CompatTelRunner.exe" -Enabled True | Out-Null
        New-NetFirewallRule -DisplayName "Windows Smartscreen Filter (Smartscreen-In)" -Description "Inbound rule to block Windows Smartscreen Filter." -Action Block -Direction Inbound -Profile Any -InterfaceType Any -Program "%SystemDrive%\Windows\System32\smartscreen.exe" -Enabled True | Out-Null
        New-NetFirewallRule -DisplayName "Windows Smartscreen Filter (Smartscreen-Out)" -Description "Outbound rule to block Windows Smartscreen Filter." -Action Block -Direction Outbound -Profile Any -InterfaceType Any -Program "%SystemDrive%\Windows\System32\smartscreen.exe" -Enabled True | Out-Null
        New-NetFirewallRule -DisplayName "Content Delivery Manager Background (ContentDeliveryManager.Background.dll-In)" -Description "Inbound rule to block Content Delivery Manager Background access." -Action Block -Direction Inbound -Profile Any -InterfaceType Any -Program "%SystemDrive%\Windows\SystemApps\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\ContentDeliveryManager.Background.dll" -Enabled True | Out-Null
        New-NetFirewallRule -DisplayName "Content Delivery Manager Background (ContentDeliveryManager.Background.dll-Out)" -Description "Outbound rule to block Content Delivery Manager Background access." -Action Block -Direction Outbound -Profile Any -InterfaceType Any -Program "%SystemDrive%\Windows\SystemApps\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\ContentDeliveryManager.Background.dll" -Enabled True | Out-Null

        # Delete the CompatTelRunner executable.
        If (Test-Path -Path "$Env:SystemRoot\System32\CompatTelRunner.exe")
        {
            Invoke-Expression -Command ('TAKEOWN.EXE /F "{0}" /A' -f "$Env:SystemRoot\System32\CompatTelRunner.exe") | Out-Null
            Invoke-Expression -Command ('ICACLS.EXE "{0}" /GRANT *S-1-5-32-544:F' -f "$Env:SystemRoot\System32\CompatTelRunner.exe") | Out-Null
            Stop-Process -Name CompatTelRunner -Force
            Remove-Item -Path "$Env:SystemRoot\System32\CompatTelRunner.exe" -Force
            If (!(Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" -ItemType Directory -Force | Out-Null }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" -Name Debugger -Value "%SystemRoot%\System32\taskkill.exe" -Type ExpandString -Force
        }

        # Disable Clipboard history, its synchronization service and any Remote Desktop redirection.
        If ($Build -ge 17763)
        {
            If (!(Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ItemType Directory -Force | Out-Null }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name AllowCrossDeviceClipboard -Value 0 -Force
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name AllowClipboardHistory -Value 0 -Force
            If (!(Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Terminal Server Client")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\Terminal Server Client" -ItemType Directory -Force | Out-Null }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Terminal Server Client" -Name DisableClipboardRedirection -Value 1 -Force
            If (!(Test-Path -Path "HKCU:\Software\Microsoft\Clipboard")) { New-Item -Path "HKCU:\Software\Microsoft\Clipboard" -ItemType Directory -Force | Out-Null }
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -Name EnableClipboardHistory -Value 0 -Force
        }

        If ($Build -ge 18363) {
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\CLSID\{1d64637d-31e9-4b06-9124-e83fb178ac6e}\TreatAs" -Name "(Default)" -Value "{64bc32b5-4eec-4de7-972d-bd8bd0324537}" -Force
        }

        # Uninstall Cortana.
        If ($Build -ge 19041) { Get-AppxPackage -Name *Microsoft.549981C3F5F10* | Remove-AppxPackage -AllUsers | Out-Null }

        # Prevent the automatic use of sign-in information to finish setting up the device after an update or restart.
        $SID = Get-CimInstance -ClassName Win32_UserAccount | Where-Object -Property Name -EQ $Env:USERNAME | Select-Object -ExpandProperty SID
        If (!(Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID" -ItemType Directory -Force | Out-Null }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$SID" -Name OptOut -Value 1 -Force

        If ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name DrvType) -eq 'SSD')
        {
            # Enable TRIM support for NTFS and ReFS file systems for SSD drives.
            Invoke-Expression -Command ('FSUTIL BEHAVIOR SET DISABLEDELETENOTIFY NTFS 0') | Out-Null
            $QueryReFS = Invoke-Expression -Command ('FSUTIL BEHAVIOR QUERY DISABLEDELETENOTIFY') | Select-String -Pattern ReFS
            If ($QueryReFS) { Invoke-Expression -Command ('FSUTIL BEHAVIOR SET DISABLEDELETENOTIFY REFS 0') | Out-Null }

            # Disable Swapfile.sys which can improve SSD performance.
            If(!(Get-AppxProvisionedPackage -Online | Where-Object -Property DisplayName -EQ Microsoft.WindowsStore)){
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name SwapfileControl -Value 0 -Force
            }

            # Disable Prefetch and Superfetch (optimal for SSD drives).
            If (!(Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -ItemType Directory -Force | Out-Null }
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name EnablePrefetcher -Value 0 -Force
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name EnableSuperfetch -Value 0 -Force
        }

        If ((Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty PCSystemType) -eq 2)
        {
            # Set the active power scheme to Balanced if the system type is detected as a laptop.
            Invoke-Expression -Command ('POWERCFG -S 381b4222-f694-41f0-9685-ff5bb260df2e') | Out-Null
        }
        Else
        {
            # Disable hibernation.
            Invoke-Expression -Command ('POWERCFG -H OFF') | Out-Null

            # Disable the automatic disabling of network cards to save power.
            Get-NetAdapter -Physical | Get-NetAdapterPowerManagement | Where-Object -Property AllowComputerToTurnOffDevice -NE Unsupported | ForEach-Object -Process {
                $PSItem.AllowComputerToTurnOffDevice = 'Disabled'
                $PSItem | Set-NetAdapterPowerManagement
            }

            # Set the active power scheme to Ultimate Performance if the runtime Windows version is Windows 10 Pro for Workstations or the Ultimate Performance power scheme GUID is detected, else set the active power scheme to High Performance.
            If ((Get-WindowsEdition -Online | Select-Object -ExpandProperty Edition) -eq 'ProfessionalWorkstation') { Invoke-Expression -Command ('POWERCFG -S e9a42b02-d5df-448d-aa00-03f14749eb61') | Out-Null }
            ElseIf (POWERCFG -L | Out-String | Select-String -Pattern 'e9a42b02-d5df-448d-aa00-03f14749eb61') { Invoke-Expression -Command ('POWERCFG -S e9a42b02-d5df-448d-aa00-03f14749eb61') | Out-Null }
            Else { Invoke-Expression -Command ('POWERCFG -S 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c') | Out-Null }
        }

        # Use the total amount of memory installed on the device to modify the svchost.exe split threshold to reduce the amount of svchost.exe processes that run simultaneously.
        $Memory = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1KB
        If ($Memory -is [Double]) { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name SvcHostSplitThresholdInKB -Value $Memory -Force }

        # If the Windows build is 19041, use the new DISM PowerShell cmdlet to disable the Reserved Storage feature for future updates.
        If ($Build -ge 19041 -and (Get-WindowsReservedStorageState | Select-Object -ExpandProperty ReservedStorageState) -ne 'Disabled') { Set-WindowsReservedStorageState -State Disabled }

        <#Try{
            If ($Build -ge 19041 -and (Get-WmiObject -Class Win32_Processor | Select-Object -Property Name).Name.ToLower() -Like "*amd*") {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -Value 3 -Force
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -Value 3 -Force
            }
        } Catch {}#>

        # Remove the dism log file if present.
        If (Test-Path -Path $Env:SystemRoot\Logs\DISM\dism.log) { Remove-Item -Path $Env:SystemRoot\Logs\DISM\dism.log -Force }

        # Clear the DNS Cache
        Invoke-Expression -Command ('NBTSTAT -R') | Out-Null
        Stop-Service -Name Dnscache -Force
        Clear-DnsClientCache
        Start-Service -Name Dnscache

        Add-Type -AssemblyName PresentationFramework
        $RequestReboot = [Windows.MessageBox]::Show("Reboot to make changes effective?", "Restart Computer", "YesNo", "Question")
        If ($RequestReboot -eq [Windows.MessageBoxResult]::Yes)
        {
            Clear-Host
            $ProgressPreference = 'Continue'
            ForEach ($Count In (1 .. 15))
            {
                Write-Progress -Id 1 -Activity "Restarting $Env:COMPUTERNAME" -Status "Restarting in 15 seconds, $(15 - $Count) seconds left" -PercentComplete (($Count / 15) * 100)
                Start-Sleep 1
            }
            Restart-Computer -Force
        }
    }
    End
    {
        # Restore the default preferences.
        $ErrorActionPreference = $DefaultErrorActionPreference
        $ProgressPreference = $DefaultProgressPreference
    }
}

If (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Clear-Host
    Write-Host "Have you inspected this script to make sure nothing is being disabled that will be required by the running system?" -ForegroundColor Yellow
    $VerifyRun = Read-Host "[ y / N ] "
    Switch ($VerifyRun)
    {
        Y { Write-Host "`nSetting Additional Privacy Settings...`n"; Set-Additional }
        N { Write-Host "`nNo, go back."`n; Return }
        Default { Write-Host "`nNo, go back."`n; Return }
    }
}
Else { Write-Warning "This script requires administrative permissions to run."; Exit }

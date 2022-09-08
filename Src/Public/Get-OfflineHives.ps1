Function Get-OfflineHives
{
    [CmdletBinding(DefaultParameterSetName = 'Load')]
    Param
    (
        [Parameter(ParameterSetName = 'Load')]
        [Switch]$Load,
        [Parameter(ParameterSetName = 'Unload')]
        [Switch]$Unload
    )

    Begin
    {
        $Hive = [Ordered]@{
            SOFTWARE = (GetPath -Path $InstallMount -Child 'Windows\System32\Config\SOFTWARE');
            SYSTEM = (GetPath -Path $InstallMount -Child 'Windows\System32\Config\SYSTEM');
            DEFAULT = (GetPath -Path $InstallMount -Child 'Windows\System32\Config\DEFAULT');
            NTUSER = (GetPath -Path $InstallMount -Child 'Users\Default\NTUSER.DAT');
        }
        $HiveMountPoint = [Ordered]@{
            SOFTWARE = 'WIM_HKLM_SOFTWARE';
            SYSTEM = 'WIM_HKLM_SYSTEM';
            DEFAULT = 'WIM_HKU_DEFAULT';
            NTUSER = 'WIM_HKCU';
            SYSTEM_BOOT = 'BOOT_HKLM_SYSTEM';
        }
        If(Test-Path -Path (GetPath -Path $BootMount -Child 'Windows\System32\Config\SYSTEM')) {
            $Hive.SYSTEM_BOOT = (GetPath -Path $BootMount -Child 'Windows\System32\Config\SYSTEM')
        }
        $HKLM = 0x80000002
        'SeBackupPrivilege', 'SeRestorePrivilege' | Grant-Privilege
    }
    Process
    {
        $HivesMounted = $HiveMountPoint.Values.ForEach{ If (Test-Path -LiteralPath $PSItem.Insert(0, 'HKLM:\')) { $true } }
        Switch ($PSCmdlet.ParameterSetName)
        {
            'Load'
            {
                If (!$HivesMounted)
                {
                    $RegLoad = Import-Win32API -Load
                    [Void]$RegLoad::RegLoadKey($HKLM, $HiveMountPoint.SOFTWARE, $Hive.SOFTWARE)
                    [Void]$RegLoad::RegLoadKey($HKLM, $HiveMountPoint.SYSTEM, $Hive.SYSTEM)
                    [Void]$RegLoad::RegLoadKey($HKLM, $HiveMountPoint.DEFAULT, $Hive.DEFAULT)
                    [Void]$RegLoad::RegLoadKey($HKLM, $HiveMountPoint.NTUSER, $Hive.NTUSER)
                    If($Hive.SYSTEM_BOOT) {
                        [Void]$RegLoad::RegLoadKey($HKLM, $HiveMountPoint.SYSTEM_BOOT, $Hive.SYSTEM_BOOT)
                    }
                }
                Break
            }
            'Unload'
            {
                If ($HivesMounted)
                {
                    $RegUnload = Import-Win32API -Unload
                    [GC]::Collect()
                    [GC]::WaitForPendingFinalizers()
                    $Retries = $HiveMountPoint.Values.Count + 1
                    While ($Retries -gt 0 -and $HivesMounted)
                    {
                        $HiveMountPoint.Values.ForEach{ [Void]$RegUnload::RegUnLoadKey($HKLM, $PSItem) }
                        Start-Sleep 1
                        $HivesMounted = $HiveMountPoint.Values.ForEach{ If (Test-Path -LiteralPath $PSItem.Insert(0, 'HKLM:\')) { $true } }
                        If ($HivesMounted) { Start-Sleep 5 }
                        $Retries--
                    }
                }
                Break
            }
        }
    }
    End
    {
        'SeBackupPrivilege', 'SeRestorePrivilege' | Grant-Privilege -Disable
    }
}

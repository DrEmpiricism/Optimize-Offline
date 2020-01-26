Function Get-OfflineHives
{
    [CmdletBinding(DefaultParameterSetName = 'Load')]
    Param
    (
        [Parameter(ParameterSetName = 'Load')]
        [Switch]$Load,
        [Parameter(ParameterSetName = 'Unload')]
        [Switch]$Unload,
        [Parameter(ParameterSetName = 'Test')]
        [Switch]$Test
    )

    Begin
    {
        Set-ErrorAction SilentlyContinue
        $HKLM = 0x80000002
        $Hive = [Ordered]@{
            SOFTWARE = (GetPath -Path $InstallMount -Child 'Windows\System32\Config\SOFTWARE')
            SYSTEM   = (GetPath -Path $InstallMount -Child 'Windows\System32\Config\SYSTEM')
            DEFAULT  = (GetPath -Path $InstallMount -Child 'Windows\System32\Config\DEFAULT')
            NTUSER   = (GetPath -Path $InstallMount -Child 'Users\Default\NTUSER.DAT')
        }
        $HiveMountPoint = [Ordered]@{
            SOFTWARE = 'WIM_HKLM_SOFTWARE'
            SYSTEM   = 'WIM_HKLM_SYSTEM'
            DEFAULT  = 'WIM_HKU_DEFAULT'
            NTUSER   = 'WIM_HKCU'
        }
    }
    Process
    {
        Switch ($PSCmdlet.ParameterSetName)
        {
            'Load'
            {
                $RegLoad = Import-Win32API -Load
                'SeBackupPrivilege', 'SeRestorePrivilege' | Grant-Privilege
                [Void]$RegLoad::RegLoadKey($HKLM, $HiveMountPoint.SOFTWARE, $Hive.SOFTWARE)
                [Void]$RegLoad::RegLoadKey($HKLM, $HiveMountPoint.SYSTEM, $Hive.SYSTEM)
                [Void]$RegLoad::RegLoadKey($HKLM, $HiveMountPoint.DEFAULT, $Hive.DEFAULT)
                [Void]$RegLoad::RegLoadKey($HKLM, $HiveMountPoint.NTUSER, $Hive.NTUSER)
                'SeBackupPrivilege', 'SeRestorePrivilege' | Grant-Privilege -Disable
                Break
            }
            'Unload'
            {
                $RegUnload = Import-Win32API -Unload
                'SeBackupPrivilege', 'SeRestorePrivilege' | Grant-Privilege
                [GC]::Collect()
                [GC]::WaitForPendingFinalizers()
                $HiveMountPoint.Values.ForEach{ [Void]$RegUnload::RegUnLoadKey($HKLM, $PSItem) }
                'SeBackupPrivilege', 'SeRestorePrivilege' | Grant-Privilege -Disable
                Break
            }
            'Test'
            {
                $HiveMountPoint.Values.ForEach{ If (Test-Path -Path $PSItem.Insert(0, 'HKLM:\')) { $true } }
                Break
            }
        }
    }
    End
    {
        Set-ErrorAction -Restore
    }
}

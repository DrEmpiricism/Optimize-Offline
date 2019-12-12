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

    $Hive = [Ordered]@{
        SOFTWARE = (Get-Path -Path $InstallMount -ChildPath 'Windows\System32\Config\SOFTWARE')
        SYSTEM   = (Get-Path -Path $InstallMount -ChildPath 'Windows\System32\Config\SYSTEM')
        DEFAULT  = (Get-Path -Path $InstallMount -ChildPath 'Windows\System32\Config\DEFAULT')
        NTUSER   = (Get-Path -Path $InstallMount -ChildPath 'Users\Default\NTUSER.DAT')
    }

    $HiveMountPoint = [Ordered]@{
        SOFTWARE = 'WIM_HKLM_SOFTWARE'
        SYSTEM   = 'WIM_HKLM_SYSTEM'
        DEFAULT  = 'WIM_HKU_DEFAULT'
        NTUSER   = 'WIM_HKCU'
    }

    $HKLM = 0x80000002

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

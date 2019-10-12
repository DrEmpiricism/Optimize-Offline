Function Get-OfflineHives
{
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param
    (
        [Parameter(ParameterSetName = 'Load')]
        [switch]$Load,
        [Parameter(ParameterSetName = 'Unload')]
        [switch]$Unload,
        [Parameter(ParameterSetName = 'Test')]
        [switch]$Test
    )

    Switch ($PSBoundParameters.Keys)
    {
        'Load'
        {
            @(('HKLM\WIM_HKLM_SOFTWARE "{0}"' -f "$InstallMount\Windows\System32\config\software"), ('HKLM\WIM_HKLM_SYSTEM "{0}"' -f "$InstallMount\Windows\System32\config\system"), ('HKLM\WIM_HKCU "{0}"' -f "$InstallMount\Users\Default\NTUSER.DAT"), ('HKLM\WIM_HKU_DEFAULT "{0}"' -f "$InstallMount\Windows\System32\config\default")) | ForEach-Object -Process { RunExe -Executable $REG -Arguments ('LOAD {0}' -f $($_)) }
            Break
        }
        'Unload'
        {
            [System.GC]::Collect()
            @('HKLM\WIM_HKLM_SOFTWARE', 'HKLM\WIM_HKLM_SYSTEM', 'HKLM\WIM_HKCU', 'HKLM\WIM_HKU_DEFAULT') | ForEach-Object -Process { RunExe -Executable $REG -Arguments ('UNLOAD {0}' -f $($_)) }
            Break
        }
        'Test'
        {
            @('HKLM:\WIM_HKLM_SOFTWARE', 'HKLM:\WIM_HKLM_SYSTEM', 'HKLM:\WIM_HKCU', 'HKLM:\WIM_HKU_DEFAULT') | ForEach-Object -Process { If (Test-Path -Path $($_)) { $true } }
            Break
        }
    }
}
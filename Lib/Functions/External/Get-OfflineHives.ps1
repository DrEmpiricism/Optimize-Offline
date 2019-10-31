Function Get-OfflineHives
{
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param
    (
        [Parameter(ParameterSetName = 'Load')]
        [Switch]$Load,
        [Parameter(ParameterSetName = 'Unload')]
        [Switch]$Unload,
        [Parameter(ParameterSetName = 'Test')]
        [Switch]$Test
    )

    Switch ($PSBoundParameters.Keys)
    {
        'Load'
        {
            @(('HKLM\WIM_HKLM_SOFTWARE "{0}"' -f "$InstallMount\Windows\System32\config\software"), ('HKLM\WIM_HKLM_SYSTEM "{0}"' -f "$InstallMount\Windows\System32\config\system"), ('HKLM\WIM_HKCU "{0}"' -f "$InstallMount\Users\Default\NTUSER.DAT"), ('HKLM\WIM_HKU_DEFAULT "{0}"' -f "$InstallMount\Windows\System32\config\default")) | ForEach-Object -Process { [Void](RunExe $REG -Arguments ('LOAD {0}' -f $($_))) }; Break
        }
        'Unload'
        {
            [GC]::Collect()
            @('HKLM\WIM_HKLM_SOFTWARE', 'HKLM\WIM_HKLM_SYSTEM', 'HKLM\WIM_HKCU', 'HKLM\WIM_HKU_DEFAULT') | ForEach-Object -Process { [Void](RunExe $REG -Arguments ('UNLOAD {0}' -f $($_))) }; Break
        }
        'Test'
        {
            @('HKLM:\WIM_HKLM_SOFTWARE', 'HKLM:\WIM_HKLM_SYSTEM', 'HKLM:\WIM_HKCU', 'HKLM:\WIM_HKU_DEFAULT') | ForEach-Object -Process { If (Test-Path -LiteralPath $($_)) { $true } }; Break
        }
    }
}
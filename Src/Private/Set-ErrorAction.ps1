Function Set-ErrorAction
{
    [CmdletBinding(DefaultParameterSetName = 'Preference')]
    Param
    (
        [Parameter(ParameterSetName = 'Preference',
            Position = 0)]
        [ValidateSet('Stop', 'Inquire', 'Continue', 'Suspend', 'SilentlyContinue')]
        [String]$Preference,
        [Parameter(ParameterSetName = 'Restore',
            Position = 0)]
        [Switch]$Restore
    )

    Switch ($PSCmdlet.ParameterSetName)
    {
        'Preference'
        {
            $Preference = [Enum]::Parse([Management.Automation.ActionPreference], $Preference, $true)
            $Global:ErrorActionPreference = $Preference
            Break
        }
        'Restore'
        {
            $DefaultErrorActionPreference = [Enum]::Parse([Management.Automation.ActionPreference], $DefaultErrorActionPreference, $true)
            $Global:ErrorActionPreference = $DefaultErrorActionPreference
            Break
        }
    }
}
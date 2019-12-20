Function Get-Path
{
    [CmdletBinding(DefaultParameterSetName = 'None')]
    [OutputType([IO.FileSystemInfo])]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [Alias('FullName')]
        [String[]]$Path,
        [Parameter(ParameterSetName = 'Join',
            Position = 1)]
        [String]$ChildPath,
        [Parameter(ParameterSetName = 'Split',
            Position = 1)]
        [ValidateSet('Parent', 'Leaf')]
        [String]$Split = 'Parent'
    )

    Begin
    {
        Set-ErrorAction SilentlyContinue
    }
    Process
    {
        ForEach ($Item In $Path)
        {
            $IsRegistry = $null
            If (Test-Path -LiteralPath $Item)
            {
                If ((Get-Item -LiteralPath $Item -Force -ErrorAction:$ErrorActionPreference) -is [Microsoft.Win32.RegistryKey]) { $IsRegistry = $true }
                Else { $Item = (Get-Item -LiteralPath $Item -Force -ErrorAction:$ErrorActionPreference).FullName }
            }
            If ($PSCmdlet.ParameterSetName -eq 'Join' -and $ChildPath)
            {
                If ($IsRegistry -eq $true) { $PackagePath = Join-Path -Path $Item -ChildPath $ChildPath }
                Else { $PackagePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath((Join-Path -Path $Item -ChildPath $ChildPath)) }
            }
            ElseIf ($PSCmdlet.ParameterSetName -eq 'Split')
            {
                Switch ($PSBoundParameters.Split)
                {
                    'Parent'
                    {
                        If ($IsRegistry -eq $true) { $PackagePath = Split-Path -Path $Item -Parent }
                        Else { $PackagePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath((Split-Path -Path $Item -Parent)) }
                    }
                    'Leaf'
                    {
                        $PackagePath = Split-Path -Path $Item -Leaf
                    }
                }
            }
            Else
            {
                If ($IsRegistry -eq $true) { $PackagePath = $Item }
                Else { $PackagePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Item) }
            }
            If ((Test-Path -LiteralPath $PackagePath) -and $null -eq $IsRegistry) { (Get-Item -LiteralPath $PackagePath -Force -ErrorAction:$ErrorActionPreference).FullName }
            Else { $PackagePath }
        }
    }
    End
    {
        Set-ErrorAction -Restore
    }
}
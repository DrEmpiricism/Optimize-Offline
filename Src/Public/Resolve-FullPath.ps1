Function Resolve-FullPath
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
        [String]$Child,
        [Parameter(ParameterSetName = 'Split',
            Position = 1)]
        [ValidateSet('Parent', 'Leaf')]
        [String]$Split = 'Parent'
    )

    Begin
    {
        $ItemType = @{ Registry = $false; Directory = $false; File = $false }
    }
    Process
    {
        ForEach ($Item In $Path)
        {
            If ((Get-Item -LiteralPath (Split-Path -Path $Item -Qualifier) -ErrorAction:$ErrorActionPreference) -is [Microsoft.Win32.RegistryKey]) { $ItemType.Registry = $true }
            ElseIf ((Get-Item -LiteralPath (Split-Path -Path $Item -Qualifier) -ErrorAction:$ErrorActionPreference) -is [IO.DirectoryInfo]) { $ItemType.Directory = $true }
            Else { $ItemType.File = $true }
            If ($ItemType.ContainsValue($true))
            {
                If ($PSCmdlet.ParameterSetName -eq 'Join' -and $Child)
                {
                    If ($ItemType.Registry) { Join-Path -Path $Item -ChildPath $Child -ErrorAction:$ErrorActionPreference }
                    Else { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath((Join-Path -Path $Item -ChildPath $Child -ErrorAction:$ErrorActionPreference)) }
                }
                ElseIf ($PSCmdlet.ParameterSetName -eq 'Split')
                {
                    Switch ($PSBoundParameters.Split)
                    {
                        'Parent'
                        {
                            If ($ItemType.Registry) { Split-Path -Path $Item -Parent -ErrorAction:$ErrorActionPreference }
                            Else { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath((Split-Path -Path $Item -Parent -ErrorAction:$ErrorActionPreference)) }
                        }
                        'Leaf'
                        {
                            Split-Path -Path $Item -Leaf -ErrorAction:$ErrorActionPreference
                        }
                    }
                }
                Else
                {
                    If ($ItemType.Registry) { $Item }
                    Else { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Item) }
                }
            }
        }
    }
}
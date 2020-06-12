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
        [Alias('FullName', 'PSPath')]
        [String[]]$Path,
        [Parameter(ParameterSetName = 'Join',
            Position = 1)]
        [String]$Child,
        [Parameter(ParameterSetName = 'Split',
            Position = 1)]
        [ValidateSet('Parent', 'Leaf')]
        [String]$Split = 'Parent'
    )

    Process
    {
        ForEach ($Item In $Path)
        {
            Try
            {
                $Item = (Resolve-Path -Path ([Environment]::ExpandEnvironmentVariables($Item)) -ErrorAction Stop).Path
            }
            Catch [Management.Automation.ItemNotFoundException]
            {
                $Item = [Environment]::ExpandEnvironmentVariables($PSItem.TargetObject)
                $Global:Error.RemoveAt(0)
            }
            If ($Item)
            {
                Switch ($PSCmdlet.ParameterSetName)
                {
                    'Join' { Join-Path -Path $Item -ChildPath $Child -ErrorAction:$ErrorActionPreference; Break }
                    'Split'
                    {
                        Switch ($PSBoundParameters.Split)
                        {
                            'Parent' { Split-Path -Path $Item -Parent -ErrorAction:$ErrorActionPreference; Break }
                            'Leaf' { Split-Path -Path $Item -Leaf -ErrorAction:$ErrorActionPreference; Break }
                        }
                        Break
                    }
                    Default { $Item; Break }
                }
            }
        }
    }
}
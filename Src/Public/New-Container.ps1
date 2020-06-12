Function New-Container
{
    [CmdletBinding()]
    [OutputType([IO.FileSystemInfo])]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Alias('FullName', 'PSPath')]
        [String[]]$Path,
        [Switch]$PassThru
    )

    Process
    {
        ForEach ($Item In $Path)
        {
            If (!(Test-Path -LiteralPath $Item))
            {
                $RET = New-Item -Path $Item -ItemType Directory -Force -ErrorAction:$ErrorActionPreference
                If ($PassThru.IsPresent) { $RET }
            }
        }
    }
}
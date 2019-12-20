Function Export-DataFile
{
    [CmdletBinding()]
    [OutputType([IO.FileInfo])]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 0)]
        [PSObject]$Data,
        [Parameter(Mandatory = $true,
            Position = 1)]
        [String]$File,
        [Switch]$PassThru
    )

    Process
    {
        If ([IO.Path]::GetExtension($File) -ne '.XML') { $File = [IO.Path]::ChangeExtension($File, '.xml') }
        Export-Clixml -InputObject $Data -Path (Get-Path -Path $WorkFolder -ChildPath $File) -Force -ErrorAction:$ErrorActionPreference
        If ($PassThru.IsPresent) { Get-Path -Path $WorkFolder -ChildPath $File }
    }
}
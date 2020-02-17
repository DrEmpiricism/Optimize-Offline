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
        $Data | Export-Clixml -Path (GetPath -Path $WorkFolder -Child $File) -Force -ErrorAction SilentlyContinue
        If ($PassThru.IsPresent) { GetPath -Path $WorkFolder -Child $File }
    }
}
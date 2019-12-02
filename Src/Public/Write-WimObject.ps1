Function Write-WimObject
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true)]
        [PSCustomObject]$WimObject
    )

    Process
    {
        $WimObject | Add-Member -MemberType NoteProperty -Name Optimized -Value (Get-Date -Format 'G')
        $WimObject.PSTypeNames.Insert(0, 'System.IO.FileInfo.Wim')
        $WimObject
    }
}
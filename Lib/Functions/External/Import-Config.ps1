Function Import-Config
{
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param ()

    $ConfigObj = [PSCustomObject]@{ }
    Get-Content -Path $ConfigFilePath | ForEach-Object -Process {
        If (!$_.StartsWith('#') -and $_ -match '=')
        {
            $Data = $_.Split('=').Trim()
            If ($Data[1].Equals('False')) { Remove-Variable Data; Return }
            If ($Data[1].Equals('True')) { [Switch]$Data[1] = [Convert]::ToBoolean($Data[1]) }
            $ConfigObj | Add-Member -MemberType NoteProperty -Name $Data[0] -Value $Data[1]
        }
    }
    $ConfigObj
}
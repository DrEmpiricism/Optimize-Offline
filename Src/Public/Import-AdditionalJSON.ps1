Function Import-AdditionalJSON
{
    [CmdletBinding()]
    Param ()

    $AdditionalJSON = Get-Content -Path $AdditionalPath.AdditionalJson -Raw | ConvertFrom-Json
    $AdditionalParams = @{ }
    ForEach ($Member In (Get-Member -InputObject $AdditionalJSON -MemberType NoteProperty))
    {
        $Key = $Member.Name
        $Value = $AdditionalJSON.$Key
        $AdditionalParams.Add($Key, $Value)
    }
    $AdditionalParams
}
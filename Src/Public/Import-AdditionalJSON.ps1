Function Import-AdditionalJSON
{
    [CmdletBinding()]
    Param ()

    $AdditionalJSON = Get-Content -Path $OptimizeOffline.AdditionalJSON -Raw -ErrorAction:$ErrorActionPreference | ConvertFrom-Json -ErrorAction:$ErrorActionPreference
    $AdditionalParams = @{ }
    ForEach ($Node In Get-Member -InputObject $AdditionalJSON -MemberType NoteProperty)
    {
        $Key = $Node.Name
        $Value = $AdditionalJSON.$Key
        $AdditionalParams.Add($Key, $Value)
    }
    $AdditionalParams
}
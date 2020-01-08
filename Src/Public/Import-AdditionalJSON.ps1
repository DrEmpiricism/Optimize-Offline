Function Import-AdditionalJSON
{
    [CmdletBinding()]
    Param ()

    Begin
    {
        Set-ErrorAction SilentlyContinue
    }
    Process
    {
        $AdditionalJSON = Get-Content -Path $OptimizeOffline.AdditionalJSON -Raw -ErrorAction:$ErrorActionPreference | ConvertFrom-Json -ErrorAction:$ErrorActionPreference
        $AdditionalParams = @{ }
        ForEach ($Node In Get-Member -InputObject $AdditionalJSON -MemberType NoteProperty -ErrorAction:$ErrorActionPreference)
        {
            $Key = $Node.Name
            $Value = $AdditionalJSON.$Key
            $AdditionalParams.Add($Key, $Value)
        }
        $AdditionalParams
    }
    End
    {
        Set-ErrorAction -Restore
    }
}
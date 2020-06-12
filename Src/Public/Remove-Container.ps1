Function Remove-Container
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Alias('FullName', 'PSPath')]
        [String[]]$Path,
        [Switch]$Force
    )

    Begin
    {
        If ($Force.IsPresent) { 'SeTakeOwnershipPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege' | Grant-Privilege }
    }
    Process
    {
        ForEach ($Item In $Path)
        {
            If (Test-Path -LiteralPath $Item) { Remove-Item -LiteralPath $Item -Recurse -Force -ErrorAction:$ErrorActionPreference }
        }
    }
    End
    {
        If ($Force.IsPresent) { 'SeTakeOwnershipPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege' | Grant-Privilege -Disable }
    }
}
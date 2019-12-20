Function Optimize-InstallMedia
{
    [CmdletBinding()]
    Param ()

    Begin
    {
        Set-ErrorAction SilentlyContinue
    }
    Process
    {
        $ISOMedia = Import-DataFile -ISOMedia -ErrorAction:$ErrorActionPreference
        $InstallInfo = Import-DataFile Install -ErrorAction:$ErrorActionPreference
        Get-ChildItem -Path $ISOMedia.FullName -Filter *.dll | Purge
        @("$($ISOMedia.FullName)\autorun.inf", "$($ISOMedia.FullName)\setup.exe", "$($ISOMedia.FullName)\ca", "$($ISOMedia.FullName)\NanoServer", "$($ISOMedia.FullName)\support", "$($ISOMedia.FullName)\upgrade") | Purge
        Get-ChildItem -Path "$($ISOMedia.FullName)\sources" -Exclude sxs -Directory | Where-Object -Property Name -NE $InstallInfo.Language | Purge
        @('.adml', '.mui', '.rtf', '.txt') | ForEach-Object -Process { Get-ChildItem -Path "$($ISOMedia.FullName)\sources\$($InstallInfo.Language)" -Filter *$PSItem -Exclude setup.exe.mui -Recurse | Purge }
        @('.dll', '.gif', '.xsl', '.bmp', '.mof', '.ini', '.cer', '.exe', '.sdb', '.txt', '.nls', '.xml', '.cat', '.inf', '.sys', '.bin', '.ait', '.admx', '.dat', '.ttf', '.cfg', '.xsd', '.rtf', '.xrm-ms') | ForEach-Object -Process { Get-ChildItem -Path "$($ISOMedia.FullName)\sources" -Filter *$PSItem -Exclude @('EI.cfg', 'gatherosstate.exe', 'setup.exe', 'lang.ini', 'pid.txt', '*.clg') -Recurse | Purge }
        If ($DynamicParams.NetFx3) { "$($ISOMedia.FullName)\sources\sxs" | Purge }
    }
    End
    {
        Set-ErrorAction -Restore
    }
}
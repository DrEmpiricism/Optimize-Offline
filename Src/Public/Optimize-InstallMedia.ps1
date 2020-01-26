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
        $ISOMedia = Import-DataFile -ISOMedia
        $InstallInfo = Import-DataFile Install
        $ISOSources = (GetPath -Path $ISOMedia.FullName -Child sources)
        @((Get-ChildItem -Path $ISOMedia.FullName -Filter *.dll), (GetPath -Path $ISOMedia.FullName -Child autorun.inf), (GetPath -Path $ISOMedia.FullName -Child setup.exe), (GetPath -Path $ISOMedia.FullName -Child ca), (GetPath -Path $ISOMedia.FullName -Child NanoServer), (GetPath -Path $ISOMedia.FullName -Child support), (GetPath -Path $ISOMedia.FullName -Child upgrade), (Get-ChildItem -Path $ISOSources -Exclude sxs -Directory | Where-Object -Property Name -NE $InstallInfo.Language)) | Purge
        @('.adml', '.mui', '.rtf', '.txt') | ForEach-Object -Process { Get-ChildItem -Path (GetPath -Path $ISOSources -Child $InstallInfo.Language) -Filter *$PSItem -Exclude setup.exe.mui -Recurse | Purge }
        @('.dll', '.gif', '.xsl', '.bmp', '.mof', '.ini', '.cer', '.exe', '.sdb', '.txt', '.nls', '.xml', '.cat', '.inf', '.sys', '.bin', '.ait', '.admx', '.dat', '.ttf', '.cfg', '.xsd', '.rtf', '.xrm-ms') | ForEach-Object -Process { Get-ChildItem -Path $ISOSources -Filter *$PSItem -Exclude @('EI.cfg', 'gatherosstate.exe', 'setup.exe', 'lang.ini', 'pid.txt', '*.clg') -Recurse | Purge }
        If ($DynamicParams.NetFx3) { (GetPath -Path $ISOSources -Child sxs) | Purge }
    }
    End
    {
        Set-ErrorAction -Restore
    }
}
Function Optimize-InstallMedia
{
    [CmdletBinding()]
    Param ()

    $ISOMedia = Import-DataFile -ISOMedia -ErrorAction:$ErrorActionPreference
    $InstallInfo = Import-DataFile Install -ErrorAction:$ErrorActionPreference
    $ISOSources = (GetPath -Path $ISOMedia.FullName -Child sources -ErrorAction:$ErrorActionPreference)
    @((Get-ChildItem -Path $ISOMedia.FullName -Filter *.dll), (GetPath -Path $ISOMedia.FullName -Child autorun.inf), (GetPath -Path $ISOMedia.FullName -Child setup.exe), (GetPath -Path $ISOMedia.FullName -Child ca), (GetPath -Path $ISOMedia.FullName -Child NanoServer), (GetPath -Path $ISOMedia.FullName -Child support), (GetPath -Path $ISOMedia.FullName -Child upgrade), (GetPath -Path $ISOSources -Child uup), (Get-ChildItem -Path $ISOSources -Exclude sxs -Directory | Where-Object -Property Name -NE $InstallInfo.Language)) | Purge -ErrorAction:$ErrorActionPreference
    @('.adml', '.mui', '.rtf', '.txt') | ForEach-Object -Process { Get-ChildItem -Path (GetPath -Path $ISOSources -Child $InstallInfo.Language) -Filter *$PSItem -Exclude setup.exe.mui -Recurse | Purge -ErrorAction SilentlyContinue }
    @('.dll', '.gif', '.xsl', '.bmp', '.mof', '.ini', '.cer', '.exe', '.sdb', '.txt', '.nls', '.xml', '.cat', '.inf', '.sys', '.bin', '.ait', '.admx', '.dat', '.ttf', '.cfg', '.xsd', '.rtf', '.xrm-ms') | ForEach-Object -Process { Get-ChildItem -Path $ISOSources -Filter *$PSItem -Exclude @('EI.cfg', 'gatherosstate.exe', 'setup.exe', 'lang.ini', 'pid.txt', '*.clg') -Recurse | Purge -ErrorAction:$ErrorActionPreference }
    If ($DynamicParams.NetFx3) { (GetPath -Path $ISOSources -Child sxs) | Purge -ErrorAction:$ErrorActionPreference }
}
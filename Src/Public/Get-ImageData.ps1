Function Get-ImageData
{
    [CmdletBinding(DefaultParameterSetName = 'ImageData')]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter(ParameterSetName = 'ImageData',
            Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 0)]
        [IO.FileInfo]$ImageFile,
        [Parameter(ParameterSetName = 'ImageData',
            Mandatory = $false,
            Position = 1)]
        [Int]$Index = 1,
        [Parameter(ParameterSetName = 'Update')]
        [Switch]$Update
    )

    Process
    {
        Switch ($PSCmdlet.ParameterSetName)
        {
            'ImageData'
            {
                $ArchString = @{ [UInt32]0 = 'x86'; [UInt32]5 = 'arm'; [UInt32]6 = 'ia64'; [UInt32]9 = 'amd64'; [UInt32]12 = 'arm64' }
                $ImageDataFile = $ImageFile.BaseName.Replace($ImageFile.BaseName[0], $ImageFile.BaseName[0].ToString().ToUpper()).Insert($ImageFile.BaseName.Length, 'Info.xml')
                $ImageInfo = (Get-WindowsImage -ImagePath $ImageFile.FullName -Index $Index -ScratchDirectory $ScratchFolder -LogPath $DISMLog -LogLevel 1 -ErrorAction:$ErrorActionPreference)
                $ImageData = [PSCustomObject][Ordered]@{
                    Path             = $ImageInfo.ImagePath
                    Index            = $ImageInfo.ImageIndex
                    Name             = $ImageInfo.ImageName
                    Description      = $ImageInfo.ImageDescription
                    Size             = '{0:N2} GB' -f ($ImageInfo.ImageSize / 1GB)
                    Edition          = $ImageInfo.EditionID
                    VersionTable     = [PSCustomObject][Ordered]@{ Major = $ImageInfo.MajorVersion; Minor = $ImageInfo.MinorVersion; Build = $ImageInfo.Build; SPBuild = $ImageInfo.SPBuild }
                    Version          = $ImageInfo.Version
                    Build            = $ImageInfo.Build
                    Release          = $null
                    CodeName         = $null
                    Architecture     = $ArchString[$ImageInfo.Architecture]
                    Language         = $ImageInfo.Languages[$ImageInfo.DefaultLanguageIndex]
                    InstallationType = $ImageInfo.InstallationType
                    Created          = $ImageInfo.CreatedTime
                }
                If ($ImageFile.BaseName -ne 'install') { @('VersionTable', 'Release', 'CodeName', 'Created') | ForEach-Object -Process { $ImageData.PSObject.Properties.Remove($PSItem) } }
                $ImageData | Export-DataFile -File $ImageDataFile -ErrorAction:$ErrorActionPreference
                Break
            }
            'Update'
            {
                $ImageData = Import-DataFile Install -ErrorAction:$ErrorActionPreference
                $CurrentVersion = Import-DataFile -CurrentVersion -ErrorAction:$ErrorActionPreference
                If ($ImageData.Build -eq '18362' -and $CurrentVersion.CurrentBuildNumber -eq '18363')
                {
                    $ImageData.Version = $ImageData.Version.Replace($ImageData.Build, $CurrentVersion.CurrentBuildNumber)
                    $ImageData.Build = $CurrentVersion.CurrentBuildNumber
                    If ($CurrentVersion.BuildBranch.ToUpper().Split('_')[0] -eq '19H1') { $ImageData.CodeName = '19H2' }
                }
                ElseIf ($ImageData.Build -eq '19041' -and $CurrentVersion.CurrentBuildNumber -eq '19042')
                {
                    $ImageData.Version = $ImageData.Version.Replace($ImageData.Build, $CurrentVersion.CurrentBuildNumber)
                    $ImageData.Build = $CurrentVersion.CurrentBuildNumber
                    If ($CurrentVersion.DisplayVersion -eq '20H2') { $ImageData.CodeName = $CurrentVersion.DisplayVersion }
                }
                ElseIf ($ImageData.Build -eq '19041' -and $CurrentVersion.CurrentBuildNumber -eq '19043')
                {
                    $ImageData.Version = $ImageData.Version.Replace($ImageData.Build, $CurrentVersion.CurrentBuildNumber)
                    $ImageData.Build = $CurrentVersion.CurrentBuildNumber
                    If ($CurrentVersion.DisplayVersion -eq '21H1') { $ImageData.CodeName = $CurrentVersion.DisplayVersion }
                }
                ElseIf ($ImageData.Build -eq '19041' -and $CurrentVersion.CurrentBuildNumber -eq '19044')
                {
                    $ImageData.Version = $ImageData.Version.Replace($ImageData.Build, $CurrentVersion.CurrentBuildNumber)
                    $ImageData.Build = $CurrentVersion.CurrentBuildNumber
                    If ($CurrentVersion.DisplayVersion -eq '21H2') { $ImageData.CodeName = $CurrentVersion.DisplayVersion }
                }
                Else
                {
                    If ($ImageData.Build -eq '19041') { $ImageData.CodeName = '20H1' }
                    Else { $ImageData.CodeName = $CurrentVersion.BuildBranch.ToUpper().Split('_')[0] }
                }
                $ImageData.Release = $CurrentVersion.ReleaseId
                @('Path', 'Index', 'VersionTable') | ForEach-Object -Process { $ImageData.PSObject.Properties.Remove($PSItem) }
                $ImageData.PSObject.TypeNames.Insert(0, 'System.IO.Optimized.Wim')
                $ImageData | Add-Member -MemberType NoteProperty -Name Optimized -Value (Get-Date -Format 'G')
                $ImageData | Export-DataFile -File InstallInfo -ErrorAction:$ErrorActionPreference
                Break
            }
        }
        $ImageData
    }
}
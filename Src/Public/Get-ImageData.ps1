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
        If ($PSCmdlet.ParameterSetName -eq 'ImageData')
        {
            $ArchString = @{ [UInt32]0 = 'x86'; [UInt32]5 = 'arm'; [UInt32]6 = 'ia64'; [UInt32]9 = 'amd64'; [UInt32]12 = 'arm64' }
            $ImageDataFile = $ImageFile.BaseName.Replace($ImageFile.BaseName[0], $ImageFile.BaseName[0].ToString().ToUpper()).Insert($ImageFile.BaseName.Length, 'Info.xml')
            $ImageInfo = (Get-WindowsImage -ImagePath $ImageFile.FullName -Index $Index -ErrorAction:$ErrorActionPreference)
            $ImageData = [PSCustomObject][Ordered]@{
                Path             = $ImageInfo.ImagePath
                Index            = $ImageInfo.ImageIndex
                Name             = $ImageInfo.ImageName
                Description      = $ImageInfo.ImageDescription
                Size             = [Math]::Round($ImageInfo.ImageSize / 1GB).ToString() + " GB"
                Edition          = $ImageInfo.EditionID
                Version          = $ImageInfo.Version
                Build            = $ImageInfo.Build
                Release          = $null
                CodeName         = $null
                Architecture     = $ArchString[$ImageInfo.Architecture]
                Language         = $ImageInfo.Languages[$ImageInfo.DefaultLanguageIndex]
                InstallationType = $ImageInfo.InstallationType
                Created          = $ImageInfo.CreatedTime
            }
            If ($ImageFile.Name -ne 'install.wim') { @('Release', 'CodeName', 'Created') | ForEach-Object -Process { $ImageData.PSObject.Properties.Remove($PSItem) } }
            $ImageData | Export-Clixml -Path (Get-Path -Path $WorkFolder -ChildPath $ImageDataFile) -ErrorAction:$ErrorActionPreference
        }
        ElseIf ($PSCmdlet.ParameterSetName -eq 'Update')
        {
            If (!(Get-ChildItem -Path $WorkFolder -Include InstallInfo.xml, CurrentVersion.xml -Recurse -File)) { Return }
            $ImageData = Import-Clixml -Path (Get-Path -Path $WorkFolder -ChildPath InstallInfo.xml) -ErrorAction:$ErrorActionPreference
            $CurrentVersion = Import-Clixml -Path (Get-Path -Path $WorkFolder -ChildPath CurrentVersion.xml) -ErrorAction:$ErrorActionPreference
            If ($ImageData.Build -eq '18362' -and $CurrentVersion.CurrentBuildNumber -eq '18363')
            {
                $ImageData.Version = $ImageData.Version.Replace($ImageData.Build, $CurrentVersion.CurrentBuildNumber)
                $ImageData.Build = $CurrentVersion.CurrentBuildNumber
            }
            $ImageData.Release = $CurrentVersion.ReleaseID
            If ($CurrentVersion.CurrentBuildNumber -eq '18363' -and $CurrentVersion.BuildBranch.ToUpper().Split('_')[0] -eq '19H1') { $ImageData.CodeName = '19H2' }
            Else { $ImageData.CodeName = $CurrentVersion.BuildBranch.ToUpper().Split('_')[0] }
            @('Path', 'Index') | ForEach-Object -Process { $ImageData.PSObject.Properties.Remove($PSItem) }
            $ImageData.PSObject.TypeNames.Insert(0, 'System.IO.Optimized.Wim')
            $ImageData | Add-Member -MemberType NoteProperty -Name Optimized -Value (Get-Date -Format 'G')
            $ImageData | Export-Clixml -Path (Get-Path -Path $WorkFolder -ChildPath InstallInfo.xml) -Force -ErrorAction:$ErrorActionPreference
        }
        $ImageData
    }
}
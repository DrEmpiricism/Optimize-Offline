Function Get-WimFile
{
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [IO.FileInfo]$WimFile,
        [Parameter(Mandatory = $false)]
        [Int]$Index = 1
    )

    $WimArch = [Ordered]@{
        '0'  = 'x86'
        '5'  = 'arm'
        '6'  = 'ia64'
        '9'  = 'amd64'
        '12' = 'arm64'
    }
    $WimImage = (Get-WindowsImage -ImagePath $WimFile.FullName -Index $Index)
    $WimObject = [PSCustomObject]@{
        Name             = $($WimImage.ImageName)
        Description      = $($WimImage.ImageDescription)
        Size             = [Math]::Round($WimImage.ImageSize / 1GB).ToString() + " GB"
        Edition          = $($WimImage.EditionID)
        Version          = $($WimImage.Version)
        Build            = $($WimImage.Build).ToString()
        Architecture     = $WimArch[$($WimImage.Architecture.ToString())]
        Language         = $($WimImage.Languages)
        InstallationType = $($WimImage.InstallationType)
        Created          = $($WimImage.CreatedTime)
    }
    $WimObject
}
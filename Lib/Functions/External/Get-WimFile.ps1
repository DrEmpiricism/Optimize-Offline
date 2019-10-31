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

    $WimImage = (Get-WindowsImage -ImagePath $WimFile.FullName -Index $Index)
    $WimObject = [PSCustomObject]@{
        Name             = $($WimImage.ImageName)
        Description      = $($WimImage.ImageDescription)
        Size             = [Math]::Round($WimImage.ImageSize / 1GB).ToString() + " GB"
        Edition          = $($WimImage.EditionID)
        Version          = $($WimImage.Version)
        Build            = $($WimImage.Build).ToString()
        InstallationType = $($WimImage.InstallationType)
        Language         = $($WimImage.Languages)
    }
    If ($WimImage.Architecture -eq 9) { $WimObject | Add-Member -MemberType NoteProperty -Name Architecture -Value $($WimImage.Architecture -replace '9', 'amd64') }
    $WimObject
}
Function Set-LockScreen
{
    [CmdletBinding()]
    Param ()

    Try
    {
        Log $OptimizeData.ApplyingLockScreen
        $JPGImage = Get-ChildItem -Path $OptimizeOffline.LockScreen -Filter *.jpg | Select-Object -First 1 | Copy-Item -Destination (GetPath -Path $WorkFolder -Child img100.jpg) -PassThru -Force -ErrorAction Stop
        $PNGImage = GetPath -Path $WorkFolder -Child ([IO.Path]::ChangeExtension($JPGImage.BaseName.Replace('100', '103'), '.png'))
        Add-Type -AssemblyName System.Windows.Forms, System.Drawing -ErrorAction Stop
        $Bitmap = New-Object System.Drawing.Bitmap($JPGImage.FullName) -ErrorAction Stop
        $FileStream = [IO.File]::Create($PNGImage)
        $Bitmap.Save($FileStream, 'png')
    }
    Catch
    {
        Log $OptimizeData.FailedApplyingLockScreen -Type Error -ErrorRecord $Error[0]
        Return
    }
    Finally
    {
        If ($FileStream) { $FileStream.Close(); $FileStream.Dispose() }
        If ($Bitmap) { $Bitmap.Dispose() }
    }
    $InstallLockScreenImage = GetPath -Path $InstallMount -Child 'Windows\Web\Screen\img100.jpg'
    $InstallSignOutImage = GetPath -Path $InstallMount -Child 'Windows\Web\Screen\img103.png'
    $WorkLockScreenImage = GetPath -Path $WorkFolder -Child img100.jpg
    $WorkSignOutImage = GetPath -Path $WorkFolder -Child img103.png
    If ((Test-Path -Path $InstallLockScreenImage) -and (Test-Path -Path $InstallSignOutImage) -and (Test-Path -Path $WorkLockScreenImage) -and (Test-Path -Path $WorkSignOutImage))
    {
        $BKPImage = Get-ChildItem -Path (GetPath -Path $InstallLockScreenImage -Split Parent) -Include img100.jpg, img103.png -Recurse -Force | ForEach-Object -Process { Copy-Item -Path $PSItem.FullName -Destination (GetPath -Path $WorkFolder -Child $PSItem.Name.Insert($PSItem.Name.Length, '.bkp')) -PassThru -Force -ErrorAction SilentlyContinue }
        $ACL = Get-Acl -Path $InstallLockScreenImage -ErrorAction SilentlyContinue
        Try
        {
            Get-ChildItem -Path (GetPath -Path $InstallLockScreenImage -Split Parent) -Include img100.jpg, img103.png -Recurse -Force | Purge -Force -ErrorAction Stop
            $WorkLockScreenImage, $WorkSignOutImage | Copy-Item -Destination (GetPath -Path $InstallLockScreenImage -Split Parent) -Force -ErrorAction Stop
        }
        Catch
        {
            Log $OptimizeData.FailedApplyingLockScreen -Type Error -ErrorRecord $Error[0]
            $BKPImage | ForEach-Object -Process { Copy-Item -Path $PSItem.FullName -Destination (GetPath -Path (GetPath -Path $InstallLockScreenImage -Split Parent) -Child $PSItem.Name.Replace('.bkp', $null)) -Force -ErrorAction SilentlyContinue }
        }
        Finally
        {
            $ACL | Set-Acl -Path $InstallLockScreenImage -Passthru -ErrorAction SilentlyContinue | Set-Acl -Path $InstallSignOutImage -ErrorAction SilentlyContinue
        }
    }
}
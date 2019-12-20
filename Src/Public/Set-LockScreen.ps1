Function Set-LockScreen
{
    [CmdletBinding()]
    Param ()

    $JPGImage = Get-ChildItem -Path $OptimizeOffline.LockScreen -Filter *.jpg | Select-Object -First 1 | Copy-Item -Destination (Get-Path -Path $WorkFolder -ChildPath img100.jpg) -PassThru -Force
    $PNGImage = Get-Path -Path $WorkFolder -ChildPath ([IO.Path]::ChangeExtension($JPGImage.BaseName.Replace('100', '103'), '.png'))
    Try
    {
        Add-Type -AssemblyName System.Windows.Forms, System.Drawing -ErrorAction Stop
        $Bitmap = New-Object System.Drawing.Bitmap($JPGImage.FullName) -ErrorAction Stop
        $FileStream = [IO.File]::Create($PNGImage)
        $Bitmap.Save($FileStream, 'png')
    }
    Catch
    {
        Log -Error $OptimizedData.FailedApplyingLockScreen
        Start-Sleep 3
        Return
    }
    Finally
    {
        If ($FileStream) { $FileStream.Close(); $FileStream.Dispose() }
        If ($Bitmap) { $Bitmap.Dispose() }
    }
    If ((Test-Path -Path "$InstallMount\Windows\Web\Screen\img100.jpg") -and (Test-Path -Path "$InstallMount\Windows\Web\Screen\img103.png"))
    {
        If ((Test-Path -Path (Get-Path -Path $WorkFolder -ChildPath img100.jpg)) -and (Test-Path -Path (Get-Path -Path $WorkFolder -ChildPath img103.png)))
        {
            $BKPImage = Get-ChildItem -Path "$InstallMount\Windows\Web\Screen" -Include img100.jpg, img103.png -Recurse -Force | ForEach-Object -Process { Copy-Item -Path $PSItem.FullName -Destination (Get-Path -Path $WorkFolder -ChildPath $PSItem.Name.Insert($PSItem.Name.Length, '.bkp')) -PassThru -Force -ErrorAction SilentlyContinue }
            $ACL = Get-Acl -Path "$InstallMount\Windows\Web\Screen\img100.jpg"
            Try
            {
                Get-ChildItem -Path "$InstallMount\Windows\Web\Screen" -Include img100.jpg, img103.png -Recurse -Force | Purge -Force
                Get-ChildItem -Path $WorkFolder -Include img100.jpg, img103.png -Recurse | Copy-Item -Destination "$InstallMount\Windows\Web\Screen" -Force -ErrorAction Stop
            }
            Catch
            {
                Log -Error $OptimizedData.FailedApplyingLockScreen
                $BKPImage | ForEach-Object -Process { Copy-Item -Path $PSItem.FullName -Destination (Get-Path -Path "$InstallMount\Windows\Web\Screen" -ChildPath $PSItem.Name.Replace('.bkp', $null)) -Force -ErrorAction SilentlyContinue }
                Return
            }
            Finally
            {
                $ACL | Set-Acl -Path "$InstallMount\Windows\Web\Screen\img100.jpg" -Passthru -ErrorAction SilentlyContinue | Set-Acl -Path "$InstallMount\Windows\Web\Screen\img103.png" -ErrorAction SilentlyContinue
            }
        }
    }
}
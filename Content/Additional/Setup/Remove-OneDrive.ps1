Function Remove-OneDrive
{
    [CmdletBinding()]
    Param ()

    Begin
    {
        $EAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'
        $ProgressPreference = 'SilentlyContinue'
    }
    Process
    {
        Clear-Host
        Write-Host "Performing a full removal of Microsoft OneDrive..." -NoNewline -ForegroundColor Cyan

        # Stops the OneDrive processes and uninstalls the OneDriveSetup application.
        Get-Process | Where-Object Name -Like "OneDrive*" | Stop-Process -Force
        Get-Service | Where-Object Name -Like "OneSyncSvc*" | Stop-Service -Force -NoWait
        $OneDrive = "$Env:SystemRoot\SysWOW64\OneDriveSetup.exe"
        If (!(Test-Path -Path $OneDrive)) { $OneDrive = "$Env:SystemRoot\System32\OneDriveSetup.exe" }
        Start-Process -FilePath $OneDrive -ArgumentList ('/Uninstall') -Wait
        Start-Sleep 2

        # Removes the OneDrive folder from the Navigation Pane.
        If (!(Test-Path -Path "HKCR:"))
        {
            [void](New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT)
            [void](New-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -ItemType Directory -Force)
            [void](New-Item -Path "HKCR:\WOW6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -ItemType Directory -Force)
            Set-ItemProperty -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Type DWord
            Set-ItemProperty -Path "HKCR:\WOW6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Type DWord
            Remove-PSDrive -Name HKCR
        }
        Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -Force

        # Removes the OneDrive auto-run hook and File Explorer namespace from the default user profile and the current user registry hive.
        $DefaultUser = Join-Path -Path (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" -Name Default | Select-Object -ExpandProperty Default) -ChildPath NTUSER.DAT
        Start-Process -FilePath REG -ArgumentList ('LOAD HKLM\DEFAULT_USER "{0}"' -f $DefaultUser) -WindowStyle Hidden -Wait
        Remove-ItemProperty -Path "HKLM:\DEFAULT_USER\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveSetup" -Force
        [void](New-Item -Path "HKLM:\DEFAULT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" -ItemType Directory -Force)
        Set-ItemProperty -Path "HKLM:\DEFAULT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" -Name "OneDrive" -Value ([Byte[]](0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)) -Type Binary
        Start-Process -FilePath REG -ArgumentList ('REG UNLOAD HKLM\DEFAULT_USER') -WindowStyle Hidden -Wait

        # Disables OneDrive policies.
        [void](New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -ItemType Directory -Force)
        [void](New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\OneDrive" -ItemType Directory -Force)
        [void](New-Item -Path "HKCU:\SOFTWARE\Microsoft\OneDrive" -ItemType Directory -Force)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "PreventNetworkTrafficPreUserSignIn" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSync" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableMeteredNetworkFileSync" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\OneDrive" -Name "DisableMeteredNetworkFileSync" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableLibrariesDefaultSaveToOneDrive" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\OneDrive" -Name "DisableLibrariesDefaultSaveToOneDrive" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\OneDrive" -Name "DisablePersonalSync" -Value 1 -Type DWord

        # Removes OneDrive directories, Start Menu shell link and global environmental variable.
        Remove-Item -Path "$Env:LOCALAPPDATA\Microsoft\OneDrive" -Recurse -Force
        Remove-Item -Path "$Env:PROGRAMDATA\Microsoft OneDrive" -Recurse -Force
        Remove-Item -Path "$Env:SYSTEMDRIVE\OneDriveTemp" -Recurse -Force
        If ((Get-ChildItem -Path "$Env:USERPROFILE\OneDrive" -Recurse | Measure-Object).Count -eq 0) { Remove-Item -Path "$Env:USERPROFILE\OneDrive" -Recurse -Force }
        Remove-Item -Path "$Env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force
        Remove-Item Env:OneDrive

        # Removes the OneDrive component store items.
        ForEach ($Item in Get-ChildItem -Path $Env:SystemRoot\WinSxS -Filter *OneDrive*)
        {
            Start-Process -FilePath TAKEOWN -ArgumentList ('/F "{0}" /A /R /D Y' -f $($Item.FullName)) -WindowStyle Hidden -Wait
            Start-Process -FilePath ICACLS -ArgumentList ('"{0}" /GRANT *S-1-5-32-544:F /T /C' -f $($Item.FullName)) -WindowStyle Hidden -Wait
            Remove-Item -Path $($Item.FullName) -Recurse -Force
        }
        Get-Process -Name explorer | Stop-Process -Force
        Write-Host "[Complete]" -ForegroundColor Cyan
    }
    End
    {
        $ErrorActionPreference = $EAP
    }
}
Remove-OneDrive
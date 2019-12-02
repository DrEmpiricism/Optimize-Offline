Function Import-RegistryTemplates
{
    [CmdletBinding()]
    Param ()

    Begin
    {
        Get-ChildItem -Path $AdditionalPath.RegistryTemplates -Filter *.Offline | Purge
        [IO.FileInfo]$RegistryLog = $RegistryLog
        RegHives -Load
    }
    Process
    {
        If (!$RegistryLog.Exists) { $RegistryLog = New-Item -Path $RegistryLog -ItemType File -Force }
        Get-ChildItem -Path $AdditionalPath.RegistryTemplates -Filter *.reg | ForEach-Object -Process {
            $REGContent = Get-Content -Path $($PSItem.FullName)
            $REGContent = $REGContent -replace 'HKEY_LOCAL_MACHINE\\SOFTWARE', 'HKEY_LOCAL_MACHINE\WIM_HKLM_SOFTWARE'
            $REGContent = $REGContent -replace 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet', 'HKEY_LOCAL_MACHINE\WIM_HKLM_SYSTEM\ControlSet001'
            $REGContent = $REGContent -replace 'HKEY_LOCAL_MACHINE\\SYSTEM', 'HKEY_LOCAL_MACHINE\WIM_HKLM_SYSTEM'
            $REGContent = $REGContent -replace 'HKEY_CLASSES_ROOT', 'HKEY_LOCAL_MACHINE\WIM_HKLM_SOFTWARE\Classes'
            $REGContent = $REGContent -replace 'HKEY_CURRENT_USER', 'HKEY_LOCAL_MACHINE\WIM_HKCU'
            $REGContent = $REGContent -replace 'HKEY_USERS\\.DEFAULT', 'HKEY_LOCAL_MACHINE\WIM_HKU_DEFAULT'
            $REGContent | Set-Content -Path "$($PSItem.FullName.Replace('.reg', '.Offline'))" -Encoding Unicode -Force
        }
        $Templates = Get-ChildItem -Path $AdditionalPath.RegistryTemplates -Filter *.Offline | Select-Object -Property Name, BaseName, Extension, Directory, FullName
        ForEach ($Template In $Templates)
        {
            Write-Output ('Importing Registry Template: "{0}"' -f $($Template.Name.Replace($Template.Extension, '.reg'))) | Out-File -FilePath $RegistryLog -Encoding UTF8 -Append -Force
            $RET = StartExe $REGEDIT -Arguments ('/S "{0}"' -f $Template.FullName)
            If ($RET -ne 0) { Log -Error ('Failed to Import Registry Template: "{0}"' -f $($Template.Name.Replace($Template.Extension, '.reg'))) }
            $Template.FullName | Purge
        }
    }
    End
    {
        RegHives -Unload
    }
}
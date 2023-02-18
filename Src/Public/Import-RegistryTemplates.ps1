Function Import-RegistryTemplates
{
    [CmdletBinding()]
    Param ()

    Get-ChildItem -Path $OptimizeOffline.RegistryTemplates -Filter *.Offline | Purge
    Get-ChildItem -Path $OptimizeOffline.RegistryTemplates -Filter *.reg | ForEach-Object -Process {
        $REGContent = Get-Content -Path $PSItem.FullName
        $REGContent = $REGContent -replace 'HKEY_CLASSES_ROOT', 'HKEY_LOCAL_MACHINE\WIM_HKLM_SOFTWARE\Classes'
        $REGContent = $REGContent -replace 'HKEY_LOCAL_MACHINE\\SOFTWARE', 'HKEY_LOCAL_MACHINE\WIM_HKLM_SOFTWARE'
        $REGContent = $REGContent -replace 'HKEY_LOCAL_MACHINE\\SYSTEM', 'HKEY_LOCAL_MACHINE\WIM_HKLM_SYSTEM'
        $REGContent = $REGContent -replace 'HKEY_CURRENT_USER', 'HKEY_LOCAL_MACHINE\WIM_HKCU'
        $REGContent = $REGContent -replace 'HKEY_USERS\\.DEFAULT', 'HKEY_LOCAL_MACHINE\WIM_HKU_DEFAULT'
        $REGContent = $REGContent -replace 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet', 'HKEY_LOCAL_MACHINE\WIM_HKLM_SYSTEM\ControlSet001'
        $REGContent | Set-Content -Path $PSItem.FullName.Replace($PSItem.Extension, '.Offline') -Encoding Unicode -Force
    }
    If (Get-ChildItem -Path $OptimizeOffline.RegistryTemplates -Filter *.Offline)
    {
        RegHives -Load
        Get-ChildItem -Path $OptimizeOffline.RegistryTemplates -Filter *.Offline | ForEach-Object -Process {
            Try
            {
                Log ($OptimizeData.ImportingRegistryTemplate -f $PSItem.Name.Replace($PSItem.Extension, '.reg'))
                $RET = StartExe $REGEDIT -Arguments ('/S "{0}"' -f $PSItem.FullName)
                If ($RET -ne 0) { Throw }
            }
            Catch
            {
                Log ($OptimizeData.FailedImportingRegistryTemplate -f $PSItem.Name.Replace($PSItem.Extension, '.reg')) -Type Error
            }
            Finally
            {
                RegHives -Unload; Purge $PSItem.FullName; Start-Sleep 2
            }
        }
    }
}
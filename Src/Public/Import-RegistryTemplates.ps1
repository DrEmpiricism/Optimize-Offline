Function Import-RegistryTemplates
{
    [CmdletBinding()]
    Param ()

    Begin
    {
        RegHives -Load
    }
    Process
    {
        Get-ChildItem -Path $OptimizeOffline.RegistryTemplates -Filter *.Offline | Purge -ErrorAction SilentlyContinue
        Get-ChildItem -Path $OptimizeOffline.RegistryTemplates -Filter *.reg | ForEach-Object -Process {
            $REGContent = Get-Content -Path $PSItem.FullName
            $REGContent = $REGContent -replace 'HKEY_CLASSES_ROOT', 'HKEY_LOCAL_MACHINE\WIM_HKLM_SOFTWARE\Classes'
            $REGContent = $REGContent -replace 'HKEY_LOCAL_MACHINE\\SOFTWARE', 'HKEY_LOCAL_MACHINE\WIM_HKLM_SOFTWARE'
            $REGContent = $REGContent -replace 'HKEY_LOCAL_MACHINE\\SYSTEM', 'HKEY_LOCAL_MACHINE\WIM_HKLM_SYSTEM'
            $REGContent = $REGContent -replace 'HKEY_CURRENT_USER', 'HKEY_LOCAL_MACHINE\WIM_HKCU'
            $REGContent = $REGContent -replace 'HKEY_USERS\\.DEFAULT', 'HKEY_LOCAL_MACHINE\WIM_HKU_DEFAULT'
            $REGContent = $REGContent -replace 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet', 'HKEY_LOCAL_MACHINE\WIM_HKLM_SYSTEM\ControlSet001'
            $REGContent | Set-Content -Path $PSItem.FullName.Replace($PSItem.Extension, '.Offline') -Encoding Unicode -Force -ErrorAction SilentlyContinue
        }
        Get-ChildItem -Path $OptimizeOffline.RegistryTemplates -Filter *.Offline | ForEach-Object -Process {
            Try
            {
                Write-Output ('Importing Registry Template: "{0}"' -f $PSItem.Name.Replace($PSItem.Extension, '.reg')) | Out-File -FilePath $RegistryLog -Encoding UTF8 -Append -Force -ErrorAction SilentlyContinue
                $RET = StartExe $REGEDIT -Arguments ('/S "{0}"' -f $PSItem.FullName) -ErrorAction:$ErrorActionPreference
                If ($RET -ne 0) { Throw }
            }
            Catch
            {
                Log -Error ('Failed to Import Registry Template: "{0}"' -f $PSItem.Name.Replace($PSItem.Extension, '.reg'))
            }
            Finally
            {
                $PSItem.FullName | Purge -ErrorAction SilentlyContinue
            }
        }
    }
    End
    {
        RegHives -Unload
    }
}
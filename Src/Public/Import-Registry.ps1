Function Import-Registry
{
    [CmdletBinding()]
    Param (
		[String]$Path
    )

    $RegKeyProcessor = { 
        param(
            [String[]]$REGContent
        ) 
        $REGContent = $REGContent -replace 'HKEY_CLASSES_ROOT', 'HKEY_LOCAL_MACHINE\WIM_HKLM_SOFTWARE\Classes'
        $REGContent = $REGContent -replace 'HKEY_LOCAL_MACHINE\\SOFTWARE', 'HKEY_LOCAL_MACHINE\WIM_HKLM_SOFTWARE'
        $REGContent = $REGContent -replace 'HKEY_LOCAL_MACHINE\\SYSTEM', 'HKEY_LOCAL_MACHINE\WIM_HKLM_SYSTEM'
        $REGContent = $REGContent -replace 'HKEY_CURRENT_USER', 'HKEY_LOCAL_MACHINE\WIM_HKCU'
        $REGContent = $REGContent -replace 'HKEY_USERS\\.DEFAULT', 'HKEY_LOCAL_MACHINE\WIM_HKU_DEFAULT'
        $REGContent = $REGContent -replace 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet', 'HKEY_LOCAL_MACHINE\WIM_HKLM_SYSTEM\ControlSet001'

        return $REGContent
    }

    If ((Get-Item $Path) -is [System.IO.DirectoryInfo]){
        Get-ChildItem -Path $Path -Filter *.Offline | Purge
        Get-ChildItem -Path $Path -Filter *.reg | ForEach-Object -Process {
            $REGContent = Get-Content -Path $PSItem.FullName
            $REGContent = $RegKeyProcessor.Invoke($REGContent)
            $REGContent | Set-Content -Path $PSItem.FullName.Replace($PSItem.Extension, '.Offline') -Encoding Unicode -Force
        }
        If (Get-ChildItem -Path $Path -Filter *.Offline)
        {
            RegHives -Load
            Get-ChildItem -Path $Path -Filter *.Offline | ForEach-Object -Process {
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
    } Else {
        $RegFile = Get-Item $Path
        $REGContent = Get-Content -Path $RegFile.FullName
        $REGContent = $RegKeyProcessor.Invoke($REGContent)
        $REGContent | Set-Content -Path $RegFile.FullName.Replace($RegFile.Extension, '.Offline') -Encoding Unicode -Force
        RegHives -Load
        $ProcessedItem = Get-Item $RegFile.FullName.Replace($RegFile.Extension, '.Offline')
        Try
        {
            Log ($OptimizeData.ImportingRegistryTemplate -f $ProcessedItem.Name.Replace($ProcessedItem.Extension, '.reg'))
            $RET = StartExe $REGEDIT -Arguments ('/S "{0}"' -f $ProcessedItem.FullName)
            If ($RET -ne 0) { Throw }
        }
        Catch
        {
            Log ($OptimizeData.FailedImportingRegistryTemplate -f $ProcessedItem.Name.Replace($ProcessedItem.Extension, '.reg')) -Type Error
        }
        Finally
        {
            RegHives -Unload; Purge $ProcessedItem.FullName; Start-Sleep 2
        }
    }
}
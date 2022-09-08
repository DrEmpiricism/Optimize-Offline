Function Import-Registry
{
    [CmdletBinding()]
    Param (
		[String]$Path,
        [Parameter(Mandatory=$false)]
        [switch]$RegistryLoaded = $false
    )

    $REGContentHandler = {
        param(
            [string]$Content
        ) 
	    $Content = $Content -replace 'HKEY_CLASSES_ROOT', 'HKEY_LOCAL_MACHINE\WIM_HKLM_SOFTWARE\Classes'
        $Content = $Content -replace 'HKEY_LOCAL_MACHINE\\SOFTWARE', 'HKEY_LOCAL_MACHINE\WIM_HKLM_SOFTWARE'
        $Content = $Content -replace 'HKEY_LOCAL_MACHINE\\SYSTEM', 'HKEY_LOCAL_MACHINE\WIM_HKLM_SYSTEM'
        $Content = $Content -replace 'HKEY_CURRENT_USER', 'HKEY_LOCAL_MACHINE\WIM_HKCU'
        $Content = $Content -replace 'HKEY_USERS\\.DEFAULT', 'HKEY_LOCAL_MACHINE\WIM_HKU_DEFAULT'
        $Content = $Content -replace 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet', 'HKEY_LOCAL_MACHINE\WIM_HKLM_SYSTEM\ControlSet001'
        return $Content
    }

    If(!$RegistryLoaded) {
        RegHives -Load
    }
    

    If ((Get-Item $Path) -is [System.IO.DirectoryInfo]){
        Get-ChildItem -Path $Path -Filter *.Offline | Purge
        Get-ChildItem -Path $Path -Filter *.reg | ForEach-Object -Process {
            $REGContent = Get-Content -Path $PSItem.FullName -Raw
            $REGContent = $REGContentHandler.Invoke($REGContent)
            $REGContent | Set-Content -Path $PSItem.FullName.Replace($PSItem.Extension, '.Offline') -Encoding Unicode -Force
        }
        If (Get-ChildItem -Path $Path -Filter *.Offline)
        {
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
                    Purge $PSItem.FullName; Start-Sleep 2
                }
            }
        }
    } Else {
        $RegFile = Get-Item $Path
        $REGContent = Get-Content -Path $RegFile.FullName -Raw
        $REGContent = $REGContentHandler.Invoke($REGContent)
        $REGContent | Set-Content -Path $RegFile.FullName.Replace($RegFile.Extension, '.Offline') -Encoding Unicode -Force
        
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
            Purge $ProcessedItem.FullName; Start-Sleep 2
        }
    }

    If(!$RegistryLoaded) {
        RegHives -Unload
    }
    
}
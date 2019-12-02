<#
	===========================================================================
	Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2019 v5.6.170
	Created on:   	11/20/2019 11:53 AM
	Created by:   	BenTheGreat
	Filename:     	OfflineResources.psm1
	Last updated:	12/02/2019
	-------------------------------------------------------------------------
	Module Name: OfflineResources
	===========================================================================
#>

Try { Get-Module -Name Dism -ListAvailable | Import-Module -Scope Global -ErrorAction Stop }
Catch { Write-Error $PSItem.Exception.Message; Break }

#region Module Declarations
$OfflineResources = New-Object -TypeName PSObject -Property @{ }
$OfflineResources | Add-Member -MemberType NoteProperty -Name Path -Value (Join-Path -Path $PSScriptRoot -ChildPath OfflineResources.psm1)
$OfflineResources | Add-member -MemberType NoteProperty -Name Name -Value (Split-Path -Path $OfflineResources.Path -Leaf)
$OfflineResources | Add-Member -MemberType NoteProperty -Name BaseName -Value ([IO.Path]::GetFileNameWithoutExtension($OfflineResources.Name))
$OfflineResources | Add-Member -MemberType NoteProperty -Name Directory -Value (Split-Path -Path $OfflineResources.Path -Parent)

$OptimizeOffline = New-Object -TypeName PSObject -Property @{ }
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Path -Value (Join-Path -Path (Split-Path -Path $OfflineResources.Directory) -ChildPath Optimize-Offline.psm1)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Name -Value (Split-Path -Path $OptimizeOffline.Path -Leaf)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name BaseName -Value ([IO.Path]::GetFileNameWithoutExtension($OptimizeOffline.Name))
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Directory -Value (Split-Path -Path $OptimizeOffline.Path -Parent)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name LocalizedData -Value (Join-Path -Path $OptimizeOffline.Directory -ChildPath en-US)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name LocalizedDataStrings -Value (Join-Path -Path $OptimizeOffline.LocalizedData -ChildPath Optimize-Offline.strings.psd1)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name ConfigurationJSON -Value (Join-Path -Path $OptimizeOffline.Directory -ChildPath Configuration.json)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name ManifestDataFile -Value (Join-Path -Path $OptimizeOffline.Directory -ChildPath Optimize-Offline.psd1)
#endregion Module Declarations

#region Data and Resource Declarations
$PublicFunctions = @(Get-ChildItem -Path (Join-Path -Path $OfflineResources.Directory -ChildPath Public) -Filter *.ps1)
$PrivateFunctions = @(Get-ChildItem -Path (Join-Path -Path $OfflineResources.Directory -ChildPath Private) -Filter *.ps1)

ForEach ($Function In @($PublicFunctions + $PrivateFunctions))
{
	Try { . $Function.FullName }
	Catch { Write-Error ('Failed to import required function "{0}", {1}' -f $Function.FullName, $PSItem); Break }
}

Try { $ManifestData = Import-PowerShellDataFile -Path $OptimizeOffline.ManifestDataFile -ErrorAction Stop }
Catch { Write-Error ('Failed to import the manifest data file: "{0}"' -f (Split-Path -Path $OptimizeOffline.ManifestDataFile -Leaf)); Break }
#endregion Data and Resource Declarations

#region Local Variable Declarations
$DirectoryPath = @{
	Resources  = (Join-Path -Path $OptimizeOffline.Directory -ChildPath Src)
	Content    = (Join-Path -Path $OptimizeOffline.Directory -ChildPath Content)
	Culture    = (Join-Path -Path $OptimizeOffline.Directory -ChildPath en-US)
	Additional = (Join-Path -Path $OptimizeOffline.Directory -ChildPath 'Content\Additional')
	Packages   = (Join-Path -Path $OptimizeOffline.Directory -ChildPath Packages)
}

$PackagePath = @{
	DaRT          = (Join-Path -Path $DirectoryPath.Packages -ChildPath DaRT)
	Dedup         = (Join-Path -Path $DirectoryPath.Packages -ChildPath Deduplication)
	DevMode       = (Join-Path -Path $DirectoryPath.Packages -ChildPath DeveloperMode)
	MicrosoftEdge = (Join-Path -Path $DirectoryPath.Packages -ChildPath MicrosoftEdge)
	Win32Calc     = (Join-Path -Path $DirectoryPath.Packages -ChildPath Win32Calc)
	WindowsStore  = (Join-Path -Path $DirectoryPath.Packages -ChildPath WindowsStore)
}

$ContentPath = @{
	AppxWhitelist         = (Join-Path -Path $DirectoryPath.Content -ChildPath AppxWhitelist.json)
	CustomAppAssociations = (Join-Path -Path $DirectoryPath.Content -ChildPath CustomAppAssociations.xml)
}

$AdditionalPath = @{
	InstallDrivers    = (Join-Path -Path $DirectoryPath.Additional -ChildPath 'Drivers\Install')
	BootDrivers       = (Join-Path -Path $DirectoryPath.Additional -ChildPath 'Drivers\Boot')
	RecoveryDrivers   = (Join-Path -Path $DirectoryPath.Additional -ChildPath 'Drivers\Recovery')
	LockScreen        = (Join-Path -Path $DirectoryPath.Additional -ChildPath LockScreen)
	RegistryTemplates = (Join-Path -Path $DirectoryPath.Additional -ChildPath RegistryTemplates)
	Setup             = (Join-Path -Path $DirectoryPath.Additional -ChildPath Setup)
	SystemLogo        = (Join-Path -Path $DirectoryPath.Additional -ChildPath SystemLogo)
	Unattend          = (Join-Path -Path $DirectoryPath.Additional -ChildPath Unattend)
	Wallpaper         = (Join-Path -Path $DirectoryPath.Additional -ChildPath Wallpaper)
	AdditionalJSON    = (Join-Path -Path $DirectoryPath.Additional -ChildPath Additional.json)
}
#endregion Local Variable Declarations

#region Variable Declarations
$ConfigParams = [Collections.Specialized.OrderedDictionary]::New()
$DynamicParams = [Collections.Hashtable]::New()
$TempDirectory = (Join-Path -Path $OptimizeOffline.Directory -ChildPath OfflineTemp_$(Get-Random))
$LogFolder = (Join-Path -Path $TempDirectory -ChildPath LogOffline)
$WorkFolder = (Join-Path -Path $TempDirectory -ChildPath WorkOffline)
$ScratchFolder = (Join-Path -Path $TempDirectory -ChildPath ScratchOffline)
$ImageFolder = (Join-Path -Path $TempDirectory -ChildPath ImageOffline)
$InstallMount = (Join-Path -Path $TempDirectory -ChildPath InstallMountOffline)
$BootMount = (Join-Path -Path $TempDirectory -ChildPath BootMountOffline)
$RecoveryMount = (Join-Path -Path $TempDirectory -ChildPath RecoveryMountOffline)
$ModuleLog = (Join-Path -Path $LogFolder -ChildPath Optimize-Offline.log)
$RegistryLog = (Join-Path -Path $LogFolder -ChildPath RegistrySettings.log)
$DISMLog = (Join-Path -Path $LogFolder -ChildPath DISM.log)
$PackageLog = (Join-Path -Path $LogFolder -ChildPath PackageSummary.log)
$ErrorRecordLog = (Join-Path -Path $LogFolder -ChildPath ErrorRecord.log)
$DISM = (Join-Path -Path $Env:SystemRoot\System32 -ChildPath dism.exe)
$REG = (Join-Path -Path $Env:SystemRoot\System32 -ChildPath reg.exe)
$REGEDIT = (Join-Path -Path $Env:SystemRoot -ChildPath regedit.exe)
$EXPAND = (Join-Path -Path $Env:SystemRoot\System32 -ChildPath expand.exe)
#endregion Variable Declarations

#region New Alias Creation
New-Alias -Name Create -Value New-Container
New-Alias -Name Purge -Value Remove-Container
New-Alias -Name Cleanup -Value Invoke-Cleanup
New-Alias -Name StartExe -Value Start-Executable
New-Alias -Name Log -Value Write-Log
New-Alias -Name WimData -Value Get-WimFile
New-Alias -Name RegKey -Value Set-KeyProperty
New-Alias -Name RegHives -Value Get-OfflineHives
New-Alias -Name Stop -Value Stop-Optimize
New-Alias -Name FormatError -Value Format-ErrorRecord
#endregion New Alias Creation

$ExportResourceParams = @{
	Function = $PublicFunctions.Basename
	Variable = 'OptimizeOffline', 'ManifestData', 'PackagePath', 'ContentPath', 'AdditionalPath', 'ConfigParams', 'DynamicParams', 'TempDirectory', 'LogFolder', 'WorkFolder', 'ScratchFolder', 'ImageFolder', 'InstallMount', 'BootMount', 'RecoveryMount', 'ModuleLog', 'RegistryLog', 'DISMLog', 'PackageLog', 'ErrorRecordLog', 'DISM', 'REG', 'REGEDIT', 'EXPAND'
	Alias    = '*'
}
Export-ModuleMember @ExportResourceParams
# SIG # Begin signature block
# MIIMDgYJKoZIhvcNAQcCoIIL/zCCC/sCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUtrk3SkG4YElMDJYu/l8vfdQo
# RTigggjkMIIDZTCCAk2gAwIBAgIQcvzm3AoNiblMifO61mXaqjANBgkqhkiG9w0B
# AQsFADBFMRQwEgYKCZImiZPyLGQBGRYEVEVDSDEVMBMGCgmSJomT8ixkARkWBU9N
# TklDMRYwFAYDVQQDEw1PTU5JQy5URUNILUNBMB4XDTE5MDUxNTEyMDYwN1oXDTI0
# MDUxNTEyMTYwN1owRTEUMBIGCgmSJomT8ixkARkWBFRFQ0gxFTATBgoJkiaJk/Is
# ZAEZFgVPTU5JQzEWMBQGA1UEAxMNT01OSUMuVEVDSC1DQTCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAMivWQ61s2ol9vV7TTAhP5hy2CADYNl0C/yVE7wx
# 4eEeiVfiFT+A78GJ4L1h2IbTM6EUlGAtxlz152VFBrY0Hm/nQ1WmrUrneFAb1kTb
# NLGWCyoH9ImrZ5l7NCd97XTZUYsNtbix3nMqUuPPq+UA23pekolHBCpRoDdya22K
# XEgFhOdWfKWsVSCZYiQZyT/moXO2aCmgILq0qtNvNS24grVXTX+qgr1OeiOIF+0T
# SB1oYqTNvROUJ4D6sv4Ap5hJ5PFYmbQrBnytEBGQwXyumQGoK8l/YUBbScsoSjNH
# +GkJMVox7GZObEGf1aLNMCXh7bjpXFw/RJgvBmypkWPIdOUCAwEAAaNRME8wCwYD
# VR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFGzmcuTlwYRYLA1E
# /XGZHHp2+GqTMBAGCSsGAQQBgjcVAQQDAgEAMA0GCSqGSIb3DQEBCwUAA4IBAQCk
# iQqEJdY3YdQWWM3gBqfgJOaqA4oMTAJCIwj+N3zc4UUChaMOq5kAKRRLMtXOv9fH
# 7L0658kt0+URQIB3GrtkV/h3VYdwACWQLGHvGfZ2paFQTF7vT8KA4fi8pkfRoupg
# 4PZ+drXL1Nq/Nbsr0yaakm2VSlij67grnMOdYBhwtf919qQZdvodJQKL+XipjmT3
# tapbg0FMnugL6vhsB6H8nGWO8szHws2UkiWXSmnECJLYQxZ009do3L0/J4BJvak5
# RUzNcZJIuTnifEIax68UcKHU8bFAaiz5Zns74d0qqZx6ZctYLlPI58mhSn9pohoL
# ozlL4YdE7lQ8EDTiKZTIMIIFdzCCBF+gAwIBAgITGgAAAAgLhnXW+w68VgAAAAAA
# CDANBgkqhkiG9w0BAQsFADBFMRQwEgYKCZImiZPyLGQBGRYEVEVDSDEVMBMGCgmS
# JomT8ixkARkWBU9NTklDMRYwFAYDVQQDEw1PTU5JQy5URUNILUNBMB4XDTE5MDUx
# ODE5MDQ1NloXDTIwMDUxNzE5MDQ1NlowUzEUMBIGCgmSJomT8ixkARkWBFRFQ0gx
# FTATBgoJkiaJk/IsZAEZFgVPTU5JQzEOMAwGA1UEAxMFVXNlcnMxFDASBgNVBAMT
# C0JlblRoZUdyZWF0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvnkk
# jYlPGAeAApx5Qgn0lbHLI2jywWcsMl2Aff0FDH+4IemQQSQWsU+vCuunrpqvCXMB
# 7yHgecxw37BWnbfEpUyYLZAzuDUxJM1/YQclhH7yOb0GvhHaUevDMCPaqFT1/QoS
# 4PzMim9nj1CU7un8QVTnUCSivC88kJnvBA6JciUoRGU5LAjLDhrMa+v+EQjnkErb
# Y0L3bi3D+ROA23D1oS6nuq27zeRHawod1wscT+BYGiyP/7w8u/GQdGZPeNdw0168
# XCEicDUEiB/s4TI4dCr+0B80eI/8jHTYs/LFj+v6QETiQChR5Vk8lsS3On1LI8Fo
# 8Ki+PPgYCdScxiYNfQIDAQABo4ICUDCCAkwwJQYJKwYBBAGCNxQCBBgeFgBDAG8A
# ZABlAFMAaQBnAG4AaQBuAGcwEwYDVR0lBAwwCgYIKwYBBQUHAwMwDgYDVR0PAQH/
# BAQDAgeAMB0GA1UdDgQWBBQQg/QKzp8JFAJtalEPhIrNKV7A2jAfBgNVHSMEGDAW
# gBRs5nLk5cGEWCwNRP1xmRx6dvhqkzCByQYDVR0fBIHBMIG+MIG7oIG4oIG1hoGy
# bGRhcDovLy9DTj1PTU5JQy5URUNILUNBLENOPUFOVUJJUyxDTj1DRFAsQ049UHVi
# bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
# bixEQz1PTU5JQyxEQz1URUNIP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFz
# ZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvgYIKwYBBQUHAQEE
# gbEwga4wgasGCCsGAQUFBzAChoGebGRhcDovLy9DTj1PTU5JQy5URUNILUNBLENO
# PUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1D
# b25maWd1cmF0aW9uLERDPU9NTklDLERDPVRFQ0g/Y0FDZXJ0aWZpY2F0ZT9iYXNl
# P29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwMQYDVR0RBCowKKAm
# BgorBgEEAYI3FAIDoBgMFkJlblRoZUdyZWF0QE9NTklDLlRFQ0gwDQYJKoZIhvcN
# AQELBQADggEBAEyyXCN8L6z4q+gFjbm3B3TvuCAlptX8reIuDg+bY2Bn/WF2KXJm
# +FNZakUKccesxl2XUJo2O7KZBKKjZYMwEBK7NhTOvC50VupJc0p6aXrMrcOnAjAn
# NrjWbKYmc6bG7uCzuEBPlJVmnhdRLgRJKfJDAfXPWkYebV666WnggugL4ROOYtOY
# 3J8j/2cyYE6OD5YTl1ydnYzyNUeZq2IVfxw5BK83lVK5uuneg+4QQaUNWBU5mtIa
# 6t748F1ZEQm3UNk8ImFKWp4dsgAHpPC5wZo/BAMO8PP8BW3+6yvewWnUAGTU4f07
# b1SjZsLcQ6D0eCcFD+7I7MkcSz2ARu6wUOcxggKUMIICkAIBATBcMEUxFDASBgoJ
# kiaJk/IsZAEZFgRURUNIMRUwEwYKCZImiZPyLGQBGRYFT01OSUMxFjAUBgNVBAMT
# DU9NTklDLlRFQ0gtQ0ECExoAAAAIC4Z11vsOvFYAAAAAAAgwCQYFKw4DAhoFAKCC
# AQ0wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwG
# CisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFKQnKpyt3C+nVSjuMxg5zOOLs9rB
# MIGsBgorBgEEAYI3AgEMMYGdMIGaoGSAYgBXAGkAbgBkAG8AdwBzACAASQBtAGEA
# ZwBlACAAKABXAEkATQApACAAbwBwAHQAaQBtAGkAegBhAHQAaQBvAG4AIAByAGUA
# cwBvAHUAcgBjAGUAIABtAG8AZAB1AGwAZQAuoTKAMGh0dHBzOi8vZ2l0aHViLmNv
# bS9EckVtcGlyaWNpc20vT3B0aW1pemUtT2ZmbGluZTANBgkqhkiG9w0BAQEFAASC
# AQAH0G1/CTcwi60gg5UPEYfIX4ClnQDjyy4m83wi1OVp6/P/PxQSQ4r2xwA1nWfR
# OnKftjreMQ1DmHF5eSvhVXMW4gQAEh9RiXHkq6wC0N1/y7WUf0QwaJUeNEBh18iY
# Wbg4ohGjWhfv3Zxm99KmWBUskMbUX1HdtuFv4hcqcDKij5WPjcyww9HTlPNl0ES7
# KQLM9Ei1aLIBOAZj0/tqxeC/EzCp8Rl6bwhKYv0wS7t1LPzk5zLAnwnzNBcv+mf3
# ws+Wr1OlAiZECV5gNZu5+nKv/xX2czYyBbHkFfCeC6vTJHvJMiOmC2AUzqLIP7/z
# QmX+zLWrkkeUl9PV/6wazosA
# SIG # End signature block

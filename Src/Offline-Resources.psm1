Using namespace System.Collections.Generic
#Requires -RunAsAdministrator
#Requires -Version 5
<#
	===========================================================================
	Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2019 v5.7.174
	Created on:   	11/20/2019 11:53 AM
	Created by:   	BenTheGreat
	Filename:     	Offline-Resources.psm1
	Last updated:	04/14/2020
	-------------------------------------------------------------------------
	Module Name: Offline-Resources
	===========================================================================
#>

#region Set Local Variables
$ResourcesRoot = $PSScriptRoot
$ModuleRoot = Split-Path -Path $ResourcesRoot
#endregion Set Local Variables

#region Import Resource Functions
$PublicFunctions = @(Get-ChildItem -Path (Join-Path -Path $ResourcesRoot -ChildPath Public) -Filter *.ps1 -ErrorAction SilentlyContinue)
$PrivateFunctions = @(Get-ChildItem -Path (Join-Path -Path $ResourcesRoot -ChildPath Private) -Filter *.ps1 -ErrorAction SilentlyContinue)
ForEach ($Function In @($PublicFunctions + $PrivateFunctions))
{
	Try { . $Function.FullName }
	Catch { Write-Warning ('Failed to import the required function "{0}", {1}' -f $Function.FullName, $PSItem); Break }
}
#endregion Import Resource Functions

#region Module Path Declarations
$OfflineResources = [Collections.Specialized.OrderedDictionary]::New()
$OfflineResources.Path = (Resolve-FullPath -Path $ResourcesRoot -Child Offline-Resources.psm1)
$OfflineResources.Name = (Resolve-FullPath -Path $OfflineResources.Path -Split Leaf)
$OfflineResources.BaseName = ([IO.Path]::GetFileNameWithoutExtension($OfflineResources.Name))
$OfflineResources.Directory = (Resolve-FullPath -Path $OfflineResources.Path -Split Parent)

$OptimizeOffline = [Collections.Specialized.OrderedDictionary]::New()
$OptimizeOffline.Path = (Resolve-FullPath -Path $ModuleRoot -Child Optimize-Offline.psm1)
$OptimizeOffline.Name = (Resolve-FullPath $OptimizeOffline.Path -Split Leaf)
$OptimizeOffline.BaseName = ([IO.Path]::GetFileNameWithoutExtension($OptimizeOffline.Name))
$OptimizeOffline.Directory = (Resolve-FullPath -Path $OptimizeOffline.Path -Split Parent)
$OptimizeOffline.Culture = 'en-US'
$OptimizeOffline.Resources = (Resolve-FullPath -Path $OptimizeOffline.Directory -Child Src)
$OptimizeOffline.Content = (Resolve-FullPath -Path $OptimizeOffline.Directory -Child Content)
$OptimizeOffline.LocalizedData = (Resolve-FullPath -Path $OptimizeOffline.Directory -Child $OptimizeOffline.Culture)
$OptimizeOffline.Additional = (Resolve-FullPath -Path $OptimizeOffline.Content -Child Additional)
$OptimizeOffline.Packages = (Resolve-FullPath -Path $OptimizeOffline.Directory -Child Packages)
$OptimizeOffline.LocalizedDataStrings = (Resolve-FullPath -Path $OptimizeOffline.LocalizedData -Child Optimize-Offline.strings.psd1)
$OptimizeOffline.ConfigurationJSON = (Resolve-FullPath -Path $OptimizeOffline.Directory -Child Configuration.json)
$OptimizeOffline.ManifestDataFile = (Resolve-FullPath -Path $OptimizeOffline.Directory -Child Optimize-Offline.psd1)
$OptimizeOffline.AppxWhitelist = (Resolve-FullPath -Path $OptimizeOffline.Content -Child AppxWhitelist.json)
$OptimizeOffline.CustomAppAssociations = (Resolve-FullPath -Path $OptimizeOffline.Content -Child CustomAppAssociations.xml)
$OptimizeOffline.DevMode = (Resolve-FullPath -Path $OptimizeOffline.Packages -Child DeveloperMode)
$OptimizeOffline.WindowsStore = (Resolve-FullPath -Path $OptimizeOffline.Packages -Child WindowsStore)
$OptimizeOffline.MicrosoftEdge = (Resolve-FullPath -Path $OptimizeOffline.Packages -Child MicrosoftEdge)
$OptimizeOffline.Win32Calc = (Resolve-FullPath -Path $OptimizeOffline.Packages -Child Win32Calc)
$OptimizeOffline.Dedup = (Resolve-FullPath -Path $OptimizeOffline.Packages -Child Deduplication)
$OptimizeOffline.DaRT = (Resolve-FullPath -Path $OptimizeOffline.Packages -Child DaRT)
$OptimizeOffline.Setup = (Resolve-FullPath -Path $OptimizeOffline.Additional -Child Setup)
$OptimizeOffline.Wallpaper = (Resolve-FullPath -Path $OptimizeOffline.Additional -Child Wallpaper)
$OptimizeOffline.SystemLogo = (Resolve-FullPath -Path $OptimizeOffline.Additional -Child SystemLogo)
$OptimizeOffline.LockScreen = (Resolve-FullPath -Path $OptimizeOffline.Additional -Child LockScreen)
$OptimizeOffline.RegistryTemplates = (Resolve-FullPath -Path $OptimizeOffline.Additional -Child RegistryTemplates)
$OptimizeOffline.LayoutModification = (Resolve-FullPath -Path $OptimizeOffline.Additional -Child LayoutModification)
$OptimizeOffline.Unattend = (Resolve-FullPath -Path $OptimizeOffline.Additional -Child Unattend)
$OptimizeOffline.Drivers = (Resolve-FullPath -Path $OptimizeOffline.Additional -Child Drivers)
$OptimizeOffline.InstallDrivers = (Resolve-FullPath -Path $OptimizeOffline.Drivers -Child Install)
$OptimizeOffline.BootDrivers = (Resolve-FullPath -Path $OptimizeOffline.Drivers -Child Boot)
$OptimizeOffline.RecoveryDrivers = (Resolve-FullPath -Path $OptimizeOffline.Drivers -Child Recovery)
#endregion Module Path Declarations

#region Data Declarations
Try { $ManifestData = Import-PowerShellDataFile -Path $OptimizeOffline.ManifestDataFile -ErrorAction Stop }
Catch { Write-Warning ('Failed to import the manifest data file: "{0}"' -f (Resolve-FullPath -Path $OptimizeOffline.ManifestDataFile -Split Leaf)); Break }

Try { Import-LocalizedData -BaseDirectory $OptimizeOffline.Directory -FileName Optimize-Offline.strings.psd1 -BindingVariable OptimizeData -ErrorAction Stop }
Catch { Write-Warning ('Failed to import the localized data file: "{0}"' -f (Resolve-FullPath -Path $OptimizeOffline.LocalizedDataStrings -Split Leaf)); Break }
#endregion Data Declarations

#region Variable Declarations
$LocalScope = [PSCustomObject]::New()
$OptimizeOfflineParams = [PSCustomObject]::New()
$DynamicParams = [Collections.Hashtable]::New()
$ConfigParams = [Collections.Specialized.OrderedDictionary]::New()
$OptimizeErrors = [List[Object]]::New()
$TempDirectory = (Resolve-FullPath -Path $OptimizeOffline.Directory -Child OfflineTemp_$(Get-Random))
$LogFolder = (Resolve-FullPath -Path $TempDirectory -Child LogOffline)
$WorkFolder = (Resolve-FullPath -Path $TempDirectory -Child WorkOffline)
$ScratchFolder = (Resolve-FullPath -Path $TempDirectory -Child ScratchOffline)
$ImageFolder = (Resolve-FullPath -Path $TempDirectory -Child ImageOffline)
$InstallMount = (Resolve-FullPath -Path $TempDirectory -Child InstallMountOffline)
$BootMount = (Resolve-FullPath -Path $TempDirectory -Child BootMountOffline)
$RecoveryMount = (Resolve-FullPath -Path $TempDirectory -Child RecoveryMountOffline)
$ModuleLog = (Resolve-FullPath -Path $LogFolder -Child Optimize-Offline.log)
$ErrorLog = (Resolve-FullPath -Path $LogFolder -Child OptimizeErrors.log)
$RegistryLog = (Resolve-FullPath -Path $LogFolder -Child RegistrySettings.log)
$DISMLog = (Resolve-FullPath -Path $LogFolder -Child DISM.log)
$DISM = If (Get-DISMPath) { Resolve-FullPath -Path (Get-DISMPath) -Child dism.exe } Else { Resolve-FullPath -Path $Env:SystemRoot -Child 'System32\dism.exe' }
$REG = (Resolve-FullPath -Path $Env:SystemRoot -Child 'System32\reg.exe')
$REGEDIT = (Resolve-FullPath -Path $Env:SystemRoot -Child regedit.exe)
$EXPAND = (Resolve-FullPath -Path $Env:SystemRoot -Child 'System32\expand.exe')
#endregion Variable Declarations

#region Resource Alias Creation
New-Alias -Name Create -Value New-Container
New-Alias -Name Purge -Value Remove-Container
New-Alias -Name StartExe -Value Start-Executable
New-Alias -Name Log -Value Write-Log
New-Alias -Name RegKey -Value Set-KeyProperty
New-Alias -Name RegHives -Value Get-OfflineHives
New-Alias -Name GetPath -Value Resolve-FullPath
#endregion Resource Alias Creation

$ExportResourceParams = @{
	Function = $PublicFunctions.Basename
	Variable = 'OptimizeOffline', 'ManifestData', 'OptimizeData', 'LocalScope', 'OptimizeParams', 'DynamicParams', 'ConfigParams', 'OptimizeErrors', 'TempDirectory', 'LogFolder', 'WorkFolder', 'ScratchFolder', 'ImageFolder', 'InstallMount', 'BootMount', 'RecoveryMount', 'ModuleLog', 'ErrorLog', 'RegistryLog', 'DISMLog', 'DISM', 'REG', 'REGEDIT', 'EXPAND'
	Alias    = '*'
}
Export-ModuleMember @ExportResourceParams
# SIG # Begin signature block
# MIIMFAYJKoZIhvcNAQcCoIIMBTCCDAECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU3YDLOq3MptySxyVcAOeCmMuA
# d0SgggjkMIIDZTCCAk2gAwIBAgIQcvzm3AoNiblMifO61mXaqjANBgkqhkiG9w0B
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
# b1SjZsLcQ6D0eCcFD+7I7MkcSz2ARu6wUOcxggKaMIIClgIBATBcMEUxFDASBgoJ
# kiaJk/IsZAEZFgRURUNIMRUwEwYKCZImiZPyLGQBGRYFT01OSUMxFjAUBgNVBAMT
# DU9NTklDLlRFQ0gtQ0ECExoAAAAIC4Z11vsOvFYAAAAAAAgwCQYFKw4DAhoFAKCC
# ARMwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwG
# CisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFDcigZFeiZJPvn0t+EYrzbgXx9T/
# MIGyBgorBgEEAYI3AgEMMYGjMIGgoGqAaABSAGUAcwBvAHUAcgBjAGUAcwAgAE0A
# bwBkAHUAbABlACAAZgBvAHIAIAB0AGgAZQAgAE8AcAB0AGkAbQBpAHoAZQAtAE8A
# ZgBmAGwAaQBuAGUAIABmAHIAYQBtAGUAdwBvAHIAawAuoTKAMGh0dHBzOi8vZ2l0
# aHViLmNvbS9EckVtcGlyaWNpc20vT3B0aW1pemUtT2ZmbGluZTANBgkqhkiG9w0B
# AQEFAASCAQAFJxowv2xfjTmcmEj4KjhkOtnVD1Yxalm9bGby4ImuOmRYUdASW6T4
# JhsuRu01i9oiTZP7qG11h1KtPuaNwXz9GPAdOBy50WgJjgDEz99+g4TtBFMPeMgF
# sMEdqJrTVh0OmrNAS1IUN/lOqMDZeEe9yWFUlUsUFKAf2oWPdbSvbzyx6CdM3rZe
# I0K0vEQnK11U+8ox3FwQFpNXNNDhodEMGM/dedL1c9ZsaRsj92Qqna5g1iMUVHbT
# Xp9OnxnjcRIpajEexnsUJ/tneX4x9urPOaCFvASW+fVRav+h7EKxNK/lCMKMq2j5
# ReRuTXJObmeYE6wcLNqRqZYqPHc/CJUl
# SIG # End signature block

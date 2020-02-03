#Requires -RunAsAdministrator
#Requires -Version 5
<#
	===========================================================================
	Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2019 v5.7.172
	Created on:   	11/20/2019 11:53 AM
	Created by:   	BenTheGreat
	Filename:     	Offline-Resources.psm1
	Last updated:	02/03/2020
	-------------------------------------------------------------------------
	Module Name: Offline-Resources
	===========================================================================
#>

#region Import Resource Functions
$PublicFunctions = @(Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath Public) -Filter *.ps1 -ErrorAction SilentlyContinue)
$PrivateFunctions = @(Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath Private) -Filter *.ps1 -ErrorAction SilentlyContinue)

ForEach ($Function In @($PublicFunctions + $PrivateFunctions))
{
	Try { . $Function.FullName }
	Catch { Write-Warning ('Failed to import the required function "{0}", {1}' -f $Function.FullName, $PSItem); Break }
}
#endregion Import Resource Functions

#region New Alias Creation
New-Alias -Name Create -Value New-Container
New-Alias -Name Purge -Value Remove-Container
New-Alias -Name StartExe -Value Start-Executable
New-Alias -Name Log -Value Write-Log
New-Alias -Name RegKey -Value Set-KeyProperty
New-Alias -Name RegHives -Value Get-OfflineHives
New-Alias -Name GetPath -Value Resolve-FullPath
#endregion New Alias Creation

#region Module Declarations
$OfflineResources = [PSCustomObject]::New()
$OfflineResources | Add-Member -MemberType NoteProperty -Name Path -Value (GetPath -Path $PSScriptRoot -Child Offline-Resources.psm1)
$OfflineResources | Add-member -MemberType NoteProperty -Name Name -Value (GetPath -Path $OfflineResources.Path -Split Leaf)
$OfflineResources | Add-Member -MemberType NoteProperty -Name BaseName -Value ([IO.Path]::GetFileNameWithoutExtension($OfflineResources.Name))
$OfflineResources | Add-Member -MemberType NoteProperty -Name Directory -Value (GetPath -Path $OfflineResources.Path -Split Parent)

$OptimizeOffline = [PSCustomObject]::New()
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Path -Value (GetPath -Path (GetPath -Path $OfflineResources.Directory -Split Parent) -Child Optimize-Offline.psm1)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Name -Value (GetPath -Path $OptimizeOffline.Path -Split Leaf)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name BaseName -Value ([IO.Path]::GetFileNameWithoutExtension($OptimizeOffline.Name))
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Directory -Value (GetPath -Path $OptimizeOffline.Path -Split Parent)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Culture -Value 'en-US'
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Resources -Value (GetPath -Path $OptimizeOffline.Directory -Child Src)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Content -Value (GetPath -Path $OptimizeOffline.Directory -Child Content)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name LocalizedData -Value (GetPath -Path $OptimizeOffline.Directory -Child $OptimizeOffline.Culture)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Additional -Value (GetPath -Path $OptimizeOffline.Content -Child Additional)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Packages (GetPath -Path $OptimizeOffline.Directory -Child Packages)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name LocalizedDataStrings -Value (GetPath -Path $OptimizeOffline.LocalizedData -Child Optimize-Offline.strings.psd1)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name ConfigurationJSON -Value (GetPath -Path $OptimizeOffline.Directory -Child Configuration.json)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name ManifestDataFile -Value (GetPath -Path $OptimizeOffline.Directory -Child Optimize-Offline.psd1)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name DaRT -Value (GetPath -Path $OptimizeOffline.Packages -Child DaRT)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Dedup -Value (GetPath -Path $OptimizeOffline.Packages -Child Deduplication)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name DevMode -Value (GetPath -Path $OptimizeOffline.Packages -Child DeveloperMode)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name MicrosoftEdge -Value (GetPath -Path $OptimizeOffline.Packages -Child MicrosoftEdge)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Win32Calc -Value (GetPath -Path $OptimizeOffline.Packages -Child Win32Calc)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name WindowsStore -Value (GetPath -Path $OptimizeOffline.Packages -Child WindowsStore)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name AppxWhitelist -Value (GetPath -Path $OptimizeOffline.Content -Child AppxWhitelist.json)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name CustomAppAssociations -Value (GetPath -Path $OptimizeOffline.Content -Child CustomAppAssociations.xml)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Drivers -Value (GetPath -Path $OptimizeOffline.Additional -Child Drivers)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name InstallDrivers -Value (GetPath -Path $OptimizeOffline.Drivers -Child Install)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name BootDrivers -Value (GetPath -Path $OptimizeOffline.Drivers -Child Boot)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name RecoveryDrivers -Value (GetPath -Path $OptimizeOffline.Drivers -Child Recovery)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name LockScreen -Value (GetPath -Path $OptimizeOffline.Additional -Child LockScreen)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name RegistryTemplates -Value (GetPath -Path $OptimizeOffline.Additional -Child RegistryTemplates)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Setup -Value (GetPath -Path $OptimizeOffline.Additional -Child Setup)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name SystemLogo -Value (GetPath -Path $OptimizeOffline.Additional -Child SystemLogo)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Unattend -Value (GetPath -Path $OptimizeOffline.Additional -Child Unattend)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Wallpaper -Value (GetPath -Path $OptimizeOffline.Additional -Child Wallpaper)
#endregion Module Declarations

#region Data Declarations
Try { $ManifestData = Import-PowerShellDataFile -Path $OptimizeOffline.ManifestDataFile -ErrorAction Stop }
Catch { Write-Warning ('Failed to import the manifest data file: "{0}"' -f (GetPath -Path $OptimizeOffline.ManifestDataFile -Split Leaf)); Break }
#endregion Data Declarations

#region Variable Declarations
$OptimizeParams = [PSCustomObject]::New()
$DynamicParams = [Collections.Hashtable]::New()
$ConfigParams = [Collections.Specialized.OrderedDictionary]::New()
$HostEnvironment = [Collections.Generic.List[Object]]::New(@('Microsoft Windows 10', 'Microsoft Windows Server 2016', 'Microsoft Windows Server 2019'))
$OptimizeErrors = [Collections.Generic.List[Object]]::New()
$TempDirectory = (GetPath -Path $OptimizeOffline.Directory -Child OfflineTemp_$(Get-Random))
$LogFolder = (GetPath -Path $TempDirectory -Child LogOffline)
$WorkFolder = (GetPath -Path $TempDirectory -Child WorkOffline)
$ScratchFolder = (GetPath -Path $TempDirectory -Child ScratchOffline)
$ImageFolder = (GetPath -Path $TempDirectory -Child ImageOffline)
$InstallMount = (GetPath -Path $TempDirectory -Child InstallMountOffline)
$BootMount = (GetPath -Path $TempDirectory -Child BootMountOffline)
$RecoveryMount = (GetPath -Path $TempDirectory -Child RecoveryMountOffline)
$ModuleLog = (GetPath -Path $LogFolder -Child Optimize-Offline.log)
$RegistryLog = (GetPath -Path $LogFolder -Child RegistrySettings.log)
$DISMLog = (GetPath -Path $LogFolder -Child DISM.log)
$PackageLog = (GetPath -Path $LogFolder -Child PackageSummary.log)
$ErrorLog = (GetPath -Path $LogFolder -Child OptimizeErrors.log)
If (Test-Path -LiteralPath (GetPath -Path (Get-DISMPath) -Child dism.exe)) { $DISM = GetPath -Path (Get-DISMPath) -Child dism.exe }
Else { $DISM = GetPath -Path $Env:SystemRoot\System32 -Child dism.exe }
$REG = (GetPath -Path $Env:SystemRoot\System32 -Child reg.exe)
$REGEDIT = (GetPath -Path $Env:SystemRoot -Child regedit.exe)
$EXPAND = (GetPath -Path $Env:SystemRoot\System32 -Child expand.exe)
#endregion Variable Declarations

$ExportResourceParams = @{
	Function = $PublicFunctions.Basename
	Variable = 'OptimizeOffline', 'ManifestData', 'OptimizeParams', 'DynamicParams', 'ConfigParams', 'HostEnvironment', 'OptimizeErrors', 'TempDirectory', 'LogFolder', 'WorkFolder', 'ScratchFolder', 'ImageFolder', 'InstallMount', 'BootMount', 'RecoveryMount', 'ModuleLog', 'RegistryLog', 'DISMLog', 'PackageLog', 'ErrorLog', 'DISM', 'REG', 'REGEDIT', 'EXPAND'
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

<#
	===========================================================================
	Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2019 v5.6.170
	Created on:   	11/20/2019 11:53 AM
	Created by:   	BenTheGreat
	Filename:     	Offline-Resources.psm1
	Last updated:	12/11/2019
	-------------------------------------------------------------------------
	Module Name: Offline-Resources
	===========================================================================
#>

#region Import Required Module and Functions
Try { Get-Module -Name Dism -ListAvailable | Import-Module -Scope Global -ErrorAction Stop }
Catch { Write-Warning "Failed to import the required Dism module."; Break }

$PublicFunctions = @(Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath Public) -Filter *.ps1)
$PrivateFunctions = @(Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath Private) -Filter *.ps1)

ForEach ($Function In @($PublicFunctions + $PrivateFunctions))
{
	Try { . $Function.FullName }
	Catch { Write-Warning ('Failed to import the required function "{0}", {1}' -f $Function.FullName, $PSItem); Break }
}
#endregion Import Required Module and Functions

#region Module Declarations
$OfflineResources = [PSCustomObject]::New()
$OfflineResources | Add-Member -MemberType NoteProperty -Name Path -Value (Get-Path -Path $PSScriptRoot -ChildPath Offline-Resources.psm1)
$OfflineResources | Add-member -MemberType NoteProperty -Name Name -Value (Get-Path -Path $OfflineResources.Path -Split Leaf)
$OfflineResources | Add-Member -MemberType NoteProperty -Name BaseName -Value ([IO.Path]::GetFileNameWithoutExtension($OfflineResources.Name))
$OfflineResources | Add-Member -MemberType NoteProperty -Name Directory -Value (Get-Path -Path $OfflineResources.Path -Split Parent)

$OptimizeOffline = [PSCustomObject]::New()
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Path -Value (Get-Path -Path (Get-Path -Path $OfflineResources.Directory -Split Parent) -ChildPath Optimize-Offline.psm1)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Name -Value (Get-Path -Path $OptimizeOffline.Path -Split Leaf)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name BaseName -Value ([IO.Path]::GetFileNameWithoutExtension($OptimizeOffline.Name))
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Directory -Value (Get-Path -Path $OptimizeOffline.Path -Split Parent)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Resources -Value (Get-Path -Path $OptimizeOffline.Directory -ChildPath Src)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Content -Value (Get-Path -Path $OptimizeOffline.Directory -ChildPath Content)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name LocalizedData -Value (Get-Path -Path $OptimizeOffline.Directory -ChildPath en-US)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Additional -Value (Get-Path -Path $OptimizeOffline.Content -ChildPath Additional)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Packages (Get-Path -Path $OptimizeOffline.Directory -ChildPath Packages)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name LocalizedDataStrings -Value (Get-Path -Path $OptimizeOffline.LocalizedData -ChildPath Optimize-Offline.strings.psd1)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name ConfigurationJSON -Value (Get-Path -Path $OptimizeOffline.Directory -ChildPath Configuration.json)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name ManifestDataFile -Value (Get-Path -Path $OptimizeOffline.Directory -ChildPath Optimize-Offline.psd1)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name DaRT -Value (Get-Path -Path $OptimizeOffline.Packages -ChildPath DaRT)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Dedup -Value (Get-Path -Path $OptimizeOffline.Packages -ChildPath Deduplication)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name DevMode -Value (Get-Path -Path $OptimizeOffline.Packages -ChildPath DeveloperMode)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name MicrosoftEdge -Value (Get-Path -Path $OptimizeOffline.Packages -ChildPath MicrosoftEdge)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Win32Calc -Value (Get-Path -Path $OptimizeOffline.Packages -ChildPath Win32Calc)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name WindowsStore -Value (Get-Path -Path $OptimizeOffline.Packages -ChildPath WindowsStore)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name AppxWhitelist -Value (Get-Path -Path $OptimizeOffline.Content -ChildPath AppxWhitelist.json)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name CustomAppAssociations -Value (Get-Path -Path $OptimizeOffline.Content -ChildPath CustomAppAssociations.xml)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Drivers -Value (Get-Path -Path $OptimizeOffline.Additional -ChildPath Drivers)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name InstallDrivers -Value (Get-Path -Path $OptimizeOffline.Drivers -ChildPath Install)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name BootDrivers -Value (Get-Path -Path $OptimizeOffline.Drivers -ChildPath Boot)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name RecoveryDrivers -Value (Get-Path -Path $OptimizeOffline.Drivers -ChildPath Recovery)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name LockScreen -Value (Get-Path -Path $OptimizeOffline.Additional -ChildPath LockScreen)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name RegistryTemplates -Value (Get-Path -Path $OptimizeOffline.Additional -ChildPath RegistryTemplates)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Setup -Value (Get-Path -Path $OptimizeOffline.Additional -ChildPath Setup)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name SystemLogo -Value (Get-Path -Path $OptimizeOffline.Additional -ChildPath SystemLogo)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Unattend -Value (Get-Path -Path $OptimizeOffline.Additional -ChildPath Unattend)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name Wallpaper -Value (Get-Path -Path $OptimizeOffline.Additional -ChildPath Wallpaper)
$OptimizeOffline | Add-Member -MemberType NoteProperty -Name AdditionalJSON -Value (Get-Path -Path $OptimizeOffline.Additional -ChildPath Additional.json)
#endregion Module Declarations

#region Data Declarations
Try { $ManifestData = Import-PowerShellDataFile -Path $OptimizeOffline.ManifestDataFile -ErrorAction Stop }
Catch { Write-Warning ('Failed to import the manifest data file: "{0}"' -f (Get-Path -Path $OptimizeOffline.ManifestDataFile -Split Leaf)); Break }
#endregion Data Declarations

#region Variable Declarations
$ConfigParams = [Collections.Specialized.OrderedDictionary]::New()
$DynamicParams = [Collections.Hashtable]::New()
$TempDirectory = (Get-Path -Path $OptimizeOffline.Directory -ChildPath OfflineTemp_$(Get-Random))
$LogFolder = (Get-Path -Path $TempDirectory -ChildPath LogOffline)
$WorkFolder = (Get-Path -Path $TempDirectory -ChildPath WorkOffline)
$ScratchFolder = (Get-Path -Path $TempDirectory -ChildPath ScratchOffline)
$ImageFolder = (Get-Path -Path $TempDirectory -ChildPath ImageOffline)
$InstallMount = (Get-Path -Path $TempDirectory -ChildPath InstallMountOffline)
$BootMount = (Get-Path -Path $TempDirectory -ChildPath BootMountOffline)
$RecoveryMount = (Get-Path -Path $TempDirectory -ChildPath RecoveryMountOffline)
$ModuleLog = (Get-Path -Path $LogFolder -ChildPath Optimize-Offline.log)
$RegistryLog = (Get-Path -Path $LogFolder -ChildPath RegistrySettings.log)
$DISMLog = (Get-Path -Path $LogFolder -ChildPath DISM.log)
$PackageLog = (Get-Path -Path $LogFolder -ChildPath PackageSummary.log)
$DISM = (Get-Path -Path $Env:SystemRoot\System32 -ChildPath dism.exe)
$REG = (Get-Path -Path $Env:SystemRoot\System32 -ChildPath reg.exe)
$REGEDIT = (Get-Path -Path $Env:SystemRoot -ChildPath regedit.exe)
$EXPAND = (Get-Path -Path $Env:SystemRoot\System32 -ChildPath expand.exe)
#endregion Variable Declarations

#region New Alias Creation
New-Alias -Name Create -Value New-Container
New-Alias -Name Purge -Value Remove-Container
New-Alias -Name StartExe -Value Start-Executable
New-Alias -Name Log -Value Write-Log
New-Alias -Name RegKey -Value Set-KeyProperty
New-Alias -Name RegHives -Value Get-OfflineHives
New-Alias -Name Stop -Value Stop-Optimize
#endregion New Alias Creation

$ExportResourceParams = @{
	Function = $PublicFunctions.Basename
	Variable = 'OptimizeOffline', 'ManifestData', 'ConfigParams', 'DynamicParams', 'TempDirectory', 'LogFolder', 'WorkFolder', 'ScratchFolder', 'ImageFolder', 'InstallMount', 'BootMount', 'RecoveryMount', 'ModuleLog', 'RegistryLog', 'DISMLog', 'PackageLog', 'DISM', 'REG', 'REGEDIT', 'EXPAND'
	Alias    = '*'
}
Export-ModuleMember @ExportResourceParams
# SIG # Begin signature block
# MIIMFAYJKoZIhvcNAQcCoIIMBTCCDAECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUfdhq/FoPvp1a2bafPoWtnnLH
# NwOgggjkMIIDZTCCAk2gAwIBAgIQcvzm3AoNiblMifO61mXaqjANBgkqhkiG9w0B
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
# CisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFDEcG12KwQdJWZ6pv1fxPp/Gq9NY
# MIGyBgorBgEEAYI3AgEMMYGjMIGgoGqAaABSAGUAcwBvAHUAcgBjAGUAcwAgAE0A
# bwBkAHUAbABlACAAZgBvAHIAIAB0AGgAZQAgAE8AcAB0AGkAbQBpAHoAZQAtAE8A
# ZgBmAGwAaQBuAGUAIABmAHIAYQBtAGUAdwBvAHIAawAuoTKAMGh0dHBzOi8vZ2l0
# aHViLmNvbS9EckVtcGlyaWNpc20vT3B0aW1pemUtT2ZmbGluZTANBgkqhkiG9w0B
# AQEFAASCAQBR6JccsiRShdfv9BchmTcd+mtriDHotDQdt3jFvhiiZqeNcyvLgRXZ
# QweJKvpGWj62lm2lAr5oMCD1p1RIux8ZU+cUNK6YNnuh/QJeJyPwQ0EAyJrOfU3Z
# uQwgOL647GorugZUl4/vnXqtnZa8SJ9cxosTsph//AbFBmiHvzCeZixkUry890re
# AzZ3tF8x3r7QaMeqOPqrHfdeJJ4Z1xCgfDXbZDssJexOZRVy8GXgIXeGcqGAJPwY
# d/LeeCn3vMyDu8VegXciyw/0GaA/+8gDeNyN6SpcDrlWoh+sIW5944vXO9PENLmi
# NnI7tlZt8Ewoy+k8N0n6KzEALzuZXdVZ
# SIG # End signature block

Using namespace System.Collections.Generic
#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
	===========================================================================
	Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2021 v5.8.192
	Created on:   	11/20/2019 11:53 AM
	Created by:   	BenTheGreat
	Filename:     	Offline-Resources.psm1
	Last updated:	08/04/2021
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
$OptimizeOffline.SelectiveRegistry = (Resolve-FullPath -Path $OptimizeOffline.Additional -Child SelectiveRegistry)
#endregion Module Path Declarations


#region List paths
$OptimizeOffline.Lists = @{}
$OptimizeOffline.Lists.Path = (Resolve-FullPath -Path $OptimizeOffline.Content -Child Lists)

$OptimizeOffline.Lists.WindowsApps = @{}
$OptimizeOffline.Lists.WindowsApps.Path = (Resolve-FullPath -Path $OptimizeOffline.Lists.Path -Child WindowsApps)
$OptimizeOffline.Lists.WindowsApps.Whitelist = (Resolve-FullPath -Path $OptimizeOffline.Lists.WindowsApps.Path -Child WindowsAppsWhitelist.json)
$OptimizeOffline.Lists.WindowsApps.Blacklist = (Resolve-FullPath -Path $OptimizeOffline.Lists.WindowsApps.Path -Child WindowsAppsBlacklist.json)
$OptimizeOffline.Lists.WindowsApps.Template = (Resolve-FullPath -Path $OptimizeOffline.Lists.WindowsApps.Path -Child WindowsAppsTemplate.json)

$OptimizeOffline.Lists.SystemApps = @{}
$OptimizeOffline.Lists.SystemApps.Path = (Resolve-FullPath -Path $OptimizeOffline.Lists.Path -Child SystemApps)
$OptimizeOffline.Lists.SystemApps.Whitelist = (Resolve-FullPath -Path $OptimizeOffline.Lists.SystemApps.Path -Child SystemAppsWhitelist.json)
$OptimizeOffline.Lists.SystemApps.Blacklist = (Resolve-FullPath -Path $OptimizeOffline.Lists.SystemApps.Path -Child SystemAppsBlacklist.json)
$OptimizeOffline.Lists.SystemApps.Template = (Resolve-FullPath -Path $OptimizeOffline.Lists.SystemApps.Path -Child SystemAppsTemplate.json)

$OptimizeOffline.Lists.Capabilities = @{}
$OptimizeOffline.Lists.Capabilities.Path = (Resolve-FullPath -Path $OptimizeOffline.Lists.Path -Child Capabilities)
$OptimizeOffline.Lists.Capabilities.Whitelist = (Resolve-FullPath -Path $OptimizeOffline.Lists.Capabilities.Path -Child CapabilitiesWhitelist.json)
$OptimizeOffline.Lists.Capabilities.Blacklist = (Resolve-FullPath -Path $OptimizeOffline.Lists.Capabilities.Path -Child CapabilitiesBlacklist.json)
$OptimizeOffline.Lists.Capabilities.Template = (Resolve-FullPath -Path $OptimizeOffline.Lists.Capabilities.Path -Child CapabilitiesTemplate.json)

$OptimizeOffline.Lists.Packages = @{}
$OptimizeOffline.Lists.Packages.Path = (Resolve-FullPath -Path $OptimizeOffline.Lists.Path -Child Packages)
$OptimizeOffline.Lists.Packages.Whitelist = (Resolve-FullPath -Path $OptimizeOffline.Lists.Packages.Path -Child PackagesWhitelist.json)
$OptimizeOffline.Lists.Packages.Blacklist = (Resolve-FullPath -Path $OptimizeOffline.Lists.Packages.Path -Child PackagesBlacklist.json)
$OptimizeOffline.Lists.Packages.Template = (Resolve-FullPath -Path $OptimizeOffline.Lists.Packages.Path -Child PackagesTemplate.json)

$OptimizeOffline.Lists.FeaturesToEnable = @{}
$OptimizeOffline.Lists.FeaturesToEnable.Path = (Resolve-FullPath -Path $OptimizeOffline.Lists.Path -Child FeaturesToEnable)
$OptimizeOffline.Lists.FeaturesToEnable.List = (Resolve-FullPath -Path $OptimizeOffline.Lists.FeaturesToEnable.Path -Child FeaturesToEnableList.json)
$OptimizeOffline.Lists.FeaturesToEnable.Template = (Resolve-FullPath -Path $OptimizeOffline.Lists.FeaturesToEnable.Path -Child FeaturesToEnableTemplate.json)

$OptimizeOffline.Lists.FeaturesToDisable = @{}
$OptimizeOffline.Lists.FeaturesToDisable.Path = (Resolve-FullPath -Path $OptimizeOffline.Lists.Path -Child FeaturesToDisable)
$OptimizeOffline.Lists.FeaturesToDisable.List = (Resolve-FullPath -Path $OptimizeOffline.Lists.FeaturesToDisable.Path -Child FeaturesToDisableList.json)
$OptimizeOffline.Lists.FeaturesToDisable.Template = (Resolve-FullPath -Path $OptimizeOffline.Lists.FeaturesToDisable.Path -Child FeaturesToDisableTemplate.json)

$OptimizeOffline.Lists.Services = @{}
$OptimizeOffline.Lists.Services.Path = (Resolve-FullPath -Path $OptimizeOffline.Lists.Path -Child Services)
$OptimizeOffline.Lists.Services.List = (Resolve-FullPath -Path $OptimizeOffline.Lists.Services.Path -Child ServicesList.json)
$OptimizeOffline.Lists.Services.Advanced = (Resolve-FullPath -Path $OptimizeOffline.Lists.Services.Path -Child ServicesAdvanced.json)
$OptimizeOffline.Lists.Services.Template = (Resolve-FullPath -Path $OptimizeOffline.Lists.Services.Path -Child ServicesTemplate.json)
#endregion List paths

#region Data Declarations
Try { $ManifestData = Import-PowerShellDataFile -Path $OptimizeOffline.ManifestDataFile -ErrorAction Stop }
Catch { Write-Warning ('Failed to import the manifest data file: "{0}"' -f (Resolve-FullPath -Path $OptimizeOffline.ManifestDataFile -Split Leaf)); Break }

Try { Import-LocalizedData -BaseDirectory $OptimizeOffline.Directory -FileName Optimize-Offline.strings.psd1 -BindingVariable OptimizeData -ErrorAction Stop }
Catch { Write-Warning ('Failed to import the localized data file: "{0}"' -f (Resolve-FullPath -Path $OptimizeOffline.LocalizedDataStrings -Split Leaf)); Break }
#endregion Data Declarations

#region translations
$OptimizeOffline.ServicesStartLabels = @{
	0 = $OptimizeData.ServiceStartBoot
	1 = $OptimizeData.ServiceStartSystem
	2 = $OptimizeData.ServiceStartAutomatic
	3 = $OptimizeData.ServiceStartManual
	4 = $OptimizeData.ServiceStartDisabled
}
#endregion translations

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
$DISM = If (Get-DeploymentTool) { Resolve-FullPath -Path $(Get-DeploymentTool) -Child dism.exe } Else { Resolve-FullPath -Path $Env:SystemRoot -Child 'System32\dism.exe' }
$OSCDIMG = If (Get-DeploymentTool -OSCDIMG) { 
	Resolve-FullPath -Path $(Get-DeploymentTool -OSCDIMG) -Child oscdimg.exe 
} Elseif (Test-Path -Path $(Resolve-FullPath -Path $OptimizeOffline.Directory -Child oscdimg.exe)) {
	Resolve-FullPath -Path $OptimizeOffline.Directory -Child oscdimg.exe
} Else {
	$null
}
$REG = (Resolve-FullPath -Path $Env:SystemRoot -Child 'System32\reg.exe')
$REGEDIT = (Resolve-FullPath -Path $Env:SystemRoot -Child regedit.exe)
$EXPAND = (Resolve-FullPath -Path $Env:SystemRoot -Child 'System32\expand.exe')
$AllowedRemovalOptions = @('All', 'Select', 'List', 'Whitelist', 'BlackList', 'Advanced')
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
	Variable = 'OptimizeOffline', 'ManifestData', 'OptimizeData', 'LocalScope', 'OptimizeParams', 'DynamicParams', 'ConfigParams', 'OptimizeErrors', 'TempDirectory', 'LogFolder', 'WorkFolder', 'ScratchFolder', 'ImageFolder', 'InstallMount', 'BootMount', 'RecoveryMount', 'ModuleLog', 'ErrorLog', 'RegistryLog', 'DISMLog', 'DISM', 'OSCDIMG', 'REG', 'REGEDIT', 'EXPAND', 'AllowedRemovalOptions'
	Alias    = '*'
}
Export-ModuleMember @ExportResourceParams
# SIG # Begin signature block
# MIIMFAYJKoZIhvcNAQcCoIIMBTCCDAECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUJEtFCcJUCgrg3LUnsuvNRKks
# Sh2gggjkMIIDZTCCAk2gAwIBAgIQcvzm3AoNiblMifO61mXaqjANBgkqhkiG9w0B
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
# ozlL4YdE7lQ8EDTiKZTIMIIFdzCCBF+gAwIBAgITGgAAABuiU/ojidF4nQAAAAAA
# GzANBgkqhkiG9w0BAQsFADBFMRQwEgYKCZImiZPyLGQBGRYEVEVDSDEVMBMGCgmS
# JomT8ixkARkWBU9NTklDMRYwFAYDVQQDEw1PTU5JQy5URUNILUNBMB4XDTIwMDUx
# NjExNTAzOFoXDTIxMDUxNjExNTAzOFowUzEUMBIGCgmSJomT8ixkARkWBFRFQ0gx
# FTATBgoJkiaJk/IsZAEZFgVPTU5JQzEOMAwGA1UEAxMFVXNlcnMxFDASBgNVBAMT
# C0JlblRoZUdyZWF0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAllg+
# PmYSHbLuBPbIuHgIAhNky4d9dENqbHAO2W25Tsn4wPz/g7CLHK+kaVq8LwIj6pC9
# zwdlXs6zWcU54xCmNwKhEs75WLeMA3KuV3B07SEULRloQuzlhzzbRulvAeQRHOPK
# zj+qtgmLY69U8o/FsSYG5ZehaCDXF+0N7tC/IWuJViaQnxNBISRlOo+2iUIHk5E9
# bTwFBOySBHizHYFKtcm7viRaH4izBL5zBPZZwrwA9iQDVU/Nld5EMyWouDkPybtG
# IuVLj/6PWEdNOHw1QcYFlmb+7AE5DyPkouR6VMrMwloVRCMdGyMsuoxO89C925GJ
# XxggpgmlS+sW9koCWQIDAQABo4ICUDCCAkwwJQYJKwYBBAGCNxQCBBgeFgBDAG8A
# ZABlAFMAaQBnAG4AaQBuAGcwEwYDVR0lBAwwCgYIKwYBBQUHAwMwDgYDVR0PAQH/
# BAQDAgeAMDEGA1UdEQQqMCigJgYKKwYBBAGCNxQCA6AYDBZCZW5UaGVHcmVhdEBP
# TU5JQy5URUNIMB0GA1UdDgQWBBSobni9ugG9hTy2Dmdb/GDEwJJpxTAfBgNVHSME
# GDAWgBRs5nLk5cGEWCwNRP1xmRx6dvhqkzCByQYDVR0fBIHBMIG+MIG7oIG4oIG1
# hoGybGRhcDovLy9DTj1PTU5JQy5URUNILUNBLENOPUFOVUJJUyxDTj1DRFAsQ049
# UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJh
# dGlvbixEQz1PTU5JQyxEQz1URUNIP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/
# YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvgYIKwYBBQUH
# AQEEgbEwga4wgasGCCsGAQUFBzAChoGebGRhcDovLy9DTj1PTU5JQy5URUNILUNB
# LENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxD
# Tj1Db25maWd1cmF0aW9uLERDPU9NTklDLERDPVRFQ0g/Y0FDZXJ0aWZpY2F0ZT9i
# YXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwDQYJKoZIhvcN
# AQELBQADggEBAHkE5DhgUC3lTaRW9IO5XDjndfLppttn4C6YgU/XKYqFryxIIhVc
# PjNSbjDhqIXP+HyurG56f/0DgnOwj2x0ijVXYxpW1IOW6ni1NGbq22WJF1Zbsl6X
# YkBV0Uwi9nDNkXTf0lDebn0fTujWTuSQTUi5QB/w12X6yQUd7H/S51ycsnYRZpnz
# NnVmTJPJAmPSERpemwj9gZkiibbdm9vAO5p9UesX9iqwSyrhsfwS1rmW4tUWqYqH
# hZIpQjF1CCV3+u6H/f9XXGtwDl4OKFYOiXUqHx7U7+AYwRd51uQgtKocNa0d7pD9
# 3bLGrPlkmMsI8xKcO909nyejvk01H5obHCcxggKaMIIClgIBATBcMEUxFDASBgoJ
# kiaJk/IsZAEZFgRURUNIMRUwEwYKCZImiZPyLGQBGRYFT01OSUMxFjAUBgNVBAMT
# DU9NTklDLlRFQ0gtQ0ECExoAAAAbolP6I4nReJ0AAAAAABswCQYFKw4DAhoFAKCC
# ARMwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwG
# CisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFCMnRsKbsteKHu7ZYzNoDBPh0O7q
# MIGyBgorBgEEAYI3AgEMMYGjMIGgoGqAaABSAGUAcwBvAHUAcgBjAGUAcwAgAE0A
# bwBkAHUAbABlACAAZgBvAHIAIAB0AGgAZQAgAE8AcAB0AGkAbQBpAHoAZQAtAE8A
# ZgBmAGwAaQBuAGUAIABmAHIAYQBtAGUAdwBvAHIAawAuoTKAMGh0dHBzOi8vZ2l0
# aHViLmNvbS9EckVtcGlyaWNpc20vT3B0aW1pemUtT2ZmbGluZTANBgkqhkiG9w0B
# AQEFAASCAQAhDdBBTJG9Bt7CetTLk0J2gWGr8A9UMNQsDPWi+Xoo6RkHV7YS3Y22
# SKfbY7EpQyy1vkFIVEOYoqC5UTytTdsmHPejbNpjoOSi12cCbJTCzR8LfHEqqEiU
# eRnwjvcox6ozjFO/8Ge7H2N+CVjJ+p2X0SJ9U+YyGpAEXkyff6qi0qJDoiZLyv+K
# hSmO2So1UrceINwFGrnIlM2vrl/iRy6tS6ICEs/HD1o65q46zLw1ZgSV+nLqV7XC
# k8ozY9yV73ZQkETPG6q7WvMnyEIRTz8RXWMRJXqEXRhxfJNxYvqivVUrRGjAZbkC
# c6UrrwGtj8ThprVl8EwyqUAp68p2JZI7
# SIG # End signature block

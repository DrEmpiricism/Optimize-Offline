<#
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2019 v5.6.168
	 Created by:   	BenTheGreat
	 Filename:     	OfflineProcessing.psm1
	 Last updated:	11/15/2019
	===========================================================================
#>

#region Variables
$ScriptInfo = [PSCustomObject]@{ Version = '3.2.7.7'; Name = 'Optimize-Offline'; Path = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath Optimize-Offline.ps1 }
$ModuleInfo = [PSCustomObject]@{ Name = 'OfflineProcessing'; Path = Join-Path -Path $PSScriptRoot -ChildPath OfflineProcessing.psm1 }
$ScriptRootPath = Split-Path -Path $ScriptInfo.Path -Parent
$ModuleRootPath = Split-Path -Path $ModuleInfo.Path -Parent
$DaRTPath = Join-Path -Path $ScriptRootPath -ChildPath 'Resources\DaRT'
$DedupPath = Join-Path -Path $ScriptRootPath -ChildPath 'Resources\Deduplication'
$DevModePath = Join-Path -Path $ScriptRootPath -ChildPath 'Resources\DeveloperMode'
$EdgeAppPath = Join-Path -Path $ScriptRootPath -ChildPath 'Resources\MicrosoftEdge'
$StoreAppPath = Join-Path -Path $ScriptRootPath -ChildPath 'Resources\WindowsStore'
$Win32CalcPath = Join-Path -Path $ScriptRootPath -ChildPath 'Resources\Win32Calc'
$AdditionalPath = Join-Path -Path $ScriptRootPath -ChildPath 'Content\Additional'
$AppAssocPath = Join-Path -Path $ScriptRootPath -ChildPath 'Content\CustomAppAssociations.xml'
$WhitelistJsonPath = Join-Path -Path $ScriptRootPath -ChildPath 'Content\AppxWhiteList.json'
$AdditionalJsonPath = Join-Path -Path $AdditionalPath -ChildPath Additional.json
$TempDirectory = Join-Path -Path $ScriptRootPath -ChildPath "OfflineTemp_$(Get-Random)"
$LogDirectory = Join-Path -Path $TempDirectory -ChildPath LogOffline
$WorkDirectory = Join-Path -Path $TempDirectory -ChildPath WorkOffline
$ScratchDirectory = Join-Path -Path $TempDirectory -ChildPath ScratchOffline
$ImageDirectory = Join-Path -Path $TempDirectory -ChildPath ImageOffline
$InstallMount = Join-Path -Path $TempDirectory -ChildPath InstallMountOffline
$BootMount = Join-Path -Path $TempDirectory -ChildPath BootMountOffline
$RecoveryMount = Join-Path -Path $TempDirectory -ChildPath RecoveryMountOffline
$ScriptLog = Join-Path -Path $LogDirectory -ChildPath Optimize-Offline.log
$PackageLog = Join-Path -Path $LogDirectory -ChildPath PackageSummary.log
$DISMLog = Join-Path -Path $LogDirectory -ChildPath DISM.log
$DISM = Join-Path -Path $Env:SystemRoot\System32 -ChildPath dism.exe
$REG = Join-Path -Path $Env:SystemRoot\System32 -ChildPath reg.exe
$REGEDIT = Join-Path -Path $Env:SystemRoot -ChildPath regedit.exe
$EXPAND = Join-Path -Path $Env:SystemRoot\System32 -ChildPath expand.exe
$DynamicParams = @{ }
#endregion Variables

$Internal = @(Get-ChildItem -Path (Join-Path -Path $ModuleRootPath -ChildPath 'Functions\Internal') -Filter *.ps1)
$External = @(Get-ChildItem -Path (Join-Path -Path $ModuleRootPath -ChildPath 'Functions\External') -Filter *.ps1)
ForEach ($Function In @($Internal + $External)) { . $Function.FullName }

New-Alias -Name Create -Value New-Container
New-Alias -Name Purge -Value Remove-Container
New-Alias -Name RegKey -Value Set-KeyProperty
New-Alias -Name Cleanup -Value Invoke-Cleanup
New-Alias -Name RunExe -Value Start-Executable
New-Alias -Name Log -Value Write-Log
New-Alias -Name WimData -Value Get-WimFile
New-Alias -Name RegHives -Value Get-OfflineHives
New-Alias -Name RegImport -Value Import-RegistryTemplates
New-Alias -Name Stop -Value Stop-Optimize
New-Alias -Name UnmountAll -Value Dismount-Images
New-Alias -Name TestReq -Value Test-Requirements
New-Alias -Name SetLock -Value Set-LockScreen

Export-ModuleMember -Function $External.Basename -Variable * -Alias *
# SIG # Begin signature block
# MIIMFgYJKoZIhvcNAQcCoIIMBzCCDAMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQULN6wrwXxNGxVbabkcUUtaogs
# n9egggjkMIIDZTCCAk2gAwIBAgIQcvzm3AoNiblMifO61mXaqjANBgkqhkiG9w0B
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
# b1SjZsLcQ6D0eCcFD+7I7MkcSz2ARu6wUOcxggKcMIICmAIBATBcMEUxFDASBgoJ
# kiaJk/IsZAEZFgRURUNIMRUwEwYKCZImiZPyLGQBGRYFT01OSUMxFjAUBgNVBAMT
# DU9NTklDLlRFQ0gtQ0ECExoAAAAIC4Z11vsOvFYAAAAAAAgwCQYFKw4DAhoFAKCC
# ARUwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwG
# CisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFP3ZJKJPkGaQAp2CeQz11sM5BgDB
# MIG0BgorBgEEAYI3AgEMMYGlMIGioEaARABPAHAAdABpAG0AaQB6AGUALQBPAGYA
# ZgBsAGkAbgBlACAAUAByAG8AYwBlAHMAcwBpAG4AZwAgAE0AbwBkAHUAbABloViA
# Vmh0dHBzOi8vZ2l0aHViLmNvbS9EckVtcGlyaWNpc20vT3B0aW1pemUtT2ZmbGlu
# ZS9yYXcvbWFzdGVyL0xpYi9PZmZsaW5lUHJvY2Vzc2luZy5wc20xMA0GCSqGSIb3
# DQEBAQUABIIBAFebyxDTfH4fCsYb99sxX3l3csET+lMye821OtOUqBMBTB0i2JSY
# heEWMxs6SwuQ7A0Fervyx3MOHk1k4SnvliD04CePADdBEPL9V1j3Z4n6qt4nV7Yi
# zFTEXCBTYgimhLDh5RrdZDYdo8KKZjLIXkmYgTkvj+mu02dJwJAXA+76tlL1TM6g
# tpOTGzP0CudnHlPr6TyKKXwiPaqkkdwkxHAGp1u+rCngskQPsJaw35TzmkwJmZtq
# +K9OGFF4ck/GLWU5tGPPVKpQ/kEjKwHduggpDVfV9h+95d2C3Gb19QvjXSRatOyS
# 2GtlBPcYTsKWZTJ2zleLNjOl29fRlxmkN3k=
# SIG # End signature block

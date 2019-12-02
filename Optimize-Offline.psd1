<#
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2019 v5.6.170
	 Created on:   	11/20/2019 11:53 AM
	 Created by:   	BenTheGreat
	 Filename:     	Optimize-Offline.psd1
	 -------------------------------------------------------------------------
	 Module Manifest
	-------------------------------------------------------------------------
	 Module Name: Optimize-Offline
	===========================================================================
#>

@{
	GUID                   = "86c4db30-1a45-43c7-a96b-46d2a1d84671"
	RootModule             = "Optimize-Offline.psm1"
	ModuleName             = "Optimize-Offline"
	ModuleVersion          = "4.0.0.0"
	Author                 = "Ben White"
	Copyright              = "(c) 2019. All rights reserved."
	Description            = "The Optimize-Offline module enables the offline optimizing of Windows 10 image (WIM) files for optimal runtime environments."
	Culture                = "en-US"
	PowerShellVersion      = "5.0"
	DotNetFrameworkVersion = "4.0"
	CLRVersion             = "2.0.50727"
	ProcessorArchitecture  = "AMD64"
	HostEnvironment        = @("Microsoft Windows 10", "Microsoft Windows Server 2016", "Microsoft Windows Server 2019")
	RequiredModules        = @("Dism", ".\Src\OfflineResources.psm1")
	NestedModules          = @(".\Src\OfflineResources.psm1")
	ModuleList             = @(".\Optimize-Offline.psm1", ".\Src\OfflineResources.psm1")
	FunctionsToExport      = "Optimize-Offline"
	CmdletsToExport        = @()
	PrivateData            = @{
		PSData = @{
			Tags         = @("Image optimization", "Offline Windows image", "WIM image", "Offline servicing", "Windows 10", "LTSC", "Deployment", "Debloat", "PSModule")
			LicenseUri   = "https://github.com/DrEmpiricism/Optimize-Offline/blob/master/LICENSE"
			ProjectUri   = "https://github.com/DrEmpiricism/Optimize-Offline"
			ReleaseNotes = "FullRelease"
		}
	}
}
<#
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2021 v5.8.194
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
	GUID                   = '86c4db30-1a45-43c7-a96b-46d2a1d84671'
	RootModule             = 'Optimize-Offline.psm1'
	ModuleVersion          = '4.0.1.9'
	ModuleForkVersion      = 'gdeliana-7.1'
	Author                 = 'Ben White'
	Copyright              = '(c) 2021. All rights reserved.'
	Description            = 'The Optimize-Offline module enables the offline optimizing of Windows images (WIM/ESD) files for optimal runtime environments.'
	HelpInfoUri            = 'https://github.com/DrEmpiricism/Optimize-Offline/blob/master/en-US/Optimize-Offline-help.xml'
	PowerShellVersion      = '5.1'
	DotNetFrameworkVersion = '4.0'
	CLRVersion             = '4.0'
	ProcessorArchitecture  = 'Amd64'
	RequiredModules        = @('.\Src\Offline-Resources.psm1')
	ModuleList             = @('.\Optimize-Offline.psm1', '.\Src\Offline-Resources.psm1')
	NestedModules          = @('.\Src\Offline-Resources.psm1')
	FunctionsToExport      = 'Optimize-Offline'
	CmdletsToExport        = @()
	PrivateData            = @{
		PSData = @{
			Tags         = @('Image Optimization', 'WIM Optimization', 'Offline Windows Image', 'Offline Servicing', 'Offline Imaging', 'WIM', 'SWM', 'ESD', 'Windows 10', 'Windows 11', 'LTSC', 'Enterprise', '19H1', '19H2', '20H1', '20H2', '21H1', '21H2', 'Deployment', 'Debloat', 'DISM', 'PSModule')
			LicenseUri   = 'https://github.com/DrEmpiricism/Optimize-Offline/blob/master/LICENSE'
			ProjectUri   = 'https://github.com/DrEmpiricism/Optimize-Offline'
			ReleaseNotes = 'https://github.com/DrEmpiricism/Optimize-Offline/blob/master/ChangeLog.md'
		}
	}
}
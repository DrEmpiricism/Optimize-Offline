Using module .\Optimize-Offline.psm1
#Requires -RunAsAdministrator
<#
	.SYNOPSIS
		Start-Optimize is a configuration call script for the Optimize-Offline module.

	.DESCRIPTION
		Start-Optimize automatically imports the configuration JSON file (Configuration.json) into the Optimize-Offline module.

	.EXAMPLE
		.\Start-Optimize.ps1

		This command requires no additional parameters and will import all values set in the configuration JSON file into the Optimize-Offline module and begin the optimization process.

	.NOTES
		Start-Optimize requires that the configuration JSON file is present in the root path of the Optimize-Offline module.
#>
[CmdletBinding()]
Param ()

# Ensure we are running with administrative permissions first.
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
	Write-Warning "Elevation is required to process optimizations. Please relaunch Start-Optimize as an administrator."
	Start-Sleep 3
	Exit
}

# Ensure the configuration JSON file is present.
If (!(Test-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath Configuration.json)))
{
	Write-Warning "Missing the required configuration JSON file."
	Start-Sleep 3
	Exit
}

# Import the Dism module.
Try { Get-Module -Name Dism -ListAvailable | Import-Module -MinimumVersion 3.0 -ErrorAction Stop }
Catch { Write-Warning "Failed to import the required Dism module."; Break }

# Clear the global error variable.
$Error.Clear()

# If the ordered collection list variable still exists from a previous session, remove it.
If (Test-Path -Path Variable:\ConfigParams) { Remove-Variable -Name ConfigParams }

# Use a Try/Catch block in case the configuration JSON file URL formatting is invalid so we can catch it, correct its formatting and continue.
Try
{
	[IO.FileInfo]$ConfigJSON = (Join-Path -Path $PSScriptRoot -ChildPath Configuration.json)
	$ContentJSON = Get-Content -Path $ConfigJSON.FullName -Raw | ConvertFrom-Json
}
Catch [ArgumentException]
{
	$ContentJSON = (Get-Content -Path $ConfigJSON.FullName -Raw).Replace('\', '\\') | Set-Content -Path $ConfigJSON.FullName -Encoding UTF8 -Force -PassThru
	$ContentJSON = $ContentJSON | ConvertFrom-Json
	$Error.Remove($Error[-1])
}

If ($ContentJSON -is [PSObject])
{
	# Convert the JSON object into an ordered collection list. We use the PSObject.Properties method to retain the order of the list.
	$ConfigParams = [Ordered]@{ }
	$ContentJSON.PSObject.Properties.Remove('_Info')
	ForEach ($Property In $ContentJSON.PSObject.Properties.Name)
	{
		$Key = $Property
		$Value = $ContentJSON.PSObject.Properties.Item($Property).Value
		$ConfigParams.Add($Key, $Value)
	}
}

# If the ordered collection list has a key count less than two, terminate the script. Else call Optimize-Offline passing all of the set parameters to it.
If ($ConfigParams.Count -lt 2)
{
	Write-Warning "There are not enough parameters set to optimize an image."
	Start-Sleep 3
	Exit
}
Else
{
	Optimize-Offline @ConfigParams
}
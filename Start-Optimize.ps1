Using module .\Optimize-Offline.psm1
<#
	.SYNOPSIS
		Configuration call script for the Optimize-Offline cmdlet.

	.DESCRIPTION
		Start-Optimize automatically imports the configuration JSON file (Configuration.json) into the Optimize-Offline cmdlet.

	.EXAMPLE
		.\Start-Optimize.ps1

	.NOTES
		This call script requires that the configuration JSON file (Configuration.json) is located in the Optimize-Offline module root directory.
		Ensure all content within the configuration JSON file (Configuration.json) are valid and formatted properly.
		This configuration call script requires elevated permission to execute.
#>
[CmdletBinding()]
Param ()

# Ensure we are running with administrative permissions first.
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
	Write-Warning "Elevation is required to process optimizations. Please relaunch Start-Optimize.ps1 as an administrator."
	Start-Sleep 3
	Exit
}

# If the ordered collection list variable still exists from a previous optimization, remove it.
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

# If the ordered collection list has a key count less than two, terminate the script. Else call Optimize-Offline passing all of our set parameters to it.
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
Function Stop-Optimize
{
	[CmdletBinding()]
	Param ()

	Log -Info "Discarding the Image and Terminating Process." -Failed
	Dismount-Images
	$Host.UI.RawUI.WindowTitle = $null
	$SaveDirectory = Create -Path "$($OptimizeOffline.Directory)\Optimize-Offline_$((Get-Date).ToString('yyyy-MM-ddThh.mm.ss'))" -PassThru
	@($DISMLog, "$Env:SystemRoot\Logs\DISM\dism.log") | Purge
	If ($Error.Count -gt 0) { (Get-ErrorRecord | Format-List | Out-String).Trim() | Out-File -FilePath (Get-Path -Path $LogFolder -ChildPath ErrorRecord.log) -Force }
	Get-ChildItem -Path $LogFolder -Filter *.log | Move-Item -Destination $SaveDirectory.FullName -Force
	$TempDirectory | Purge
	((Compare-Object -ReferenceObject (Get-Variable).Name -DifferenceObject $DefaultVariables).InputObject).ForEach{ Remove-Variable -Name $PSItem -ErrorAction Ignore }
	(Get-Process -Id $PID).Kill()
}
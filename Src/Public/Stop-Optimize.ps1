Function Stop-Optimize
{
	[CmdletBinding()]
	Param ()

	Set-ErrorAction SilentlyContinue
	Log -Info "Discarding the Image and Terminating Process." -Failed
	Dismount-Images
	$SaveDirectory = Create -Path "$($OptimizeOffline.Directory)\Optimize-Offline_$((Get-Date).ToString('yyyy-MM-ddThh.mm.ss'))" -PassThru
	@($DISMLog, "$Env:SystemRoot\Logs\DISM\dism.log") | Purge
	Get-ChildItem -Path $LogFolder -Filter *.log | Move-Item -Destination $SaveDirectory.FullName -Force
	$TempDirectory | Purge
	((Compare-Object -ReferenceObject (Get-Variable).Name -DifferenceObject $DefaultVariables).InputObject).ForEach{ Remove-Variable -Name $PSItem -ErrorAction Ignore }
	Set-ErrorAction -Restore
	$Error.Clear()
	(Get-Process -Id $PID).Kill()
}
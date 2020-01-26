Function Stop-Optimize
{
	[CmdletBinding()]
	Param ()

	Set-ErrorAction SilentlyContinue
	Log -Info "Discarding the Image and Terminating Process." -Failed
	Dismount-Images
	$SaveDirectory = Create -Path (GetPath -Path $OptimizeOffline.Directory -Child Optimize-Offline_$((Get-Date).ToString('yyyy-MM-ddThh.mm.ss'))) -PassThru
	@($DISMLog, (GetPath -Path $Env:SystemRoot -Child 'Logs\DISM\dism.log')) | Purge
	If ($OptimizeErrors.Count -gt 0) { Export-ErrorLog }
	Get-ChildItem -Path $LogFolder -Filter *.log | Move-Item -Destination $SaveDirectory.FullName -Force
	$TempDirectory | Purge
	Set-ErrorAction -Restore
	((Compare-Object -ReferenceObject (Get-Variable).Name -DifferenceObject $DefaultVariables).InputObject).ForEach{ Remove-Variable -Name $PSItem -ErrorAction Ignore }
	$Error.Clear()
	(Get-Process -Id $PID).Kill()
}
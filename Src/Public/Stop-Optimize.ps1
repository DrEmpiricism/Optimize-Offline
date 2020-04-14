Function Stop-Optimize
{
	[CmdletBinding()]
	Param ()

	Log $OptimizeData.TerminatingOptimizations -Failed
	Dismount-Images
	$SaveDirectory = Create -Path (GetPath -Path $OptimizeOffline.Directory -Child Optimize-Offline_$((Get-Date).ToString('yyyy-MM-ddThh.mm.ss'))) -PassThru
	@($DISMLog, (GetPath -Path $Env:SystemRoot -Child 'Logs\DISM\dism.log')) | Purge -ErrorAction Ignore
	If ($Global:Error.Count -gt 0 -or $OptimizeErrors.Count -gt 0) { Export-ErrorLog -ErrorAction Ignore }
	Get-ChildItem -Path $LogFolder -Filter *.log | Move-Item -Destination $SaveDirectory.FullName -Force
	$TempDirectory | Purge
	$Global:Error.Clear()
	((Compare-Object -ReferenceObject (Get-Variable).Name -DifferenceObject $LocalScope.Variables).InputObject).ForEach{ Remove-Variable -Name $PSItem -ErrorAction Ignore }
	(Get-Process -Id $PID).Kill()
}
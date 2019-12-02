Function Stop-Optimize
{
	[CmdletBinding()]
	Param ()

	Log -Info "Dismounting and Discarding the Image." -Failed
	Dismount-Images
	$Host.UI.RawUI.WindowTitle = $null
	$SaveDirectory = Create -Path "$($OptimizeOffline.Directory)\Optimize-Offline_$((Get-Date).ToString('yyyy-MM-ddThh.mm.ss'))" -PassThru
	@($DISMLog, "$Env:SystemRoot\Logs\DISM\dism.log") | Purge
	Get-ChildItem -Path $LogFolder -Filter *.log | Move-Item -Destination $SaveDirectory.FullName -Force
	$TempDirectory | Purge
	((Compare-Object -ReferenceObject (Get-Variable).Name -DifferenceObject $DefaultVariables).InputObject).ForEach{ Remove-Variable -Name $PSItem -ErrorAction Ignore }
	(Get-Process -Id $PID).Kill()
}
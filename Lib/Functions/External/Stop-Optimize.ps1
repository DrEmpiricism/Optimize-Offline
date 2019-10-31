Function Stop-Optimize
{
	[CmdletBinding()]
	Param ()

	$Host.UI.RawUI.WindowTitle = "Dismounting and discarding the image."
	Log -Info "Dismounting and discarding the image." -Failed
	UnmountAll
	$SaveDirectory = Create -Path "$ScriptRootPath\Optimize-Offline_$((Get-Date).ToString('yyyy-MM-ddThh.mm.ss'))" -PassThru
	If ($Error.Count -gt 0)
	{
		($Error | ForEach-Object -Process { [PSCustomObject] @{ Line = $_.InvocationInfo.ScriptLineNumber; Error = $_.Exception.Message } } | Format-Table -AutoSize -Wrap | Out-String).Trim() | Out-File -FilePath (Join-Path -Path $SaveDirectory.FullName -ChildPath ErrorRecord.log) -Force
	}
	@($DISMLog, "$Env:SystemRoot\Logs\DISM\dism.log") | Purge
	Get-ChildItem -Path $LogDirectory -Filter *.log | Move-Item -Destination $SaveDirectory.FullName -Force
	$TempDirectory | Purge
	((Compare-Object -ReferenceObject (Get-Variable).Name -DifferenceObject $DefaultVariables).InputObject).ForEach{ Remove-Variable $_ -ErrorAction SilentlyContinue }
	Return
}
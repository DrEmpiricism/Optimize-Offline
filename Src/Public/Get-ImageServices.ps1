Function Get-ImageServices {
	$ServicesStartLabels = @(
		"Boot",
		"System",
		"Automatic",
		"Manual",
		"Disabled"
	)
	$RegPath = "HKLM:\WIM_HKLM_SYSTEM\ControlSet001\Services"
	$Services = [System.Collections.ArrayList]@();
	Get-ChildItem -Path $RegPath | Where-Object{$_.ValueCount -gt 0} | ForEach-Object -Process {

		$ServiceDetails =  Get-Service -Name $PSItem.PSChildName -ErrorAction Ignore

		$FolderKeys = Get-ItemProperty -Path "$RegPath\$($PSItem.PSChildName)"

		If($null -ne $FolderKeys.Start -and $null -eq $FolderKeys.Owners -and $FolderKeys.Start -ne 4 -and $FolderKeys.Start -gt 1){
			$O = New-Object PSObject -Property @{
				name = [String]$PSItem.PSChildName
				description = $(If ($null -ne $ServiceDetails -and $null -ne $ServiceDetails.DisplayName) {$ServiceDetails.DisplayName} Else {""})
				start = $FolderKeys.Start
				startLabel = $ServicesStartLabels[$FolderKeys.Start]
			}
			[void]$Services.Add($O)
		}
	}

	return $Services
}
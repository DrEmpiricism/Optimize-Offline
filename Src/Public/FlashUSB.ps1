Function FlashUSB {

	Add-Type -AssemblyName System.Windows.Forms
		
	$FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ 
		InitialDirectory = [Environment]::GetFolderPath('Documents')
		Filter = 'All allowed types|*.iso;*.ISO'
		Multiselect = $false
		AddExtension = $true
		CheckPathExists = $true
	}

	$null = $FileBrowser.ShowDialog()

	If($FileBrowser.FileName){
		$ISOPath = Get-Item -Path $FileBrowser.FileName
	} Else {
		Write-Host "No iso file selected"
		return $false
	}

	$Results = Get-Disk |
	Where-Object BusType -eq USB

	If ($Results.Count -eq 0) {
		Write-Host "No USB drives found"
		return $false
	}
	
	$USB = $Results |
	Out-GridView -Title 'Select USB Drive to Format' -OutputMode Single
	$USB_Number = $USB.Number
	
	$USB | Clear-Disk -RemoveData -RemoveOEM -Confirm:$false -PassThru
	
	Set-Disk -PartitionStyle GPT -Number $USB_Number

	$USB = $USB | New-Partition -UseMaximumSize -AssignDriveLetter |
	Format-Volume -FileSystem FAT32

	If ($USB.Count -eq 0) {
		Write-Host "No USB drive selected"
		return $false
	}

	$Volumes = (Get-Volume).Where({$_.DriveLetter}).DriveLetter
	Mount-DiskImage -ImagePath $ISOPath
	$ISO = (Compare-Object -ReferenceObject $Volumes -DifferenceObject (Get-Volume).Where({$_.DriveLetter}).DriveLetter).InputObject

	& "$($ISO):\boot\bootsect.exe" /nt60 "$($USB.DriveLetter):"
	Copy-Item -Path "$($ISO):\*" -Destination "$($USB.DriveLetter):" -Recurse -Verbose

	Dismount-DiskImage -ImagePath $ISOPath

	Write-Host "USB is is flashed and bootable"

	return $true
}

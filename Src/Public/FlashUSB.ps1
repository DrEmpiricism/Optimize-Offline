Function FlashUSB {

	[CmdletBinding()]

	Param (
		[Parameter(
			Mandatory = $true,
			HelpMessage = 'full path of the iso file to be flashed to the usb device'
		)]
		[String]$ISOPath,
		[Parameter(
			Mandatory = $true,
			HelpMessage = 'USB device drive object'
		)]
		[PSCustomObject]$USB
	)

	If ($USB.Count -eq 0 -or $USB.BusType -ne "USB") {
		throw "Could not find USB partition"
	}

	[Void]($USB | Clear-Disk -RemoveData -RemoveOEM -Confirm:$false -PassThru)
	[Void](Set-Disk -PartitionStyle GPT -Number $USB.Number)
	$USB = $USB | New-Partition -UseMaximumSize -AssignDriveLetter |
	Format-Volume -FileSystem FAT32

	$Volumes = (Get-Volume).Where({$_.DriveLetter}).DriveLetter
	[Void](Mount-DiskImage -ImagePath $ISOPath)
	$ISOMount = (Compare-Object -ReferenceObject $Volumes -DifferenceObject (Get-Volume).Where({$_.DriveLetter}).DriveLetter).InputObject

	[Void](& "$($ISOMount):\boot\bootsect.exe" /nt60 "$($USB.DriveLetter):")
	Copy-Item -Path "$($ISOMount):\*" -Destination "$($USB.DriveLetter):" -Recurse
	[Void](Dismount-DiskImage -ImagePath $ISOPath)
}

Function Write-USB {

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
		[PSCustomObject]$USBDrive,
		[Parameter(
			Mandatory = $false,
			HelpMessage = 'ScratchDirectory'
		)]
		[String]$ScratchDirectory,
		[Parameter(
			Mandatory = $false,
			HelpMessage = 'Log path'
		)]
		[String]$LogPath
	)

	Try {
		If ($USBDrive.Count -eq 0 -or $USBDrive.BusType -ne "USB") {
			Throw "Could not find USB drive"
		}
		$ISO = (Get-Item $ISOPath)
		$ISOSize = $ISO.Length
		$FreeSizeOffset = 1024*1024*30
		If (!$ISO -or $ISOSize -eq 0) {
			Throw "Invalid iso file"
		}
		If ($USBDrive.Size -lt ($ISOSize + $FreeSizeOffset)) {
			Throw "USB disk size is smaller than ISO size"
		}
		If (($ISOSize + $FreeSizeOffset) -gt 32GB) {
			Throw "ISO size exceeds the FAT32 partition size limit 32GB"
		}
	
		[Void]($USBDrive | Clear-Disk -RemoveData -RemoveOEM -Confirm:$false -PassThru)
	
		If ($USBDrive.PartitionStyle -eq 'RAW') {
			[Void]($USBDrive | Initialize-Disk -PartitionStyle GPT)
		} Else {
			[Void]($USBDrive | Set-Disk -PartitionStyle GPT)
		}
	
		$Volumes = (Get-Volume).Where({$_.DriveLetter}).DriveLetter
		[Void](Mount-DiskImage -ImagePath $ISOPath)
		$ISOMount = (Compare-Object -ReferenceObject $Volumes -DifferenceObject (Get-Volume).Where({$_.DriveLetter}).DriveLetter).InputObject
	
		$USBVolume = $USBDrive |
		New-Partition -Size ($ISOSize+$FreeSizeOffset) -AssignDriveLetter |
		Format-Volume -FileSystem FAT32 -Force
	
		[Void](& "$($ISOMount):\boot\bootsect.exe" /NT60 "$($USBVolume.DriveLetter):")
		Copy-Item -Path "$($ISOMount):\*" -Destination "$($USBVolume.DriveLetter):" -Recurse -Exclude "install.wim" -Force
		If((Get-Item "$($ISOMount):\sources\install.wim").Length -gt 4GB) {
			[Void](Split-WindowsImage -ImagePath "$($ISOMount):\sources\install.wim" -SplitImagePath "$($USBVolume.DriveLetter):\sources\install.swm" -FileSize 4096 -ScratchDirectory $ScratchDirectory -LogPath $LogPath -LogLevel 1)
		} else {
			Copy-Item -Path "$($ISOMount):\sources\install.wim" -Destination "$($USBVolume.DriveLetter):\sources\install.wim" -Force
		}
	} Catch {
		Throw $Error[0]
	} Finally {
		If ($ISOPath) {
			[Void](Dismount-DiskImage -ImagePath $ISOPath)
		}
	}
}

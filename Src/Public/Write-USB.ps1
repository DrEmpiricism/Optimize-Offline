
Function Update_bcd
{
	param ($usbpartition)
	& bcdedit /store "$usbpartition\boot\bcd" /set '{default}' bootmenupolicy Legacy | Out-Null
	& bcdedit /store "$usbpartition\EFI\Microsoft\boot\bcd" /set '{default}' bootmenupolicy Legacy |Out-Null
	Set-ItemProperty -Path "$usbpartition\boot\bcd" -Name IsReadOnly -Value $true
	Set-ItemProperty -Path "$usbpartition\EFI\Microsoft\boot\bcd" -Name IsReadOnly -Value $true
}
Function Write-USB {

	[CmdletBinding()]

	Param (
		[Parameter(
			Mandatory = $true,
			HelpMessage = 'full path of the source files to be flashed to the usb device'
		)]
		[String]$Source,
		[Parameter(
			Mandatory = $true,
			HelpMessage = 'USB device drive object'
		)]
		[PSCustomObject]$USBDrive,
		[Parameter(
			Mandatory = $false,
			HelpMessage = 'USB label'
		)]
		[String]$Label = "Windows_Install",
		[Parameter(
			Mandatory = $false,
			HelpMessage = "If usb will support legacy bios booting scheme"
		)]
		[Switch]$Legacy = $false,
		[Parameter(
			Mandatory = $false,
			HelpMessage = "Will override the main USB partition FS type to this one"
		)]
		[ValidateSet("NTFS", "FAT32")]
		[String]$ForceFS,
		[Parameter(
			Mandatory = $false,
			HelpMessage = "Will override the main USB partition schema to this one"
		)]
		[ValidateSet("MBR", "GPT")]
		[String]$ForcePartitionSchema
	)

	Try {
		If ($USBDrive.Count -eq 0 -or $USBDrive.BusType -ne "USB") {
			Throw "Could not find USB drive"
		}
		$TotalSize = 0
		Get-ChildItem -Path $source -Recurse  | Where-Object {!$_.PSIsContainer} | ForEach-Object -Process {
			$TotalSize = $TotalSize + $_.Length
		}
		If ($USBDrive.Size -lt $TotalSize + 100MB) {
			Throw "USB disk size is smaller than ISO size"
		}
		$PartitionSchema = $(If($ForcePartitionSchema) {$ForcePartitionSchema} Else {"MBR"})
		$FileSystem = $(If ($ForceFS) {$ForceFS} Else {If($Legacy) {"FAT32"} Else {"NTFS"}})
@"
select disk $($USBDrive.DiskNumber)
clean
convert $PartitionSchema
rescan
exit
"@ | diskpart | Out-Null
	
		Stop-Service ShellHWDetection -ErrorAction SilentlyContinue | Out-Null
	
		If(!$Legacy){
			$USBUEFIVolume = $USBDrive |
			New-Partition -Size 1GB -AssignDriveLetter |
			Format-Volume -FileSystem FAT32 -NewFileSystemLabel "BOOT"
	
			Copy-Item -Path "$Source\bootmgr*" -Destination "$($USBUEFIVolume.DriveLetter):\"
			Copy-Item -Path "$Source\boot" -Destination "$($USBUEFIVolume.DriveLetter):\boot" -Recurse
			Copy-Item -Path "$Source\efi" -Destination "$($USBUEFIVolume.DriveLetter):\efi" -Recurse
			If (!(Test-Path -path "$($USBUEFIVolume.DriveLetter):\sources")) {
				New-Item "$($USBUEFIVolume.DriveLetter):\sources" -Type Directory | Out-Null
			}
			Copy-Item -Path "$Source\sources\boot.wim" -Destination "$($USBUEFIVolume.DriveLetter):\sources"
	
			Update_bcd $($USBUEFIVolume.DriveLetter+":")
		}
		$NewPartitionParams = @{
			AssignDriveLetter = $true
			ErrorAction = "Stop"
		}
		If($PartitionSchema -eq "MBR") {
			$NewPartitionParams.IsActive = $true
		}
		If ($FileSystem -eq "FAT32" -and $USBDrive.Size -gt 32GB) {
			$NewPartitionParams.Size = 32GB
		} Else {
			$NewPartitionParams.UseMaximumSize = $true
		}
		$USBVolume = $USBDrive |
		New-Partition @NewPartitionParams |
		Format-Volume -FileSystem $FileSystem -ErrorAction Stop -NewFileSystemLabel $Label

		$CopyItemParams = @{
			Path = "$Source\*"
			Destination = "$($USBVolume.DriveLetter):"
			Recurse = $true
			Force = $true
			ErrorAction = "Stop"
			Exclude = @()
		}

		If (!$Legacy) {
			$CopyItemParams.Exclude = $CopyItemParams.Exclude + "boot.wim"
		}
		
		If ($FileSystem -eq "FAT32" -and (Test-Path -Path "$Source\sources\install.wim") -and (Get-Item -Path "$Source\sources\install.wim").Length -gt 4GB) {
			[Void](New-Item -Path "$($USBVolume.DriveLetter):\sources" -Type Directory)
			[Void](Split-WindowsImage -ImagePath "$Source\sources\install.wim" -SplitImagePath "$($USBVolume.DriveLetter):\sources\install.swm" -FileSize 4090 -LogPath $DISMLog -ScratchDirectory $ScratchFolder -LogLevel 1 -ErrorAction Stop)
			$CopyItemParams.Exclude = $CopyItemParams.Exclude + "install.wim"
		}
		Copy-Item @CopyItemParams
	
		If(!$Legacy){
			Update_bcd $($USBVolume.DriveLetter+":")
		} Else {
			[Void](& "$Source\boot\bootsect.exe" /nt60 "$($USBVolume.DriveLetter):")
		}
	} Catch {
		Throw $Error[0]
	} Finally {
		Start-Service ShellHWDetection -ErrorAction SilentlyContinue | Out-Null
		If (!$Legacy -and $USBUEFIVolume) {
@"
select volume $($USBUEFIVolume.DriveLetter)
remove letter=$($USBUEFIVolume.DriveLetter)
rescan
exit
"@ | diskpart | Out-Null
		}
	}
}

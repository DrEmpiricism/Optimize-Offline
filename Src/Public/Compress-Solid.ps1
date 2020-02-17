Function Compress-Solid
{
	[CmdletBinding()]
	[OutputType([IO.FileInfo])]
	Param ()

	$ImageInfo = Import-DataFile Install -ErrorAction:$ErrorActionPreference
	$DestinationImage = '{0}\{1}' -f $ImageFolder, [IO.Path]::ChangeExtension((GetPath -Path $ImageInfo.Path -Split Leaf), '.esd')
	$RET = StartExe $DISM -Arguments ('/Export-Image /SourceImageFile:"{0}" /SourceIndex:{1} /DestinationImageFile:"{2}" /Compress:Recovery /CheckIntegrity /ScratchDir:"{3}" /LogPath:"{4}" /LogLevel:1' -f $ImageInfo.Path, $ImageInfo.Index, $DestinationImage, $ScratchFolder, $DISMLog) -ErrorAction:$ErrorActionPreference
	If ($RET -eq 0) { Get-Item -Path $DestinationImage -ErrorAction:$ErrorActionPreference }
}
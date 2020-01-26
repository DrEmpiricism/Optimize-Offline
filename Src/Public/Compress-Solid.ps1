Function Compress-Solid
{
	[CmdletBinding()]
	[OutputType([IO.FileInfo])]
	Param ()

	Begin
	{
		$ImageInfo = Import-DataFile Install -ErrorAction SilentlyContinue
		$DestinationImage = '{0}\{1}' -f $ImageFolder, [IO.Path]::ChangeExtension((GetPath -Path $ImageInfo.Path -Split Leaf), '.esd')
		$CompressionType = 'Recovery'
	}
	Process
	{
		$RET = StartExe $DISM -Arguments ('/Export-Image /SourceImageFile:"{0}" /SourceIndex:{1} /DestinationImageFile:"{2}" /Compress:{3} /CheckIntegrity /ScratchDir:"{4}" /LogPath:"{5}"' -f $ImageInfo.Path, $ImageInfo.Index, $DestinationImage, $CompressionType, $ScratchFolder, $DISMLog)
		If ($RET -eq 0) { Get-Item -Path $DestinationImage }
	}
}
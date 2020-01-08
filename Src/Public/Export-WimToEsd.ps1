Function Export-WimToEsd
{
	[CmdletBinding()]
	[OutputType([Int])]
	Param ()

	$ImageInfo = Import-DataFile Install -ErrorAction:$ErrorActionPreference
	$DestinationImage = '{0}\{1}' -f $ImageFolder, [IO.Path]::ChangeExtension((Get-Path -Path $ImageInfo.Path -Split Leaf), '.esd')
	$CompressionType = 'Recovery'
	StartExe $DISM -Arguments @('/Export-Image /SourceImageFile:"{0}" /SourceIndex:{1} /DestinationImageFile:"{2}" /Compress:{3} /ScratchDir:"{4}" /LogPath:"{5}"' -f $ImageInfo.Path, $ImageInfo.Index, $DestinationImage, $CompressionType, $ScratchFolder, $DISMLog) -ErrorAction:$ErrorActionPreference
}
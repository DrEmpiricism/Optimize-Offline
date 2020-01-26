Function Import-DataFile
{
	[CmdletBinding(DefaultParameterSetName = 'Image')]
	[OutputType([PSObject])]
	Param
	(
		[Parameter(ParameterSetName = 'Image',
			Position = 0)]
		[ValidateSet('Install', 'Boot', 'Recovery')]
		[String]$Image,
		[Parameter(ParameterSetName = 'CurrentVersion',
			Position = 0)]
		[Switch]$CurrentVersion,
		[Parameter(ParameterSetName = 'ISOMedia',
			Position = 0)]
		[Switch]$ISOMedia
	)

	Switch ($PSCmdlet.ParameterSetName)
	{
		'Image' { Import-Clixml -Path (GetPath -Path $WorkFolder -Child ($Image + 'Info.xml')) -ErrorAction:$ErrorActionPreference }
		'CurrentVersion' { Import-Clixml -Path (GetPath -Path $WorkFolder -Child CurrentVersion.xml) -ErrorAction:$ErrorActionPreference }
		'ISOMedia' { Import-Clixml -Path (GetPath -Path $WorkFolder -Child ISOMedia.xml) -ErrorAction:$ErrorActionPreference }
	}
}
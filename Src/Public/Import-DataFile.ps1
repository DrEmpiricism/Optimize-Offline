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
		'Image'
		{
			If (Test-Path -Path (GetPath -Path $WorkFolder -Child ($Image + 'Info.xml'))) { Import-Clixml -Path (GetPath -Path $WorkFolder -Child ($Image + 'Info.xml')) -ErrorAction:$ErrorActionPreference }
			Break
		}
		'CurrentVersion'
		{
			If (Test-Path -Path (GetPath -Path $WorkFolder -Child CurrentVersion.xml)) { Import-Clixml -Path (GetPath -Path $WorkFolder -Child CurrentVersion.xml) -ErrorAction:$ErrorActionPreference }
			Break
		}
		'ISOMedia'
		{
			If (Test-Path -Path (GetPath -Path $WorkFolder -Child ISOMedia.xml)) { Import-Clixml -Path (GetPath -Path $WorkFolder -Child ISOMedia.xml) -ErrorAction:$ErrorActionPreference }
			Break
		}
	}
}
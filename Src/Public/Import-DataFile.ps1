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
			If (Test-Path -Path (Get-Path -Path $WorkFolder -ChildPath ($Image + 'Info.xml'))) { Import-Clixml -Path (Get-Path -Path $WorkFolder -ChildPath ($Image + 'Info.xml')) -ErrorAction:$ErrorActionPreference }
		}
		'CurrentVersion'
		{
			If (Test-Path -Path (Get-Path -Path $WorkFolder -ChildPath CurrentVersion.xml)) { Import-Clixml -Path (Get-Path -Path $WorkFolder -ChildPath CurrentVersion.xml) -ErrorAction:$ErrorActionPreference }
		}
		'ISOMedia'
		{
			If (Test-Path -Path (Get-Path -Path $WorkFolder -ChildPath ISOMedia.xml)) { Import-Clixml -Path (Get-Path -Path $WorkFolder -ChildPath ISOMedia.xml) -ErrorAction:$ErrorActionPreference }
		}
	}
}
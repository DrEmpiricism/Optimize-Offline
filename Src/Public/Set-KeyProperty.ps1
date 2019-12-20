Function Set-KeyProperty
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [String[]]$Path,
        [Parameter(Mandatory = $true)]
        [String]$Name,
        [Parameter(Mandatory = $false)]
        $Value,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Binary', 'DWord', 'ExpandString', 'MultiString', 'QWord', 'String')]
        [String]$Type,
        [Switch]$Force
    )

    Begin
    {
        Set-ErrorAction SilentlyContinue
        Switch ($Type)
        {
            'Binary' { [Byte[]]$Value = $Value; Break }
            'DWord' { [Int32]$Value = $Value; Break }
            'ExpandString' { [String]$Value = $Value; Break }
            'MultiString' { [Array[]]$Value = $Value; Break }
            'QWord' { [Int64]$Value = $Value; Break }
            'String' { [String]$Value = $Value; Break }
        }
        $Type = [Enum]::Parse([Microsoft.Win32.RegistryValueKind], $Type, $true)
        If ((Get-PSDrive -PSProvider Registry).Name -notcontains 'HKLM') { $PSDrive = New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE -Scope Script -ErrorAction:$ErrorActionPreference }
        Push-Location -LiteralPath HKLM:
    }
    Process
    {
        ForEach ($Key In $Path)
        {
            If (Test-Path -LiteralPath $Key)
            {
                If ($Force.IsPresent) { $Key.Split(':')[1].TrimStart('\') | Grant-KeyAccess -ErrorAction:$ErrorActionPreference }
                Set-ItemProperty -LiteralPath $Key -Name $Name -Value $Value -Type $Type -Force -ErrorAction:$ErrorActionPreference
            }
            Else
            {
                If ($Force.IsPresent -and (Test-Path -LiteralPath (Split-Path -LiteralPath $Key) -PathType Container)) { (Split-Path -LiteralPath $Key).Split(':')[1].TrimStart('\') | Grant-KeyAccess -ErrorAction:$ErrorActionPreference }
                [Void](New-Item -Path $Key -ItemType Directory -Force -ErrorAction:$ErrorActionPreference | New-ItemProperty -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction:$ErrorActionPreference)
            }
        }
    }
    End
    {
        Pop-Location
        If ($PSDrive) { Remove-PSDrive -Name $PSDrive.Name -ErrorAction:$ErrorActionPreference }
        Set-ErrorAction -Restore
    }
}
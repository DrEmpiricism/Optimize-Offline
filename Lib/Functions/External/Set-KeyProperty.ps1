Function Set-KeyProperty
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string[]]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $false)]
        $Value,
        [Parameter(Mandatory = $true)]
        [ValidateSet('DWord', 'String', 'ExpandString', 'QWord', 'Binary')]
        [string]$Type
    )

    Begin
    {
        Switch ($Type)
        {
            'DWord' { [int32]$Value = $Value; Break }
            'String' { [string]$Value = $Value; Break }
            'ExpandString' { [string]$Value = $Value; Break }
            'QWord' { [int64]$Value = $Value; Break }
            'Binary' { [byte[]]$Value = $Value; Break }
        }
    }
    Process
    {
        ForEach ($Item In $Path)
        {
            If (Test-Path -LiteralPath $Item) { Set-ItemProperty -LiteralPath $Item -Name $Name -Value $Value -Type $Type -Force -ErrorAction SilentlyContinue }
            Else { [void](New-Item -Path $Item -ItemType Directory -Force -ErrorAction SilentlyContinue | New-ItemProperty -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction SilentlyContinue) }
        }
    }
}
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
        [ValidateSet('DWord', 'String', 'ExpandString', 'MultiString', 'QWord', 'Binary')]
        [String]$Type,
        [Switch]$Force
    )

    Begin
    {
        Push-Location -Path "HKLM:"
        Switch ($Type)
        {
            'DWord' { [Int32]$Value = $Value; Break }
            'String' { [String]$Value = $Value; Break }
            'ExpandString' { [String]$Value = $Value; Break }
            'MultiString' { [Array[]]$Value = $Value; Break }
            'QWord' { [Int64]$Value = $Value; Break }
            'Binary' { [Byte[]]$Value = $Value; Break }
        }
    }
    Process
    {
        ForEach ($Item In $Path)
        {
            If (Test-Path -LiteralPath $Item)
            {
                If ($Force.IsPresent) { Grant-KeyAccess -SubKey $Item.Split(':')[1].TrimStart('\') }
                Set-ItemProperty -LiteralPath $Item -Name $Name -Value $Value -Type $Type -Force -ErrorAction SilentlyContinue
            }
            Else
            {
                If (Test-Path -LiteralPath (Split-Path -LiteralPath $Item) -PathType Container) { Grant-KeyAccess -SubKey (Split-Path -LiteralPath $Item).Split(':')[1].TrimStart('\') }
                [Void](New-Item -Path $Item -ItemType Directory -Force -ErrorAction SilentlyContinue | New-ItemProperty -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction SilentlyContinue)
            }
        }
    }
    End
    {
        Pop-Location
    }
}
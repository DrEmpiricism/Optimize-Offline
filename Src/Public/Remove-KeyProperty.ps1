Function Remove-KeyProperty
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Alias('FullName', 'PSPath')]
        [String]$Path,
        [Parameter(Mandatory = $true)]
        [String]$Name
    )

    Process
    {
        Try { Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop | Remove-ItemProperty -Name $Name -Force }
        Catch [Management.Automation.PSArgumentException] { Break }
    }
}
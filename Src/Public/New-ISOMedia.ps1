Function New-ISOMedia
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Prompt', 'No-Prompt')]
        [String]$BootType
    )
    Begin {
        $ISOMedia = Import-DataFile -ISOMedia -ErrorAction:$ErrorActionPreference
        $InstallInfo = Import-DataFile Install -ErrorAction:$ErrorActionPreference
        $ISOFile = GetPath -Path $WorkFolder -Child ($($InstallInfo.Edition).Replace(' ', '') + "_$($InstallInfo.Build).iso")

        $BootFile = Switch ($BootType)
        {
            'Prompt' { 'efisys.bin'; Break }
            'No-Prompt' { 'efisys_noprompt.bin'; Break }
        }

        If ($PSVersionTable.PSVersion.Major -gt 5 -and !(Test-Path -Path (GetPath -Path $ISOMedia -Child 'boot\etfsboot.com'))) { Log "Missing the required etfsboot.com bootfile for ISO creation." -Type Error; Start-Sleep 3; Break }
        If (!(Test-Path -Path (GetPath -Path $ISOMedia -Child "efi\Microsoft\boot\$($BootFile)"))) { Log ('Missing the required {0} bootfile for ISO creation.' -f $BootFile) -Type Error; Start-Sleep 3; Break }
    }
    Process
    {
        If ($OSCDIMG -and (Test-Path -Path $OSCDIMG))
        {
            $BootData = ('2#p0,e,b"{0}"#pEF,e,b"{1}"' -f (Get-ChildItem -Path "$($ISOMedia)\boot" -Filter etfsboot.com | Select-Object -ExpandProperty FullName), (Get-ChildItem -Path "$($ISOMedia)\efi\Microsoft\boot" -Filter $BootFile | Select-Object -ExpandProperty FullName))
            $OSCDIMGArgs = @('-bootdata:{0}', '-u2', '-udfver102', '-l"{1}"', '"{2}"', '"{3}"' -f $BootData, $InstallInfo.Name, $ISOMedia, $ISOFile)
            $RET = StartExe $OSCDIMG -Arguments $OSCDIMGArgs
            If ($RET -eq 0) { $ISOFile }
        } Elseif ($(:DIR2ISO $ISOMedia $ISOFile $($BootType -eq 'Prompt') $InstallInfo.Name) -eq $true)
        {
            Return $ISOFile
        }
    }
}
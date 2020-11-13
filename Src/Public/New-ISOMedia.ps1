Function New-ISOMedia
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Prompt', 'No-Prompt')]
        [String]$BootType
    )

    Begin
    {
        $ISOMedia = Import-DataFile -ISOMedia -ErrorAction:$ErrorActionPreference
        $InstallInfo = Import-DataFile Install -ErrorAction:$ErrorActionPreference
        $BootFile = Switch ($BootType)
        {
            'Prompt' { 'efisys.bin'; Break }
            'No-Prompt' { 'efisys_noprompt.bin'; Break }
        }
        If ($PSVersionTable.PSVersion.Major -gt 5 -and !(Test-Path -Path (GetPath -Path $ISOMedia.FullName -Child 'boot\etfsboot.com'))) { Log "Missing the required etfsboot.com bootfile for ISO creation." -Type Error; Start-Sleep 3; Break }
        If (!(Test-Path -Path (GetPath -Path $ISOMedia.FullName -Child "efi\Microsoft\boot\$($BootFile)"))) { Log ('Missing the required {0} bootfile for ISO creation.' -f $BootFile) -Type Error; Start-Sleep 3; Break }
        If ($PSVersionTable.PSVersion.Major -lt 6)
        {
            $CompilerParams = New-Object -TypeName CodeDom.Compiler.CompilerParameters -Property @{ CompilerOptions = '/unsafe'; WarningLevel = 4; TreatWarningsAsErrors = $true } -ErrorAction:$ErrorActionPreference
            If (!('ISOWriter' -as [Type]))
            {
                Add-Type @'
using System;
using System.IO;
using System.Runtime.InteropServices.ComTypes;

public class ISOWriter
{
    public unsafe static void Create(string Path, object Stream, int BlockSize, int TotalBlocks)
    {
        int BytesRead = 0;
        byte[] Buffer = new byte[BlockSize];
        int* Pointer = &BytesRead;
        var OpenFile = System.IO.File.OpenWrite(Path);
        var IStream = Stream as System.Runtime.InteropServices.ComTypes.IStream;
        if (OpenFile != null)
        {
            while (TotalBlocks-- > 0)
            {
                IStream.Read(Buffer, BlockSize, (IntPtr)Pointer);
                OpenFile.Write(Buffer, 0, BytesRead);
            }
            OpenFile.Flush();
            OpenFile.Close();
        }
    }
}
'@ -CompilerParameters $CompilerParams
            }
            $FileSystem = @{ UDF = 4 }; $PlatformId = @{ EFI = 0xEF }
            ($BootStream = New-Object -ComObject ADODB.Stream -Property @{ Type = 1 } -ErrorAction:$ErrorActionPreference).Open()
            $BootStream.LoadFromFile((Get-ChildItem -Path "$($ISOMedia.FullName)\efi\Microsoft\boot" -Filter $BootFile | Select-Object -ExpandProperty FullName))
            ($BootOptions = New-Object -ComObject IMAPI2FS.BootOptions -Property @{ PlatformId = $PlatformId.EFI } -ErrorAction:$ErrorActionPreference).AssignBootImage($BootStream)
            ($FSImage = New-Object -ComObject IMAPI2FS.MsftFileSystemImage -Property @{ FileSystemsToCreate = $FileSystem.UDF; VolumeName = $InstallInfo.Name; WorkingDirectory = $WorkFolder } -ErrorAction:$ErrorActionPreference).ChooseImageDefaultsForMediaType(13)
        }
    }
    Process
    {
        If ($PSVersionTable.PSVersion.Major -lt 6)
        {
            ForEach ($Item In Get-ChildItem -Path $ISOMedia.FullName -Force)
            {
                If ($Item -isnot [IO.FileInfo] -and $Item -isnot [IO.DirectoryInfo]) { $Item = Get-Item -Path $Item -ErrorAction:$ErrorActionPreference }
                If ($Item) { $FSImage.Root.AddTree($Item.FullName, $true) }
            }
        }
    }
    End
    {
        If ($PSVersionTable.PSVersion.Major -lt 6)
        {
            $FSImage.BootImageOptions = $BootOptions
            $WriteISO = $FSImage.CreateResultImage()
            $ISOFile = New-Item -Path $WorkFolder -Name ($($InstallInfo.Edition).Replace(' ', '') + "_$($InstallInfo.Build).iso") -ItemType File -Force -ErrorAction:$ErrorActionPreference
            If ($ISOFile.Exists)
            {
                [ISOWriter]::Create($ISOFile.FullName, $WriteISO.ImageStream, $WriteISO.BlockSize, $WriteISO.TotalBlocks)
                $ISOFile.Refresh()
                If (($WriteISO.BlockSize * $WriteISO.TotalBlocks) -eq $ISOFile.Length) { $ISOFile.FullName }
            }
            While ([Runtime.Interopservices.Marshal]::ReleaseComObject($BootStream) -gt 0) { }
            While ([Runtime.Interopservices.Marshal]::ReleaseComObject($BootOptions) -gt 0) { }
            While ([Runtime.Interopservices.Marshal]::ReleaseComObject($FSImage) -gt 0) { }
            While ([Runtime.Interopservices.Marshal]::ReleaseComObject($WriteISO) -gt 0) { }
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
        }
        Else
        {
            If ($OSCDIMG -and (Test-Path -Path $OSCDIMG))
            {
                If (!(Test-Path -Path (GetPath -Path $ISOMedia.FullName -Child 'boot\etfsboot.com'))) { Log "Missing the required etfsboot.com bootfile for ISO creation." -Type Error }
                $ISOFile = GetPath -Path $WorkFolder -Child ($($InstallInfo.Edition).Replace(' ', '') + "_$($InstallInfo.Build).iso")
                $BootData = ('2#p0,e,b"{0}"#pEF,e,b"{1}"' -f (Get-ChildItem -Path "$($ISOMedia.FullName)\boot" -Filter etfsboot.com | Select-Object -ExpandProperty FullName), (Get-ChildItem -Path "$($ISOMedia.FullName)\efi\Microsoft\boot" -Filter $BootFile | Select-Object -ExpandProperty FullName))
                $OSCDIMGArgs = @('-bootdata:{0}', '-u2', '-udfver102', '-l"{1}"', '"{2}"', '"{3}"' -f $BootData, $InstallInfo.Name, $ISOMedia.FullName, $ISOFile)
                $RET = StartExe $OSCDIMG -Arguments $OSCDIMGArgs
                If ($RET -eq 0) { $ISOFile }
            }
        }
    }
}
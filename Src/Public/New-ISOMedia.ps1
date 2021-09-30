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
        If ($PSVersionTable.PSVersion.Major -gt 5 -and !(Test-Path -Path (GetPath -Path $ISOMedia.FullName -Child 'boot\etfsboot.com'))) { Log "Missing the required etfsboot.com bootfile for ISO creation." -Type Error; Start-Sleep 3; Break }
        If (!(Test-Path -Path (GetPath -Path $ISOMedia.FullName -Child "efi\Microsoft\boot\$($BootFile)"))) { Log ('Missing the required {0} bootfile for ISO creation.' -f $BootFile) -Type Error; Start-Sleep 3; Break }
        If (!('ISOWriter' -as [Type]))
        {
            Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

public class ISOWriter
{
    [DllImport ("shlwapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true, PreserveSig = false, EntryPoint = "SHCreateStreamOnFileEx")]
    internal static extern void SHCreateStreamOnFileEx (String FileName, UInt32 Mode, UInt32 Attributes, Boolean Create, IStream StreamNull, out IStream Stream);

    public static void Create (String FilePath, ref Object ImageStream, Int32 BlockSize, Int32 TotalBlocks)
    {
        IStream ResultStream = (IStream) ImageStream, ImageFile;
        SHCreateStreamOnFileEx (FilePath, 0x1001, 0x80, true, null, out ImageFile);
        Int32 Data = TotalBlocks > 1024 ? 1024 : 1;
        Int32 Pointer = TotalBlocks % Data;
        Int32 SizeBytes = BlockSize * Data;
        Int32 Buffer = (TotalBlocks - Pointer) / Data;
        if (Pointer > 0)
            ResultStream.CopyTo (ImageFile, Pointer * SizeBytes, IntPtr.Zero, IntPtr.Zero);
        while (Buffer-- > 0)
        {
            ResultStream.CopyTo (ImageFile, SizeBytes, IntPtr.Zero, IntPtr.Zero);
        }
        ImageFile.Commit (0);
    }
}
'@
        }
        $BootOptionsDetail = @(
            @{
                File = (Get-ChildItem -Path "$($ISOMedia.FullName)\boot\etfsboot.com" | Select-Object -ExpandProperty FullName)
                PlatformId = 0
            },
            @{
                File = (Get-ChildItem -Path "$($ISOMedia.FullName)\efi\Microsoft\boot" -Filter $BootFile | Select-Object -ExpandProperty FullName)
                PlatformId = 0xEF
            }
        )
        $BootOptions = @()
        Foreach($BootOptionDetail in $BootOptionsDetail)
        {
            ($BootStream = New-Object -ComObject ADODB.Stream -Property @{ Type = 1 } -ErrorAction:$ErrorActionPreference).Open()
            $BootStream.LoadFromFile($BootOptionDetail.File)
            $BootOption = New-Object -ComObject IMAPI2FS.BootOptions -Property @{ PlatformId = $BootOptionDetail.PlatformId; Manufacturer = 'Microsoft'; Emulation = 0 } -ErrorAction:$ErrorActionPreference
            $BootOption.AssignBootImage($BootStream.psobject.BaseObject)
            $BootOptions += $BootOption.psobject.BaseObject
        }
        $FileSystem = @{ UDF = 4 };
        $FSImage = New-Object -ComObject IMAPI2FS.MsftFileSystemImage -Property @{ FileSystemsToCreate = $FileSystem.UDF; UDFRevision = 0x102; FreeMediaBlocks = 0; VolumeName = $InstallInfo.Name; WorkingDirectory = $WorkFolder } -ErrorAction:$ErrorActionPreference
    }
    Process
    {
        $FSImage.Root.AddTree($ISOMedia.FullName, $false)
    }
    End
    {
        $FSImage.BootImageOptionsArray = $BootOptions
        $WriteISO = $FSImage.CreateResultImage()
        $ISOFile = New-Item -Path $WorkFolder -Name ($($InstallInfo.Edition).Replace(' ', '') + "_$($InstallInfo.Build).iso") -ItemType File -Force -ErrorAction:$ErrorActionPreference
        If ($ISOFile.Exists)
        {
            [ISOWriter]::Create($ISOFile.FullName, [ref]$WriteISO.ImageStream, $WriteISO.BlockSize, $WriteISO.TotalBlocks)
            $ISOFile.Refresh()
            If (($WriteISO.BlockSize * $WriteISO.TotalBlocks) -eq $ISOFile.Length) { $ISOFile.FullName }
        }
        While ([Runtime.Interopservices.Marshal]::ReleaseComObject($BootStream) -gt 0) { }
        Foreach($BootOption in $BootOptions){
            While ([Runtime.Interopservices.Marshal]::ReleaseComObject($BootOption) -gt 0) { }
        }
        While ([Runtime.Interopservices.Marshal]::ReleaseComObject($FSImage) -gt 0) { }
        While ([Runtime.Interopservices.Marshal]::ReleaseComObject($WriteISO) -gt 0) { }
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
    }
}

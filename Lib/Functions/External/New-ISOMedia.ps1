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
        $CompilerParams = New-Object -TypeName System.CodeDom.Compiler.CompilerParameters -Property @{
            CompilerOptions       = '/unsafe'
            WarningLevel          = 4
            TreatWarningsAsErrors = $true
        }
        If (!('ISOWriter' -as [Type]))
        {
            Add-Type -CompilerParameters $CompilerParams -TypeDefinition @'
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
'@
        }
        Switch ($BootType)
        {
            'Prompt' { $BootFile = Get-Item -LiteralPath "$($ISOMedia.FullName)\efi\Microsoft\boot\efisys.bin" }
            'No-Prompt' { $BootFile = Get-Item -LiteralPath "$($ISOMedia.FullName)\efi\Microsoft\boot\efisys_noprompt.bin" }
        }
        $FileSystem = @{ UDF = 4 }; $PlatformId = @{ EFI = 0xEF }
        ($BootStream = New-Object -ComObject ADODB.Stream -Property @{ Type = 1 }).Open()
        $BootStream.LoadFromFile($BootFile.FullName)
        ($BootOptions = New-Object -ComObject IMAPI2FS.BootOptions -Property @{ PlatformId = $PlatformId.EFI }).AssignBootImage($BootStream)
        ($FSImage = New-Object -ComObject IMAPI2FS.MsftFileSystemImage -Property @{ FileSystemsToCreate = $FileSystem.UDF; VolumeName = $($InstallWimInfo.Name); WorkingDirectory = $WorkDirectory }).ChooseImageDefaultsForMediaType(13)
    }
    Process
    {
        ForEach ($Item In Get-ChildItem -Path $ISOMedia.FullName -Force)
        {
            If ($Item -isnot [IO.FileInfo] -and $Item -isnot [IO.DirectoryInfo]) { $Item = Get-Item -LiteralPath $Item -Force }
            If ($Item) { $FSImage.Root.AddTree($Item.FullName, $true) }
        }
    }
    End
    {
        $FSImage.BootImageOptions = $BootOptions
        $WriteISO = $FSImage.CreateResultImage()
        $ISOFile = New-Item -Path $WorkDirectory -Name ($($InstallInfo.Edition).Replace(' ', '') + "_$($InstallInfo.Build).iso") -ItemType File -Force
        [ISOWriter]::Create($ISOFile.FullName, $WriteISO.ImageStream, $WriteISO.BlockSize, $WriteISO.TotalBlocks)
        If ([Math]::Round((Get-ChildItem -Path $ISOFile.FullName -File).Length / 1GB).ToString() -gt 0) { [PSCustomObject]@{ Path = $ISOFile.FullName } } Else { [PSCustomObject]@{ Path = $null } }
        While ([System.Runtime.Interopservices.Marshal]::ReleaseComObject($WriteISO) -gt 0) { }
        While ([System.Runtime.Interopservices.Marshal]::ReleaseComObject($BootOptions) -gt 0) { }
        While ([System.Runtime.Interopservices.Marshal]::ReleaseComObject($BootStream) -gt 0) { }
        While ([System.Runtime.Interopservices.Marshal]::ReleaseComObject($FSImage) -gt 0) { }
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}
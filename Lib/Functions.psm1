<#
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2018 v5.5.150
	 Created on:   	7/22/2019 9:02 PM
	 Created by:   	BenTheGreat
	 Filename:     	Functions.psm1
	-------------------------------------------------------------------------
	 Module Name: Functions
	===========================================================================
#>

#region Helper Functions
Function Import-Config
{
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 0)]
        [ValidatePattern('\.ini$')]
        [IO.FileInfo]$Path
    )

    Begin
    {
        $ConfigFile = Get-Content -Path $Path.FullName | Where-Object { $_ -notmatch "^(\s+)?;|^\s*$" }
        $ConfigObj = New-Object -TypeName PSObject -Property @{ }
        $ConfigParams = [Ordered]@{ }
    }
    Process
    {
        ForEach ($Line In $ConfigFile)
        {
            If ($Line -match "^\[.*\]$" -and $ConfigParams.Count -gt 0)
            {
                $ConfigObj | Add-Member -MemberType Noteproperty -Name $Section -Value $([PSCustomObject]$ConfigParams) -Force
                $ConfigParams = [Ordered]@{ }
                $Section = $Line -replace '\[|\]', ''
            }
            ElseIf ($Line -match "^\[.*\]$")
            {
                $Section = $Line -replace '\[|\]', ''
            }
            ElseIf ($Line -match '=')
            {
                $Data = $Line.Split('=').Trim()
                $ConfigParams.Add($Data[0], $Data[1])
            }
        }
        $ConfigObj | Add-Member -MemberType Noteproperty -Name $Section -Value $([PSCustomObject]$ConfigParams) -Force
        $ConfigObj
    }
}

Function Out-Log
{
    [CmdletBinding(DefaultParameterSetName = 'Info')]
    Param
    (
        [Parameter(ParameterSetName = 'Info')]
        [string]$Info,
        [Parameter(ParameterSetName = 'Error')]
        [string]$Error,
        [Parameter(ParameterSetName = 'Error',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    Begin
    {
        $Timestamp = (Get-Date -Format 's')
        $LogMutex = New-Object System.Threading.Mutex($false, "SyncLogMutex")
        [void]$LogMutex.WaitOne()
    }
    Process
    {
        Switch ($PSBoundParameters.Keys)
        {
            'Info'
            {
                Add-Content -Path $ScriptLog -Value "$Timestamp [INFO]: $Info" -Encoding UTF8 -Force -ErrorAction SilentlyContinue
                Write-Host $Info -ForegroundColor Cyan
            }
            'Error'
            {
                Add-Content -Path $ScriptLog -Value "$Timestamp [ERROR]: $Error" -Encoding UTF8 -Force -ErrorAction SilentlyContinue
                Write-Host $Error -ForegroundColor Red
                If ($PSBoundParameters.ContainsKey('ErrorRecord'))
                {
                    $ExceptionMessage = '{0} ({1}: {2}:{3} char:{4})' -f $ErrorRecord.Exception.Message,
                    $ErrorRecord.FullyQualifiedErrorId,
                    $ErrorRecord.InvocationInfo.ScriptName,
                    $ErrorRecord.InvocationInfo.ScriptLineNumber,
                    $ErrorRecord.InvocationInfo.OffsetInLine
                    Add-Content -Path $ScriptLog -Value "$Timestamp [ERROR]: $ExceptionMessage" -Encoding UTF8 -Force -ErrorAction SilentlyContinue
                    Write-Host $ExceptionMessage -ForegroundColor Red
                }
            }
        }
    }
    End
    {
        [void]$LogMutex.ReleaseMutex()
    }
}

Function Close-Process
{
    [CmdletBinding()]
    Param
    (
        [Int32]$Process = $PID
    )

    Get-Process | Where-Object { $_.Name -eq 'cmd' -or $_.Name -eq 'powershell' } | Stop-Process -Force -Confirm:$false -ErrorAction Ignore
    Get-Process -Id $Process -ErrorAction Ignore | Stop-Process -Force -Confirm:$false -ErrorAction Ignore
}

Function Stop-Optimize
{
    [CmdletBinding()]
    Param ()

    Begin
    {
        $EAP = $ErrorActionPreference
        $ErrorActionPreference = 'Ignore'
    }
    Process
    {
        $Host.UI.RawUI.WindowTitle = "Dismounting and discarding the image."
        Out-Log -Info "Dismounting and discarding the image."
        If (Get-OfflineHives -Process Test) { Get-OfflineHives -Process Unload }
        $QueryHives = Invoke-Expression -Command ('REG QUERY HKLM | FINDSTR Optimize-Offline')
        If ($QueryHives) { $QueryHives | ForEach-Object { Start-Process -FilePath REG -ArgumentList ('UNLOAD {0}' -f $($_)) -WindowStyle Hidden -Wait } }
        [void](Dismount-WindowsImage -Path $MountFolder -Discard)
        [void](Clear-WindowsCorruptMountPoint)
        Add-Content -Path $ScriptLog -Value ""
        Add-Content -Path $ScriptLog -Value "***************************************************************************************************"
        Add-Content -Path $ScriptLog -Value "Optimizations failed on [$(Get-Date -UFormat "%m/%d/%Y at %r")]"
        Add-Content -Path $ScriptLog -Value "***************************************************************************************************"
        If ($Error.Count -gt 0) { $Error.ToArray() | Out-File -FilePath (Join-Path -Path $WorkFolder -ChildPath ErrorRecord.log) -Force }
        Remove-Container -Path $DISMLog
        Remove-Container -Path "$Env:SystemRoot\Logs\DISM\dism.log"
        $SaveFolder = New-OfflineDirectory -Directory Save
        Get-ChildItem -Path $WorkFolder -Include *.txt, *.log -Recurse | Move-Item -Destination $SaveFolder -Force
        Get-ChildItem -Path (Split-Path -Path $PSScriptRoot) -Filter "OptimizeOfflineTemp_*" -Directory | Remove-Container
        Exit
    }
    End
    {
        $ErrorActionPreference = $EAP
    }
}

Function New-OfflineDirectory
{
    [CmdletBinding()]
    [OutputType([IO.DirectoryInfo])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Scratch', 'Image', 'Work', 'InstallMount', 'BootMount', 'RecoveryMount', 'Save')]
        [ValidateNotNullOrEmpty()]
        [string]$Directory
    )

    Switch ($Directory)
    {
        'Scratch'
        {
            $ScratchDirectory = [IO.Directory]::CreateDirectory((Join-Path -Path $ParentDirectory -ChildPath 'ScratchOffline'))
            $ScratchDirectory = Get-Item -LiteralPath (Join-Path -Path $ParentDirectory -ChildPath $ScratchDirectory) -Force -ErrorAction SilentlyContinue
            $ScratchDirectory.FullName; Break
        }
        'Image'
        {
            $ImageDirectory = [IO.Directory]::CreateDirectory((Join-Path -Path $ParentDirectory -ChildPath 'ImageOffline'))
            $ImageDirectory = Get-Item -LiteralPath (Join-Path -Path $ParentDirectory -ChildPath $ImageDirectory) -Force -ErrorAction SilentlyContinue
            $ImageDirectory.FullName; Break
        }
        'Work'
        {
            $WorkDirectory = [IO.Directory]::CreateDirectory((Join-Path -Path $ParentDirectory -ChildPath 'WorkOffline'))
            $WorkDirectory = Get-Item -LiteralPath (Join-Path -Path $ParentDirectory -ChildPath $WorkDirectory) -Force -ErrorAction SilentlyContinue
            $WorkDirectory.FullName; Break
        }
        'InstallMount'
        {
            $InstallMountDirectory = [IO.Directory]::CreateDirectory((Join-Path -Path $ParentDirectory -ChildPath 'MountInstallOffline'))
            $InstallMountDirectory = Get-Item -LiteralPath (Join-Path -Path $ParentDirectory -ChildPath $InstallMountDirectory) -Force -ErrorAction SilentlyContinue
            $InstallMountDirectory.FullName; Break
        }
        'BootMount'
        {
            $BootMountDirectory = [IO.Directory]::CreateDirectory((Join-Path -Path $ParentDirectory -ChildPath 'MountBootOffline'))
            $BootMountDirectory = Get-Item -LiteralPath (Join-Path -Path $ParentDirectory -ChildPath $BootMountDirectory) -Force -ErrorAction SilentlyContinue
            $BootMountDirectory.FullName; Break
        }
        'RecoveryMount'
        {
            $RecoveryMountDirectory = [IO.Directory]::CreateDirectory((Join-Path -Path $ParentDirectory -ChildPath 'MountRecoveryOffline'))
            $RecoveryMountDirectory = Get-Item -LiteralPath (Join-Path -Path $ParentDirectory -ChildPath $RecoveryMountDirectory) -Force -ErrorAction SilentlyContinue
            $RecoveryMountDirectory.FullName; Break
        }
        'Save'
        {
            $SaveDirectory = [IO.Directory]::CreateDirectory((Join-Path -Path (Split-Path -Path $PSScriptRoot) -ChildPath Optimize-Offline"_[$((Get-Date).ToString('MM.dd.yy hh.mm.ss'))]"))
            $SaveDirectory = Get-Item -LiteralPath (Join-Path -Path (Split-Path -Path $PSScriptRoot) -ChildPath $SaveDirectory) -Force -ErrorAction SilentlyContinue
            $SaveDirectory.FullName; Break
        }
    }
}

Function Get-WimInfo
{
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter(Mandatory = $true,
            Position = 0)]
        [IO.FileInfo]$WimFile,
        [Parameter(Mandatory = $false)]
        [Int]$Index = 1
    )

    Begin
    {
        $EAP = $ErrorActionPreference
        $ErrorActionPreference = 'Stop'
        $WimImage = (Get-WindowsImage -ImagePath $WimFile.FullName -Index $Index)
    }
    Process
    {
        $WimObject = New-Object -TypeName PSObject -Property @{
            Name             = $($WimImage.ImageName)
            Description      = $($WimImage.ImageDescription)
            Size             = [Math]::Round($WimImage.ImageSize / 1GB).ToString() + " GB"
            Edition          = $($WimImage.EditionID)
            Version          = $($WimImage.Version)
            Build            = $($WimImage.Build).ToString()
            SPBuild          = $($WimImage.SPBuild).ToString()
            SPLevel          = $($WimImage.SPLevel).ToString()
            InstallationType = $($WimImage.InstallationType)
            DirectoryCount   = $($WimImage.DirectoryCount)
            FileCount        = $($WimImage.FileCount)
            Created          = $($WimImage.CreatedTime)
            Modified         = $($WimImage.ModifiedTime)
            Language         = $($WimImage.Languages)
        }
        If ($WimImage.Architecture -eq 9) { $WimObject | Add-Member -MemberType NoteProperty -Name Architecture -Value $($WimImage.Architecture -replace '9', 'amd64') }
        ElseIf ($WimImage.Architecture -eq 0) { $WimObject | Add-Member -MemberType NoteProperty -Name Architecture -Value $($WimImage.Architecture -replace '0', 'x86') }
        $WimObject
    }
    End
    {
        $ErrorActionPreference = $EAP
    }
}


Function Get-OfflineHives
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Load', 'Unload', 'Test')]
        [string]$Process
    )

    Switch ($Process)
    {
        'Load'
        {
            @(('HKLM\WIM_HKLM_SOFTWARE "{0}"' -f "$($MountFolder)\Windows\System32\config\software"), ('HKLM\WIM_HKLM_SYSTEM "{0}"' -f "$($MountFolder)\Windows\System32\config\system"), ('HKLM\WIM_HKCU "{0}"' -f "$($MountFolder)\Users\Default\NTUSER.DAT"), ('HKLM\WIM_HKU_DEFAULT "{0}"' -f "$($MountFolder)\Windows\System32\config\default")) | ForEach-Object { Start-Process -FilePath REG -ArgumentList ("LOAD $($_)") -WindowStyle Hidden -Wait }; Break
        }
        'Unload'
        {
            [System.GC]::Collect()
            @('HKLM\WIM_HKLM_SOFTWARE', 'HKLM\WIM_HKLM_SYSTEM', 'HKLM\WIM_HKCU', 'HKLM\WIM_HKU_DEFAULT') | ForEach-Object { Start-Process -FilePath REG -ArgumentList ('UNLOAD {0}' -f $($_)) -WindowStyle Hidden -Wait }; Break
        }
        'Test'
        {
            @('HKLM:\WIM_HKLM_SOFTWARE', 'HKLM:\WIM_HKLM_SYSTEM', 'HKLM:\WIM_HKCU', 'HKLM\WIM_HKU_DEFAULT') | ForEach-Object { If (Test-Path -Path $($_)) { $true } }; Break
        }
    }
}

Function New-Container
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Path
    )

    Process
    {
        ForEach ($Item In $Path)
        {
            If (!(Test-Path -LiteralPath $Item))
            {
                [void](New-Item -Path $Item -ItemType Directory -Force -ErrorAction SilentlyContinue)
            }
        }
    }
}

Function Remove-Container
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Path
    )

    Process
    {
        ForEach ($Item In $Path)
        {
            If (Test-Path -LiteralPath $Item)
            {
                Remove-Item -LiteralPath $Item -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

Function Set-KeyProperty
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Path,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        [Parameter(Mandatory = $false)]
        $Value,
        [Parameter(Mandatory = $true)]
        [ValidateSet('DWord', 'String', 'ExpandString', 'QWord', 'Binary')]
        [ValidateNotNullOrEmpty()]
        [string]$Type
    )

    Begin
    {
        Switch ($Type)
        {
            'DWord' { [int32]$Value = $Value }
            'String' { [string]$Value = $Value }
            'ExpandString' { [string]$Value = $Value }
            'QWord' { [int64]$Value = $Value }
            'Binary' { [byte[]]$Value = $Value }
        }
    }
    Process
    {
        ForEach ($Item In $Path)
        {
            If (Test-Path -LiteralPath $Item)
            {
                Set-ItemProperty -LiteralPath $Item -Name $Name -Value $Value -Type $Type -Force -ErrorAction SilentlyContinue
            }
            Else
            {
                [void](New-Item -Path $Item -ItemType Directory -Force -ErrorAction SilentlyContinue)
                [void](New-ItemProperty -LiteralPath $Item -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction SilentlyContinue)
            }
        }
    }
}

Function Get-RegistryTemplates
{
    [CmdletBinding()]
    Param ()

    Begin
    {
        $RegistryTemplates = @()
        $RegistryTemplates = Get-ChildItem -Path "$AdditionalPath\RegistryTemplates" -Filter *.reg -Recurse | Select-Object -Property Name, BaseName, Extension, Directory, FullName
    }
    Process
    {
        ForEach ($RegistryTemplate In $RegistryTemplates)
        {
            $REGContent = Get-Content -Path $RegistryTemplate.FullName
            $REGContent = $REGContent -replace 'HKEY_LOCAL_MACHINE\\SOFTWARE', 'HKEY_LOCAL_MACHINE\WIM_HKLM_SOFTWARE'
            $REGContent = $REGContent -replace 'HKEY_LOCAL_MACHINE\\SYSTEM', 'HKEY_LOCAL_MACHINE\WIM_HKLM_SYSTEM'
            $REGContent = $REGContent -replace 'HKEY_CLASSES_ROOT', 'HKEY_LOCAL_MACHINE\WIM_HKLM_SOFTWARE\Classes'
            $REGContent = $REGContent -replace 'HKEY_CURRENT_USER', 'HKEY_LOCAL_MACHINE\WIM_HKCU'
            $REGContent = $REGContent -replace 'HKEY_USERS\\.DEFAULT', 'HKEY_LOCAL_MACHINE\WIM_HKU_DEFAULT'
            $REGContent | Set-Content -Path "$($RegistryTemplate.FullName.Replace('.reg', '_Offline.reg'))" -Encoding Unicode -Force
        }
    }
    End
    {
        Remove-Variable RegistryTemplates
    }
}

Function Set-RegistryTemplates
{
    [CmdletBinding()]
    Param ()

    Begin
    {
        $RegistryTemplates = @()
        $RegistryTemplates = Get-ChildItem -Path "$AdditionalPath\RegistryTemplates" -Filter *_Offline.reg -Recurse | Select-Object -Property Name, BaseName, Extension, Directory, FullName
        $RegLog = Join-Path -Path $WorkFolder -ChildPath Registry-Optimizations.log
    }
    Process
    {
        Get-OfflineHives -Process Load
        ForEach ($RegistryTemplate In $RegistryTemplates)
        {
            Write-Output ('Importing Registry Template: "{0}"' -f $($RegistryTemplate.BaseName.Replace('_Offline', $null))) >> $RegLog
            $RunProcess = Start-Process -FilePath REGEDIT -ArgumentList ('/S "{0}"' -f $RegistryTemplate.FullName) -WindowStyle Hidden -Wait -PassThru
            If ($RunProcess.ExitCode -ne 0) { Out-Log -Error ('Failed to Import Registry Template: "{0}"' -f $($RegistryTemplate.BaseName.Replace('_Offline', $null))) }
            Remove-Item -Path $RegistryTemplate.FullName -Force -ErrorAction SilentlyContinue
        }
        Get-OfflineHives -Process Unload
    }
    End
    {
        Remove-Variable RegistryTemplates
    }
}

Function New-ISOMedia
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            Position = 0)]
        [string]$ISOMedia,
        [Parameter(Mandatory = $true)]
        [string]$ISOLabel,
        [Parameter(Mandatory = $true)]
        [string]$ISOPath
    )

    Begin
    {
        $CompilerParams = New-Object -TypeName System.CodeDom.Compiler.CompilerParameters -Property @{
            CompilerOptions       = '/unsafe'
            WarningLevel          = 4
            TreatWarningsAsErrors = $true
        }
        If (!('ComBuilder' -as [Type]))
        {
            Add-Type -CompilerParameters $CompilerParams -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices.ComTypes;
namespace ComBuilder {
    public class ISOWriter {
        public unsafe static void Create (string Path, object Stream, int BlockSize, int TotalBlocks) {
            int BytesRead = 0;
            byte[] Buffer = new byte[BlockSize];
            int * Pointer = & BytesRead;
            var OpenFile = System.IO.File.OpenWrite (Path);
            var IStream = Stream as System.Runtime.InteropServices.ComTypes.IStream;
            if (OpenFile != null) {
                while (TotalBlocks-- > 0) {
                    IStream.Read (Buffer, BlockSize, (IntPtr) Pointer);
                    OpenFile.Write (Buffer, 0, BytesRead);
                }
                OpenFile.Flush ();
                OpenFile.Close ();
            }
        }
    }
}
'@
        }
        $EAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'
        $BootFile = Get-Item -Path "$($ISOMedia)\efi\Microsoft\boot\efisys.bin" -Force
        [void](New-Item -Path $ISOPath -ItemType File -Force)
        $FileSystem = @{ UDF = 4 }
        $PlatformID = @{ EFI = 0xEF }
        $Emulation = @{ None = 0 }
    }
    Process
    {
        $BootStream = New-Object -ComObject ADODB.Stream
        $BootOptions = New-Object -ComObject IMAPI2FS.BootOptions
        $FSImage = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
        $FSImage.FileSystemsToCreate = $FileSystem.UDF
        $BootStream.Open()
        $BootStream.Type = 1
        $BootStream.LoadFromFile($BootFile.FullName)
        $BootOptions.AssignBootImage($BootStream)
        $BootOptions.PlatformId = $PlatformID.EFI
        $BootOptions.Emulation = $Emulation.None
        $FSImage.VolumeName = $ISOLabel
        $FSImage.ChooseImageDefaultsForMediaType(8)
        $FSImage.BootImageOptions = $BootOptions
        ForEach ($Item In Get-ChildItem -Path $ISOMedia -Force)
        {
            If ($Item -isnot [IO.FileInfo] -and $Item -isnot [IO.DirectoryInfo]) { $Item = Get-Item -LiteralPath $Item -Force }
            If ($Item) { $FSImage.Root.AddTree($Item.FullName, $true) }
        }
        $WriteISO = $FSImage.CreateResultImage()
        [ComBuilder.ISOWriter]::Create($ISOPath, $WriteISO.ImageStream, $WriteISO.BlockSize, $WriteISO.TotalBlocks)
        If (Test-Path -Path $ISOPath) { [PSCustomObject]@{ Path = $ISOPath }
        }
        While ([System.Runtime.Interopservices.Marshal]::ReleaseComObject($WriteISO) -gt 0) { }
        While ([System.Runtime.Interopservices.Marshal]::ReleaseComObject($BootOptions) -gt 0) { }
        While ([System.Runtime.Interopservices.Marshal]::ReleaseComObject($BootStream) -gt 0) { }
        While ([System.Runtime.Interopservices.Marshal]::ReleaseComObject($FSImage) -gt 0) { }
    }
    End
    {
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        $ErrorActionPreference = $EAP
    }
}

Function Grant-ProcessPrivilege
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true)]
        [string]$Privilege,
        [Parameter(Mandatory = $false)]
        [int]$Process = $PID,
        [switch]$Disable
    )

    Begin
    {
        Add-Type @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public class AccessToken {
    [DllImport ("advapi32.dll", SetLastError = true)]
    static extern bool LookupPrivilegeValue (
        string host,
        string name,
        ref long luid
    );
    [DllImport ("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    static extern bool AdjustTokenPrivileges (
        IntPtr token,
        bool disall,
        ref TOKEN_PRIVILEGES newst,
        int len,
        IntPtr prev,
        IntPtr relen
    );
    [DllImport ("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    static extern bool OpenProcessToken (
        IntPtr curProcess,
        int acc,
        ref IntPtr processToken
    );
    [DllImport ("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle (
        IntPtr handle
    );
    [StructLayout (LayoutKind.Sequential, Pack = 1)]
    struct TOKEN_PRIVILEGES {
        public int Count;
        public long Luid;
        public int Attr;
    }
    internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
    internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
    internal const int TOKEN_QUERY = 0x00000008;
    internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
    public static void AdjustPrivilege (IntPtr curProcess, string privilege, bool enable) {
        var processToken = IntPtr.Zero;
        if (!OpenProcessToken (curProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref processToken)) {
            throw new Win32Exception ();
        }
        try {
            var privileges = new TOKEN_PRIVILEGES {
                Count = 1,
                Luid = 0,
                Attr = enable ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_DISABLED,
            };
            if (!LookupPrivilegeValue (
                    null,
                    privilege,
                    ref privileges.Luid)) {
                throw new Win32Exception ();
            }
            if (!AdjustTokenPrivileges (
                    processToken,
                    false,
                    ref privileges,
                    0,
                    IntPtr.Zero,
                    IntPtr.Zero)) {
                throw new Win32Exception ();
            }
        } finally {
            CloseHandle (
                processToken
            );
        }
    }
}
'@
        $CurrentProcess = Get-Process -Id $Process
    }
    Process
    {
        [AccessToken]::AdjustPrivilege($CurrentProcess.Handle, $Privilege, !$Disable)
    }
    End
    {
        $CurrentProcess.Close()
    }
}

Function Grant-FileOwnership
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 0)]
        [string[]]$Path
    )

    Begin
    {
        $EAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'
        "SeTakeOwnershipPrivilege" | Grant-ProcessPrivilege
        "SeBackupPrivilege" | Grant-ProcessPrivilege
        "SeRestorePrivilege" | Grant-ProcessPrivilege
    }
    Process
    {
        ForEach ($Item In $Path)
        {
            $Admin = ((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([System.Security.Principal.NTAccount]))
            $Rights = [System.Security.AccessControl.FileSystemRights]::FullControl
            $Inheritance = [System.Security.AccessControl.InheritanceFlags]::None
            $Propagation = [System.Security.AccessControl.PropagationFlags]::None
            $Type = [System.Security.AccessControl.AccessControlType]::Allow
            $ACL = Get-Acl -Path $Item
            $ACL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($Admin, $Rights, $Inheritance, $Propagation, $Type)))
            $ACL | Set-Acl -Path $Item
        }
    }
    End
    {
        "SeTakeOwnershipPrivilege" | Grant-ProcessPrivilege -Disable
        "SeBackupPrivilege" | Grant-ProcessPrivilege -Disable
        "SeRestorePrivilege" | Grant-ProcessPrivilege -Disable
        $ErrorActionPreference = $EAP
    }
}

Function Grant-FolderOwnership
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 0)]
        [string[]]$Path
    )

    Begin
    {
        $EAP = $ErrorActionPreference
        $ErrorActionPreference = 'SilentlyContinue'
    }
    Process
    {
        ForEach ($Item In $Path)
        {
            Grant-FileOwnership -Path $Item
            ForEach ($Object In Get-ChildItem $Item -Recurse -Force)
            {
                If (Test-Path $Object.FullName -PathType Container)
                {
                    Grant-FolderOwnership -Path $($Object.FullName)
                }
                Else
                {
                    Grant-FileOwnership -Path $($Object.FullName)
                }
            }
        }
    }
    End
    {
        $ErrorActionPreference = $EAP
    }
}
#endregion Helper Functions

Export-ModuleMember -Function Import-Config,
					Out-Log,
					Close-Process,
					Stop-Optimize,
					New-OfflineDirectory,
					Get-WimInfo,
					Get-OfflineHives,
					New-Container,
					Remove-Container,
					Set-KeyProperty,
					Get-RegistryTemplates,
					Set-RegistryTemplates,
					New-ISOMedia,
					Grant-ProcessPrivilege,
					Grant-FileOwnership,
					Grant-FolderOwnership
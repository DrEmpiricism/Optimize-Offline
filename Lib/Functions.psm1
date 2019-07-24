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

Function Stop-Optimize
{
    [CmdletBinding()]
    Param ()

    $Host.UI.RawUI.WindowTitle = "Dismounting and discarding the image."
    Out-Log -Info "Dismounting and discarding the image."
    If (Get-OfflineHives -Process Test) { Get-OfflineHives -Process Unload }
    $QueryHives = Invoke-Expression -Command ('REG QUERY HKLM | FINDSTR Optimize-Offline') -ErrorAction SilentlyContinue
    If ($QueryHives) { $QueryHives | ForEach-Object { Start-Process -FilePath REG -ArgumentList ('UNLOAD {0}' -f $($_)) -WindowStyle Hidden -Wait } }
    Start-Sleep 5
    [void](Dismount-WindowsImage -Path $MountFolder -Discard -ErrorAction SilentlyContinue)
    Add-Content -Path $ScriptLog -Value ""
    Add-Content -Path $ScriptLog -Value "***************************************************************************************************"
    Add-Content -Path $ScriptLog -Value "Optimizations failed at [$(Get-Date -UFormat "%m/%d/%Y %r")]"
    Add-Content -Path $ScriptLog -Value "***************************************************************************************************"
    $SaveFolder = New-OfflineDirectory -Directory Save
    If ($Error.Count -gt 0) { $Error.ToArray() | Out-File -FilePath (Join-Path -Path $WorkFolder -ChildPath ErrorRecord.log) -Force -ErrorAction SilentlyContinue }
    Remove-Container -Path $DISMLog
    Remove-Container -Path "$Env:SystemRoot\Logs\DISM\dism.log"
    [void](Get-ChildItem -Path $WorkFolder -Include *.txt, *.log -Recurse -ErrorAction SilentlyContinue | Compress-Archive -DestinationPath "$SaveFolder\OptimizeLogs.zip" -CompressionLevel Fastest -ErrorAction SilentlyContinue)
    Get-ChildItem -Path (Split-Path -Path $PSScriptRoot) -Filter "OptimizeOfflineTemp_*" -Directory -ErrorAction SilentlyContinue | Remove-Container
    [void](Clear-WindowsCorruptMountPoint); Start-Sleep 5; (Get-Process -Id $PID).Kill()
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
        $RegistryTemplates = Get-ChildItem -Path "$AdditionalPath\Registry" -Filter *.reg -Recurse | Select-Object -Property Name, BaseName, Extension, Directory, FullName
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
        $RegistryTemplates = Get-ChildItem -Path "$AdditionalPath\Registry" -Filter *_Offline.reg -Recurse | Select-Object -Property Name, BaseName, Extension, Directory, FullName
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

Function New-ISO
{
    [CmdletBinding()]
    Param ()

    Begin
    {
        $WimInfo = Import-Clixml -Path (Join-Path -Path $WorkFolder -ChildPath WimInfo.xml)
        $ISOName = $($WimInfo.Edition).Replace(' ', '') + "_$($WimInfo.Build).iso"
        $ISOPath = Join-Path -Path $WorkFolder -ChildPath $ISOName
        $BootData = ('2#p0,e,b"{0}"#pEF,e,b"{1}"' -f "$($ISOMedia)\boot\etfsboot.com", "$($ISOMedia)\efi\Microsoft\boot\efisys.bin")
    }
    Process
    {
        [IO.FileInfo]$Oscdimg = @("HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots") |
        ForEach-Object { Get-ItemProperty -Path $($_) -Name KitsRoot10 -ErrorAction Ignore } |
        Select-Object -First 1 -ExpandProperty KitsRoot10 |
        Join-Path -ChildPath "Assessment and Deployment Kit\Deployment Tools\$Env:PROCESSOR_ARCHITECTURE\Oscdimg\oscdimg.exe"
        If (!$Oscdimg)
        {
            [void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
            $OpenFile = New-Object -TypeName System.Windows.Forms.OpenFileDialog
            $OpenFile.Title = "Select the Oscdimg executable for ISO creation."
            $OpenFile.InitialDirectory = [System.IO.Directory]::GetCurrentDirectory()
            $OpenFile.Filter = "oscdimg.exe|oscdimg.exe|All files|*.*"
            If ($OpenFile.ShowDialog() -eq 'OK') { [IO.FileInfo]$Oscdimg = $OpenFile.FileName }
            Else { Out-Log -Error "No oscdimg.exe was selected. Skipping ISO creation."; Return }
        }
        If ($Oscdimg.Exists)
        {
            Try
            {
                $Host.UI.RawUI.WindowTitle = "Creating a Bootable Windows Installation Media ISO."
                Out-Log -Info "Creating a Bootable Windows Installation Media ISO."
                $ProcessStartInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
                $ProcessStartInfo.FileName = $Oscdimg.FullName
                $ProcessStartInfo.Arguments = @('-bootdata:{0}', '-u2', '-udfver102', '-l"{1}"', '"{2}"', '"{3}"' -f $BootData, $($WimInfo.Name), $ISOMedia, $ISOPath)
                $ProcessStartInfo.CreateNoWindow = $true
                $ProcessStartInfo.WindowStyle = 'Hidden'
                $ProcessStartInfo.UseShellExecute = $false
                $Process = New-Object -TypeName System.Diagnostics.Process
                $Process.StartInfo = $ProcessStartInfo
                [void]$Process.Start()
                $Process.WaitForExit()
                [PSCustomObject]@{
                    Path     = $ISOPath
                    ExitCode = $Process.ExitCode
                }
            }
            Catch
            {
                Out-Log -Error "ISO creation failed." -ErrorRecord $Error[0]
                Start-Sleep 3
            }
            Finally
            {
                If ($null -ne $Process) { $Process.Dispose() }
            }
        }
    }
}
#endregion Helper Functions


Export-ModuleMember -Function Out-Log,
					Stop-Optimize,
					New-OfflineDirectory,
					Get-OfflineHives,
					New-Container,
					Remove-Container,
					Set-KeyProperty,
					Get-RegistryTemplates,
					Set-RegistryTemplates,
					New-ISO
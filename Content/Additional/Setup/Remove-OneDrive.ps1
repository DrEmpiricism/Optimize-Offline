Function Remove-OneDrive
{
	<#
	.SYNOPSIS
		Perform a full removal of all instances of Microsoft OneDrive.

	.DESCRIPTION
		Performs a full removal of all instances of Microsoft OneDrive from all current user accounts.
		Loads all users' NTUSER.DAT registry hives and removes the Microsoft OneDrive auto-run hook.
		Prevents the setup and installation of Microsoft OneDrive on future user accounts.
		Removes leftover Microsoft OneDrive directories, namespace icons and environmental variables.
		Disables Microsoft OneDrive policies.
		Optionally will remove all Microsoft OneDrive Component Store files.

	.PARAMETER RemoveComponents
		Removes the Microsoft OneDrive files in the Component Store.

	.EXAMPLE
		PS C:\> Remove-OneDrive

	.EXAMPLE
		PS C:\> Remove-OneDrive -RemoveComponents

	.NOTES
		Removing the Microsoft OneDrive Component Store files causes SFC to report repairable image corruption when ScanHealth is run and will automatically re-apply them.
	#>

	[CmdletBinding()]
	Param
	(
		[Switch]$RemoveComponents
	)

	Begin
	{
		$DefaultErrorActionPreference = $ErrorActionPreference
		$ErrorActionPreference = 'SilentlyContinue'
		$ProgressPreference = 'SilentlyContinue'
	}
	Process
	{
		Clear-Host
		Write-Host "Performing a full removal of Microsoft OneDrive." -ForegroundColor Cyan

		# Stop any running OneDrive processes and services and uninstall the OneDrive application.
		Get-Process -Name OneDrive* | Stop-Process -Force
		Get-Service -Name OneSyncSvc* | Stop-Service -Force -NoWait
		$OneDrive = "$Env:SystemRoot\SysWOW64\OneDriveSetup.exe"
		If (!(Test-Path -Path $OneDrive)) { $OneDrive = "$Env:SystemRoot\System32\OneDriveSetup.exe" }
		Start-Process -FilePath $OneDrive -ArgumentList ('/Uninstall') -Wait

		# Unregister any OneDrive scheduled tasks.
		Get-ScheduledTask -TaskName *OneDrive* | Unregister-ScheduledTask -Confirm:$false

		# Loop through the Default User and all Current User registry hives and remove the OneDrive auto-run hook.
		$LoggedOnUsers = (Get-CimInstance -ClassName Win32_LoggedOnUser | Select-Object -Property Antecedent -Unique).Antecedent.Name
		$HiveList = "HKLM:\SYSTEM\CurrentControlSet\Control\HiveList"
		$Hives = Get-Item -Path $HiveList | Select-Object -ExpandProperty Property | Where-Object { $PSItem -like "\REGISTRY\USER\S-*" -and $PSItem -notlike "*_Classes*" }
		$Users = Get-ChildItem -Path $Env:SystemDrive\Users -Force | Where-Object { $PSItem.PSIsContainer -and $PSItem.Name -ne 'Public' -and $PSItem.Name -ne 'All Users' } | Select-Object -ExpandProperty Name
		If ((Get-PSDrive -PSProvider Registry).Name -notcontains 'HKU') { $PSDrive = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Script }
		Push-Location -Path HKU:
		ForEach ($User In $Users)
		{
			$NTUSER = "$Env:SystemDrive\Users\$User\NTUSER.DAT"
			If (Test-Path -Path $NTUSER)
			{
				$NTUSERHive = $null
				If ($LoggedOnUsers -like "*$User*")
				{
					ForEach ($Hive In $Hives)
					{
						$HiveValue = (Get-ItemPropertyValue -Path $HiveList -Name $Hive) -replace "\\Device\\HarddiskVolume[0-9]*", $Env:SystemDrive
						If ($HiveValue -like "*\$User\*") { $NTUSERHive = $Hive.ToUpper().Replace('\REGISTRY\USER', 'HKU:'); Break }
					}
				}
				If (!$NTUSERHive)
				{
					$NTUSERHive = 'HKLM\NTUSER'
					Start-Process -FilePath REG -ArgumentList ('LOAD "{0}" "{1}"' -f $NTUSERHive, $NTUSER) -WindowStyle Hidden -Wait
					$NTUSERHive = $NTUSERHive.Insert(4, ':')
					Push-Location -Path HKLM:
				}
				Remove-ItemProperty -LiteralPath (Join-Path -Path $NTUSERHive -ChildPath 'Software\Microsoft\Windows\CurrentVersion\Run') -Name OneDriveSetup -Force
				Remove-ItemProperty -LiteralPath (Join-Path -Path $NTUSERHive -ChildPath 'Software\Microsoft\Windows\CurrentVersion\Run') -Name OneDrive -Force
				New-Item -Path (Join-Path -Path $NTUSERHive -ChildPath 'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run') -ItemType Directory -Force | New-ItemProperty -Name OneDrive -Value ([Byte[]](0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)) -PropertyType Binary -Force | Out-Null
				If ($NTUSERHive -eq 'HKLM:\NTUSER')
				{
					$NTUSERHive = $NTUSERHive.Remove(4, 1)
					Start-Process -FilePath REG -ArgumentList ('UNLOAD "{0}"' -f $NTUSERHive) -WindowStyle Hidden -Wait
					Pop-Location
				}
			}
		}
		Pop-Location
		If ($PSDrive) { Remove-PSDrive -Name $PSDrive.Name }

		# Remove the OneDrive folder namespace from the Navigation Pane.
		If ((Get-PSDrive -PSProvider Registry).Name -notcontains 'HKCR') { $PSDrive = New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -Scope Script }
		@("HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}", "HKCR:\WOW6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}") | Remove-Item -Recurse -Force
		New-Item -Path @("HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}", "HKCR:\WOW6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}") -ItemType Directory -Force | New-ItemProperty -Name System.IsPinnedToNameSpaceTree -Value 0 -PropertyType DWord -Force | Out-Null
		If ($PSDrive) { Remove-PSDrive -Name $PSDrive.Name }

		# Remove the OneDrive desktop icon namespace.
		Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -Force

		# Disable OneDrive policies.
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -ItemType Directory -Force | Out-Null
		New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\OneDrive" -ItemType Directory -Force | Out-Null
		New-Item -Path "HKCU:\Software\Microsoft\OneDrive" -ItemType Directory -Force | Out-Null
		New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name PreventNetworkTrafficPreUserSignIn -Value 1 -PropertyType DWord -Force | Out-Null
		New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name DisableFileSyncNGSC -Value 1 -PropertyType DWord -Force | Out-Null
		New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\OneDrive" -Name DisableFileSyncNGSC -Value 1 -PropertyType DWord -Force | Out-Null
		New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name DisableFileSync -Value 1 -PropertyType DWord -Force | Out-Null
		New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name DisableMeteredNetworkFileSync -Value 1 -PropertyType DWord -Force | Out-Null
		New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\OneDrive" -Name DisableMeteredNetworkFileSync -Value 1 -PropertyType DWord -Force | Out-Null
		New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name DisableLibrariesDefaultSaveToOneDrive -Value 1 -PropertyType DWord -Force | Out-Null
		New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\OneDrive" -Name DisableLibrariesDefaultSaveToOneDrive -Value 1 -PropertyType DWord -Force | Out-Null
		New-ItemProperty -Path "HKCU:\Software\Microsoft\OneDrive" -Name DisablePersonalSync -Value 1 -PropertyType DWord -Force | Out-Null

		# Save the paths of all opened folders so they can be restored after restarting the File Explorer process.
		$OpenedFolders = (New-Object -ComObject Shell.Application).Windows() | ForEach-Object -Process { $PSItem.Document.Folder.Self.Path }

		# Disable the AutoRestartShell to prevent the File Explorer process from automatically restarting, allowing us to remove any locked OneDrive files.
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoRestartShell -Value 0 -Type DWord -Force
		Stop-Process -Name explorer -Force

		# Remove OneDrive directories, Start Menu shell link, global environmental variable and registry property value.
		@("$Env:LOCALAPPDATA\Microsoft\OneDrive", "$Env:LOCALAPPDATA\OneDrive", "$Env:PROGRAMDATA\Microsoft OneDrive", "$Env:SYSTEMDRIVE\OneDriveTemp") | Remove-Item -Recurse -Force -ErrorAction Ignore
		If ((Get-ChildItem -Path "$Env:USERPROFILE\OneDrive" -Force -ErrorAction Ignore | Measure-Object).Count -eq 0) { Remove-Item -Path "$Env:USERPROFILE\OneDrive" -Recurse -Force -ErrorAction Ignore }
		@("$Env:AppData\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk", "$Env:AppData\Microsoft\Windows\Start Menu\Programs\desktop.ini", "Env:\OneDrive") | Remove-Item -Force -ErrorAction Ignore
		# Select-String -Path "$Env:AppData\Microsoft\Windows\Start Menu\Programs\desktop.ini" -Pattern 'OneDrive.lnk=OneDrive' | ForEach-Object -Process { $PSItem.Line.Replace('OneDrive.lnk=OneDrive', $null) } | Out-File -FilePath "$Env:AppData\Microsoft\Windows\Start Menu\Programs\desktop.ini" -Encoding Unicode -Force
		Remove-ItemProperty -Path HKCU:\Environment -Name OneDrive -Force -ErrorAction Ignore

		# Restore the AutoRestartShell back to its default value.
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoRestartShell -Value 1 -Type DWord -Force
		Start-Process -FilePath explorer -Wait

		# Remove the OneDrive Component Store files.
		If ($RemoveComponents.IsPresent)
		{
			Get-ChildItem -Path $Env:SystemRoot\WinSxS -Filter *OneDrive* -Force | ForEach-Object -Process {
				Start-Process -FilePath TAKEOWN -ArgumentList ('/F "{0}" /A /R /D Y' -f $PSItem.FullName) -WindowStyle Hidden -Wait
				Start-Process -FilePath ICACLS -ArgumentList ('"{0}" /GRANT *S-1-5-32-544:F /T /C' -f $PSItem.FullName) -WindowStyle Hidden -Wait
				Remove-Item -Path $PSItem.FullName -Recurse -Force
			}
		}

		# Restore the state of all opened folders.
		If ($OpenedFolders) { Invoke-Item -Path $OpenedFolders }
	}
	End
	{
		$ErrorActionPreference = $DefaultErrorActionPreference
	}
}

# Ensure we are running with administrative permissions.
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	$arguments = @(" Set-ExecutionPolicy Bypass -Scope Process -Force; & '" + $MyInvocation.MyCommand.Definition + "'")
	foreach ($param in $PSBoundParameters.GetEnumerator()) {
		$arguments += "-"+[string]$param.Key+$(If ($param.Value -notin @("True", "False")) {"="+$param.Value} Else {""})
	}
	If(!$noPause){
		$arguments += " ; pause"
	}
	Start-Process powershell -Verb RunAs -ArgumentList $arguments
	Stop-Process -Id $PID
}

If (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
	Clear-Host
	Write-Host "Remove the Microsoft OneDrive component store files?" -ForegroundColor Yellow
	$RemoveComponentFiles = Read-Host "[ y / N ] "
	Switch ($RemoveComponentFiles)
 {
		Y { Remove-OneDrive -RemoveComponents; Break }
		N { Remove-OneDrive; Break }
		Default { Remove-OneDrive; Break }
	}
}
Else { Write-Warning "Elevation is required to remove Microsoft OneDrive. Please relaunch this script as an administrator."; Start-Sleep 3; Exit }
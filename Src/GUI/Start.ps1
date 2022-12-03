Add-Type -AssemblyName PresentationFramework, System.Windows.Forms

$Global:Error.Clear()

$RootPath = $PSScriptRoot

$OO_Root_Path = (Get-Item -Path "$RootPath\..\..\").FullName
$OO_Lists_Path = "$($OO_Root_Path)Content\Lists\"
$ConsoleSTDOutPath = "$($OO_Root_Path)ConsoleOut.txt"
$CustomRegistryPath = "$($OO_Root_Path)\Content\CustomRegistry.reg"

$RemovalTypes = @("Blacklist", "Whitelist")
$ListTypes = @("WindowsApps", "SystemApps", "Capabilities", "Packages", "Services", "Features")
$ListTypesNoRemoval = @("Services", "Features")
$ListColumns = @{
	"WindowsApps" = @("DisplayName", "PackageName")
	"SystemApps" = @("DisplayName")
	"Capabilities" = @("Name")
	"Packages" = @("PackageName")
	"Services" = @("Name", "Description")
	"Features" = @("FeatureName", "OriginalState")
}
$ListMainKey = @{
	"WindowsApps" = "DisplayName"
	"SystemApps" = "DisplayName"
	"Capabilities" = "Name"
	"Packages" = "PackageName"
	"Services" = "Services"
	"Features" = "FeatureName"
}
$ListColumnsComboBox = @{
	"Features" = @("State")
	"Services" = @("Start")
}

Function CleanVars {
	Remove-Variable -Name Configuration, ConfigurationDef -ErrorAction Ignore
	Remove-Variable -Name OO_GUI_FlashUSBDriveNumber, OO_GUI_Timer, OO_GUI_Job -ErrorAction Ignore -Scope Global
	Foreach($ListType in $ListTypes) {
		Remove-Variable -Name "$($ListType)Template" -ErrorAction Ignore -Scope Global
	}
	If (Test-Path -Path "$ConsoleSTDOutPath") {
		Remove-Item -Path "$ConsoleSTDOutPath"
	}
}

CleanVars

$Global:OO_GUI_FlashUSBDriveNumber = -1

$Global:OO_GUI_Timer = New-Object System.Windows.Forms.Timer
$Global:OO_GUI_Timer.Interval = 3000

$Global:OO_GUI_Job = $null


$Configuration_path = (Get-Item -Path "$($OO_Root_Path)Configuration.json").FullName

## Import XAML files
Get-ChildItem -Path "$RootPath\XAML" -Filter *.xaml -Recurse | ForEach-Object -Process {
	New-Variable -Name "$($_.BaseName)XAML" -Value (Get-Content -Raw -Path $_.FullName) -Scope Script
}

## Import the List templates
Function Import-Templates {
	Foreach($ListType in $ListTypes){
		If(Test-Path -Path "$RootPath\RemovalTemplates\$($ListType)Template.json") {
			$JSON = Get-Content -Raw -Path "$RootPath\RemovalTemplates\$($ListType)Template.json" -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
		} Else {
			$JSON = @()
		}
		If(!$JSON){
			$JSON = @()
		}
		## Sync GUI list data from OO list data
		Switch($ListType) {
			"Services"{
				$Key = $ListMainKey.$ListType
				$List_OO = $(Get-Content -Raw -Path "$OO_Lists_Path\Services\ServicesList.json" -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop).$Key
				If($List_OO){
					Foreach($Item in $JSON) {
						Foreach($ItemOO in $List_OO) {
							If ($Item.Name -eq $ItemOO -or ($ItemOO -Match "\*" -and $Item.Name -like $ItemOO)){
								$Item.Start = $Item.Starts[4]
								Break
							}
						}
					}
				}
				$List_OO = $(Get-Content -Raw -Path "$OO_Lists_Path\Services\ServicesAdvanced.json" -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop).$Key
				If($List_OO){
					Foreach($Item in $JSON) {
						Foreach($ItemOO in $List_OO) {
							If($Item.Name -eq $ItemOO.name) {
								$Item.Start = $Item.Starts[$ItemOO.start]
								Break
							}
						}
					}
				}
			}
			"Features" {
				$Key = $ListMainKey.$ListType
				$List_OO_ToDisable = $(Get-Content -Raw -Path "$OO_Lists_Path\FeaturesToDisable\FeaturesToDisableList.json" -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop).$Key
				$List_OO_ToEnable = $(Get-Content -Raw -Path "$OO_Lists_Path\FeaturesToEnable\FeaturesToEnableList.json" -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop).$Key
				If($List_OO_ToDisable){
					Foreach($Item in $JSON) {
						Foreach($ItemOO in $List_OO_ToDisable){
							If ($Item.$Key -eq $ItemOO -or ($ItemOO -Match "\*" -and $Item.$Key -like $ItemOO)){
								$Item.State = "Disabled"
							}
						}
					}
				}
				If($List_OO_ToEnable){
					Foreach($Item in $JSON) {
						Foreach($ItemOO in $List_OO_ToEnable){
							If ($Item.$Key -eq $ItemOO -or ($ItemOO -Match "\*" -and $Item.$Key -like $ItemOO)){
								$Item.State = "Enabled"
							}
						}
					}
				}
			}
			default {
				If ($RemovalTypes.IndexOf($Configuration.$ListType) -gt -1){
					$Key = $ListMainKey.$ListType
					$List_OO = (Get-Content -Raw -Path "$OO_Lists_Path\$($ListType)\$($ListType)List.json" -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop).$Key
					If($List_OO){
						Foreach($Item in $JSON) {
							Foreach($ItemOO in $List_OO){
								If ($Item.$Key -eq $ItemOO -or ($ItemOO -Match "\*" -and $Item.$Key -like $ItemOO)){
									$Item.Selected = $true
								}
							}
						}
					}
				}
			}
		}
		Remove-Variable -Name "$($ListType)Template" -Scope Global -ErrorAction Ignore
		New-Variable -Name "$($ListType)Template" -Value $JSON -Scope Global
	}
}

Import-Templates

$ConfigurationDef = Get-Content -Path "$RootPath\Configuration_definition.json" -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
$Configuration = Get-Content -Path $Configuration_path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop

Function Save-List {
	param([string]$ListType)
	$PathList = "$($OO_Lists_Path)$($ListType)\$($ListType)List.json"
	$PathTemplate = "$RootPath\RemovalTemplates\$($ListType)Template.json"
	$Template = (Get-Variable -Name "$($ListType)Template" -ValueOnly -Scope Global)

	If(!(Test-Path -Path $PathList) -or !(Test-Path -Path $PathTemplate)){
		return
	}
	$List = @{ }
	$Key = $ListMainKey.$ListType
	$List.$Key = @( )
	Foreach($Item in $Template){
		If($Item.Selected){
			$List.$Key += $Item.$Key
		}
	}

	$Template | ConvertTo-Json | Out-File -FilePath $PathTemplate -Encoding UTF8 -Force -ErrorAction Ignore
	$List | ConvertTo-Json | Out-File -FilePath $PathList -Encoding UTF8 -Force -ErrorAction Ignore
}

Function Save-Features {
	$FeaturesToDisable = @()
	$FeaturesToEnable = @()

	Foreach($Feature in $Global:FeaturesTemplate){
		If($Feature.State -eq "Enabled" -and $Feature.OriginalState -eq "Disabled"){
			$FeaturesToEnable += $Feature.FeatureName
		}
		If($Feature.State -eq "Disabled" -and $Feature.OriginalState -eq "Enabled"){
			$FeaturesToDisable += $Feature.FeatureName
		}
	}
	$Global:FeaturesTemplate | ConvertTo-Json | Out-File -FilePath "$RootPath\RemovalTemplates\FeaturesTemplate.json" -Encoding UTF8 -Force -ErrorAction Ignore
	@{FeatureName = $FeaturesToEnable} | ConvertTo-Json | Out-File -FilePath "$($OO_Lists_Path)FeaturesToEnable\FeaturesToEnableList.json" -Encoding UTF8 -Force -ErrorAction Ignore
	@{FeatureName = $FeaturesToDisable} | ConvertTo-Json | Out-File -FilePath "$($OO_Lists_Path)FeaturesToDisable\FeaturesToDisableList.json" -Encoding UTF8 -Force -ErrorAction Ignore
}
Function Save-Services {
	$Services = @()
	Foreach($Service in $Global:ServicesTemplate){
		If($Service.OriginalStart -ne $Service.Start) {
			$Services += @{
				name = $Service.Name
				start = $Service.Starts.IndexOf($Service.Start)
				description = $Service.Description
			}
		}
	}
	$Global:ServicesTemplate | ConvertTo-Json | Out-File -FilePath "$RootPath\RemovalTemplates\ServicesTemplate.json" -Encoding UTF8 -Force -ErrorAction Ignore
	@{Services = $Services} | ConvertTo-Json | Out-File -FilePath "$($OO_Lists_Path)Services\ServicesAdvanced.json" -Encoding UTF8 -Force -ErrorAction Ignore
}

Function GenerateControlXaml {
	param ($Control)

	$XAML = $InputLayoutXAML
	$InputControl = Switch ($Control.Type) {
		"ComboBox" {
			$ComboBoxXAML
		}
		"Switch" {
			$CheckBoxXAML
		}
		default {""}
	}

	$InputControl = $InputControl.Replace("{Name}", $Control.Name)
	$InputControl = $InputControl.Replace("{Label}", $Control.Label)

	Switch ($Control.Type) {
		"ComboBox" {
			$InputControl = $InputControl.Replace("{Value}", $($Control.Values.IndexOf(($Configuration.($Control.Binding)))))
			$InputControl = $InputControl.Replace("{Items}", $($(Foreach($Value in $Control.Values){"
			<ComboBoxItem Content='$Value' />
			"}) -join "`n"))
		}
		"Switch" {
			$InputControl = $InputControl.Replace("{Value}", "{Binding Configuration.$($Control.Binding)}")
		}
	}

	$InputControl = $InputControl.Replace("{Tooltip}", $(If($Control.Description){ $Control.Description } Else {""}))

	$XAML = $XAML.Replace("{Input}", $InputControl)
	
	return $XAML
}

Function Set-ControlsVisibility {
	$ImageInfo = (Get-Content -Raw -Path "$RootPath\image_info.json" -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)
	If(!$ImageInfo -or !$ImageInfo.Build){
		return
	}
	$ConfigurationDef.PSObject.Properties | ForEach-Object {
		Foreach($Control in $_.Value.Controls) {
			If($Control.Restrictions -and $Control.Restrictions.Count -gt 0){
				$valid = $true
				Foreach($Restriction in $Control.Restrictions) {
					If($Restriction.Build -gt 0) {
						Switch ($Restriction.Criteria) {
							"min" {
								If($ImageInfo.Build -gt 0 -and $ImageInfo.Build -lt $Restriction.Build)
								{
									$valid = $false
									break
								}
							}
							"max" {
								If($ImageInfo.Build -gt 0 -and $ImageInfo.Build -gt $Restriction.Build)
								{
									$valid = $false
									break
								}
							}
						}
					}
				}
				$ControlWPF = $Window.FindName($Control.Name)
				$ControlWPF.Visibility = $(If (!$valid) {"Collapse"} Else {"Visible"})
				Switch($Control.Type) {
					"Switch" {
						$ControlWPF.IsChecked = $false
					}
					"ComboBox" {
						$ControlWPF.SelectedIndex = 0
					}
				}
			}
		}
	}
}

Function GenerateTabLayout {
	param ([string]$Content, [string]$TabHeader, [string]$Name, [switch]$NoScroll)
	$XAML = $(If($NoScroll.IsPresent) {$TabLayoutXAML} Else {$TabScrollXAML})
	$XAML = $XAML.Replace("{TabContent}", $Content)
	$XAML = $XAML.Replace("{TabHeader}", $TabHeader)
	$XAML = $XAML.Replace("{Name}", $Name)
	return $XAML
}

Function GenerateMainConfigTab {
	$XAML = $MainConfigTabXAML
	$TabXAML = GenerateTabLayout -Content $XAML -TabHeader "General" -Name "GeneralTab"
	$Cols = @{}
	$ConfigurationDef.PSObject.Properties | ForEach-Object -Process {
		$ControlsXAML = ""
		Foreach ($Control in $_.Value.Controls) {
			$ControlXAML = GenerateControlXaml -Control $Control
			If($ControlXAML.Trim() -ne "") {
				$ControlsXAML = $ControlsXAML + $ControlXAML
			}
		}
		If($ControlsXAML -eq ""){
			$ControlsXAML = "<TextBlock Height='30' VerticalAlignment='Center' HorizontalAlignment='Center' Width='Auto'
			Text='No configuration items available' /> 
			"
		}
		$SectionXAML = $MainConfigGroupBoxXAML
		$SectionXAML = $SectionXAML.Replace("{Header}", $_.Value.Label)
		$SectionXAML = $SectionXAML.Replace("{Content}", $ControlsXAML)
		If(!$Cols[$_.Value.Column]){
			$Cols[$_.Value.Column] = ""
		}
		$Cols[$_.Value.Column] += $SectionXAML
	}
	$ColsXAML = ""
	foreach($i in $Cols.keys){
		$ColsXAML += "
		<StackPanel Grid.Column='$i' Margin='0' Orientation='Vertical'>
			$($Cols[$i])
		</StackPanel>
		"
	}
	$TabXAML = $TabXAML.Replace("{ColsXAML}", $ColsXAML)
	$TabXAML = $TabXAML.Replace("{Cols}", $Cols.Count)
	return $TabXAML
}

Function GenerateListTab {
	param([string]$ListType, [string]$Header)
	If(!$Configuration.$ListType){
		return ""
	}
	$ListTypeSelectedIndex = $($RemovalTypes.IndexOf($Configuration.$ListType))
	If($ListTypeSelectedIndex -lt 0){
		$ListTypeSelectedIndex = 0
	}
	$TabXAML = $ListRemovalTabXAML.Replace("{ListType}", $ListType)
	$TabXAML = $TabXAML.Replace("{ListTypeSelectedIndex}", $ListTypeSelectedIndex)
	$TabXAML = $TabXAML.Replace("{Columns}", $($(Foreach($Value in $ListColumns.$ListType){"
	<GridViewColumn DisplayMemberBinding='{Binding $Value}' Header='$Value' />
	"}) -join "`n"))
	return (GenerateTabLayout -NoScroll -Content $TabXAML -TabHeader $Header  -Name "$($ListType)Tab")
}

Function GenerateListComboTab {
	param([string]$ListType, [string]$Header)
	$TabXAML = $ListRemovalComboTabXAML.Replace("{ListType}", $ListType)
	$Columns = @()
	Foreach($Column in $ListColumns.$ListType){
		$Columns += "
			<GridViewColumn DisplayMemberBinding='{Binding $Column}' Header='$Column' />
		"
	}
	Foreach($Column in $ListColumnsComboBox.$ListType){
		$Columns += "
		<GridViewColumn Header='$Column'>
			<GridViewColumn.CellTemplate>
				<DataTemplate>
					<ComboBox Width='100' SelectedItem='{Binding ElementName=$($ListType)ListView, Path=SelectedItem.$($Column), UpdateSourceTrigger=PropertyChanged}' ItemsSource='{Binding $($Column)s, Mode=TwoWay}' SelectedValue='{Binding $($Column), Mode=TwoWay}' />
				</DataTemplate>
			</GridViewColumn.CellTemplate>
		</GridViewColumn>
		"
	}
	$TabXAML = $TabXAML.Replace("{Columns}", $Columns)
	return (GenerateTabLayout -NoScroll -Content $TabXAML -TabHeader $Header  -Name "$($ListType)Tab")
}

Function GenerateOutputTab {
	$Content = $OutputTabXAML
	return (GenerateTabLayout -NoScroll -Content $Content -TabHeader "Output" -Name "OutputTab")
}


Function GenerateCustomRegistryTab {
	$Content = $CustomRegistryTabXAML
	return (GenerateTabLayout -NoScroll -Content $Content -TabHeader "Custom Registry" -Name "CustomRegistryTab")
}


$TabsXAML = "
$(GenerateMainConfigTab)
$(GenerateListTab -ListType "WindowsApps" -Header "Windows Apps")
$(GenerateListTab -ListType "SystemApps" -Header "System Apps")
$(GenerateListTab -ListType "Capabilities" -Header "Capabilities")
$(GenerateListTab -ListType "Packages" -Header "Packages")
$(GenerateListComboTab -ListType "Features" -Header "Features")
$(GenerateListComboTab -ListType "Services" -Header "Services")
$(GenerateCustomRegistryTab)
$(GenerateOutputTab)
"
$LayoutXAML = $LayoutXAML.Replace("{Tabs}", $TabsXAML)

[xml]$XAML = @"
$LayoutXAML
"@

$Reader = (New-Object System.Xml.XmlNodeReader $XAML)
$Window = [Windows.Markup.XamlReader]::Load($Reader)

If (!$Window) {
	Exit
}

$Window.Add_Closing({
	CleanVars
	If($Global:OO_GUI_Job) {
		Stop-Process $Global:OO_GUI_Job
	}
})

$Window.Icon = "$RootPath\setup.ico"
$BrowseSourcePathButton = $Window.FindName("Browse_SourcePath")
$BrowseOutputPathButton = $Window.FindName("Browse_OutputPath")
$ProcessButton = $Window.FindName("ProcessButton")
$PopulateButton = $Window.FindName("PopulateButton")
$SelectUSB = $Window.FindName("SelectUSB")
$SelectedUSB = $Window.FindName("SelectedUSB")
$FlashToUSB = $Window.FindName("FlashToUSB")
$SourcePath = $Window.FindName("SourcePath")
$OutputPath = $Window.FindName("OutputPath")
$OutputTab = $Window.FindName("OutputTab")
$Console = $Window.FindName("Console")
$CustomRegistry = $Window.FindName("CustomRegistry")
$GeneralTab = $Window.FindName("GeneralTab")
$WindowsAppsTab = $Window.FindName("WindowsAppsTab")
$SystemAppsTab = $Window.FindName("SystemAppsTab")
$CapabilitiesTab = $Window.FindName("CapabilitiesTab")
$PackagesTab = $Window.FindName("PackagesTab")
$FeaturesTab = $Window.FindName("FeaturesTab")
$ServicesTab = $Window.FindName("ServicesTab")
$CustomRegistryTab = $Window.FindName("CustomRegistryTab")

Set-ControlsVisibility

Foreach($ListType in $ListTypes) {
	New-Variable -Name "$($ListType)ListView" -Value $Window.FindName("$($ListType)ListView")
	New-Variable -Name "$($ListType)ListFilter" -Value $Window.FindName("$($ListType)ListFilter")
	New-Variable -Name "$($ListType)ListType" -Value $Window.FindName("$($ListType)ListType")
	New-Variable -Name "$($ListType)SelectAll" -Value $Window.FindName("$($ListType)SelectAll")
	New-Variable -Name "$($ListType)SelectNone" -Value $Window.FindName("$($ListType)SelectNone")
}

Function SetControlsAccess {
	param($Enabled)
	$GeneralTab.IsEnabled = $Enabled
	$WindowsAppsTab.IsEnabled = $Enabled
	$SystemAppsTab.IsEnabled = $Enabled
	$CapabilitiesTab.IsEnabled = $Enabled
	$PackagesTab.IsEnabled = $Enabled
	$FeaturesTab.IsEnabled = $Enabled
	$ServicesTab.IsEnabled = $Enabled
	$CustomRegistryTab.IsEnabled = $Enabled
	$ProcessButton.IsEnabled = $Enabled
	$PopulateButton.IsEnabled = $Enabled
	$FlashToUSB.IsEnabled = $Enabled
	$SelectUSB.IsEnabled = $Enabled
	$SourcePath.IsEnabled = $Enabled
	$BrowseSourcePathButton.IsEnabled = $Enabled
	$OutputPath.IsEnabled = $Enabled
	$BrowseOutputPathButton.IsEnabled = $Enabled
}

Function Save-Configuration {
	foreach($ListType in $ListTypes){
		If($Configuration.$ListType -and $ListTypesNoRemoval.IndexOf($ListType) -ge 0){
			continue
		}
		$Control = $Window.FindName("$($ListType)ListType")
		If($Configuration.$ListType -and $Control){
			If($RemovalTypes.IndexOf($Control.SelectedItem.Content) -ge 0){
				$Configuration.$ListType = $Control.SelectedItem.Content
			} Else {
				$Configuration.$ListType = $RemovalTypes[0]
			}
		}
	}
	$Configuration.Services = "Advanced"
	$Configuration.FeaturesToEnable = "List"
	$Configuration.FeaturesToDisable = "List"
	$Configuration | ConvertTo-Json | Out-File -FilePath $Configuration_path -Encoding UTF8 -Force -ErrorAction Ignore
}

Function SetError {
	param([string]$Err) 
	$OutputTab.IsSelected = $true
	WriteToConsole -Text "`nError GUI: $Err" -Append
}

Function WriteToConsole {
	param([string]$Text, [switch]$Append)

	If($Append){
		$Console.Text += $Text
	} Else {
		$Console.Text = $Text
	}

	$Console.ScrollToEnd()
}

Function RunOO {
	param([switch]$populateTemplates)
	$Global:populateTemplates = $populateTemplates
	Try{
		Save-Configuration
		$OutputTab.IsSelected = $true
		SetControlsAccess -Enabled $false
		$Global:OO_GUI_Job = Start-Process powershell -WindowStyle Hidden -argument "Set-ExecutionPolicy Bypass -Scope Process -Force; & '$($OO_Root_Path)Start-Optimize.ps1' -GUI -FlashUSBDriveNumber $Global:OO_GUI_FlashUSBDriveNumber $(If($populateTemplates) {"-populateTemplates"} Else {''}) *>> '$($ConsoleSTDOutPath)'" -Verb RunAs -PassThru
		$Global:OO_GUI_Timer.Start()
	} Catch {
		SetError -Err $Error[0]
		SetControlsAccess -Enabled $true
		$Global:OO_GUI_Timer.Stop()
		If(Test-Path -path "$ConsoleSTDOutPath"){
			Remove-Item -Path "$ConsoleSTDOutPath"
		}
	}
}

$ProcessButton.Add_Click({
	RunOO
})

$PopulateButton.Add_Click({
	RunOO -populateTemplates
})

$Window.DataContext = [PSCustomObject]@{
	Configuration = [PSCustomObject]$Configuration
}

If(Test-Path -Path $Configuration.SourcePath) {
	$SourcePath.Text = $Configuration.SourcePath
	SetControlsAccess -Enabled $true
}

$OutputPath.Text = $Configuration.OutputPath
$Configuration.FlashToUSB = "Off"

$SelectedFlashToUSBIndex = @("UEFI", "Legacy").IndexOf($Configuration.FlashToUSB)
If($SelectedFlashToUSBIndex -ge 0) {
	$FlashToUSB.SelectedIndex = $SelectedFlashToUSBIndex
}

$BrowseSourcePathButton.Add_Click({
	$FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ 
		InitialDirectory = [Environment]::GetFolderPath('Desktop')
		Filter = 'All allowed types|*.wim;*.swm;*.iso;*.esd;*.WIM;*.SWM;*.ISO;*.ESD'
		Multiselect = $false
		AddExtension = $true
		CheckPathExists = $true
	}

	$null = $FileBrowser.ShowDialog()

	If($FileBrowser.FileName -and $FileBrowser.FileName -ne $SourcePath.Text){
		$SourcePath.Text = Get-Item -Path $FileBrowser.FileName
	}
})

$BrowseOutputPathButton.Add_Click({
	$SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
	$SaveFileDialog.InitialDirectory = [Environment]::GetFolderPath('Desktop')
	$SourceExtension = (Get-Item $SourcePath.Text).Extension
	$SaveFileDialog.Filter = "$($SourceExtension) files (*$($SourceExtension))| *$($SourceExtension)"
	If($SaveFileDialog.ShowDialog() -eq 'Ok'){
		$OutputPath.Text = $SaveFileDialog.FileName
	}
})

$SourcePath.Add_TextChanged({
	$Enabled = ("" -ne $SourcePath.Text.Trim() -and (Test-Path -Path $SourcePath.Text.Trim()))
	$Configuration.SourcePath = $SourcePath.Text.Trim()
	Save-Configuration
	SetControlsAccess -Enabled $true
	If($Enabled){
		RunOO -populateTemplates
	}
})

$OutputPath.Add_TextChanged({
	$Configuration.OutputPath = $OutputPath.Text.Trim()
	Save-Configuration
})

Foreach($ListType in $ListTypes) {

	$SaveConfiguration = [ScriptBlock]::Create((Get-Item function:Save-Configuration).Definition)
	$SaveList = [ScriptBlock]::Create((Get-Item function:Save-List).Definition)

	$ListView = Get-Variable -Name "$($ListType)ListView" -ValueOnly

	If(!$ListView){
		Continue
	}

	$ListTemplate = (Get-Variable -Name "$($ListType)Template" -ValueOnly -Scope Global)
	$ListView.ItemsSource = $ListTemplate

	If($ListTypesNoRemoval.IndexOf($ListType) -eq -1){
		(Get-Variable -Name "$($ListType)SelectAll" -ValueOnly).Add_Click({
			$ListView.SelectAll()
			$ListView.Focus()
		}.GetNewClosure())
		(Get-Variable -Name "$($ListType)SelectNone" -ValueOnly).Add_Click({
			$ListView.UnselectAll()
			$ListView.Focus()
		}.GetNewClosure())
		(Get-Variable -Name "$($ListType)ListType" -ValueOnly).Add_SelectionChanged({
			$SaveConfiguration.Invoke()
			$ListView.Focus()
		}.GetNewClosure());
		$ListView.Add_SelectionChanged({
			$SaveList.Invoke($ListType)
		}.GetNewClosure());
	}

	$ListFilter = Get-Variable -Name "$($ListType)ListFilter" -ValueOnly
	$ListFilter.Add_TextChanged({
		$ListTemplate = (Get-Variable -Name "$($ListType)Template" -ValueOnly -Scope Global)
		If("" -eq $ListFilter.Text){
			$ListView.ItemsSource = [PSCustomObject]$ListTemplate
			$ListFilter.Focus()
			return
		}
		$Filtered = @()
		foreach($Item in $ListTemplate){
			foreach($prop in $Item.PsObject.Properties)
			{
				If($prop.Value -like "*$($ListFilter.Text)*") {
					$Filtered += $Item
					Break
				}
			}
		}
		$ListView.ItemsSource = [PSCustomObject]$Filtered
		$ListFilter.Focus()
	}.GetNewClosure())
}

$TimerTick = {
	If(Test-Path -Path "$ConsoleSTDOutPath"){
		WriteToConsole -Text (Get-Content -Path "$ConsoleSTDOutPath" -Raw -Encoding utf8)
		[Windows.Input.InputEventHandler]{ $Window.UpdateLayout() }
	}
	If($null -ne $Global:OO_GUI_Job.ExitCode){
		$Global:OO_GUI_Timer.Stop()
		SetControlsAccess -Enabled $true
		If(Test-Path -Path "$ConsoleSTDOutPath"){
			Remove-Item -Path "$ConsoleSTDOutPath"
		}
		Import-Templates
		foreach($ListType in $ListTypes) {
			$ListView = (Get-Variable -Name "$($ListType)ListView" -ValueOnly)
			$ListView.ItemsSource = (Get-Variable -Name "$($ListType)Template" -ValueOnly -Scope Global)
		}
		Set-ControlsVisibility
		Save-Configuration
		WriteToConsole -Text "`nFinished" -Append
	}
}
$Global:OO_GUI_Timer.Add_Tick($TimerTick)


$ConfigurationDef.PSObject.Properties | ForEach-Object {
	Foreach($Config in $_.Value.Controls) {
		$Control = $Window.FindName($Config.Name)
		If($Control){
			Switch($Config.Type) {
				"Combobox" {
					$SaveConfiguration = [ScriptBlock]::Create((Get-Item function:Save-Configuration).Definition)
					$Control.Add_SelectionChanged({
						If($Config.Values.IndexOf($args[0].SelectedItem.Content) -gt -1){
							$Configuration.($Config.Binding) = $args[0].SelectedItem.Content
						}
						$SaveConfiguration.Invoke()
					}.GetNewClosure())
				}
				"Switch" {
					$Control.Add_Checked({
						Save-Configuration
					})
					$Control.Add_UnChecked({
						Save-Configuration
					})
				}
			}
		}
	}
}

$Window.FindName("FeaturesListView").Add_MouseLeave({
	Save-Features
})
$Window.FindName("ServicesListView").Add_MouseLeave({
	Save-Services
})

$FlashToUSB.Add_SelectionChanged({
	If($Global:OO_GUI_FlashUSBDriveNumber -ge 0){
		$Configuration.FlashToUSB = $FlashToUSB.SelectedItem.Content
	} Else {
		$Configuration.FlashToUSB = "Off"
	}
	Save-Configuration
})
$SelectUSB.Add_Click({
	$SelectedUSB.IsEnabled = $false
	$SelectedUSB.Visibility = "Collapsed"
	$USBDrives = Get-Disk | Where-Object BusType -eq USB
	If($USBDrives.Count -eq 0) {
		[System.Windows.MessageBox]::Show('No USB drives found')
		return
	}
	$USBDrive = $USBDrives | Out-GridView -Title 'Select USB Drive to Format' -OutputMode Single
	If($USBDrive){
		$SelectedUSB.Content = $USBDrive.FriendlyName
		$Global:OO_GUI_FlashUSBDriveNumber = $USBDrive.Number
		$Configuration.FlashToUSB = $FlashToUSB.SelectedItem.Content
		Save-Configuration
		$SelectedUSB.IsEnabled = $true
		$SelectedUSB.Visibility = "Visible"
	}
})

If(Test-Path -Path $CustomRegistryPath){
	$CustomRegistry.Text = Get-Content -Path $CustomRegistryPath -Raw -ErrorAction Ignore
}

$CustomRegistry.Add_MouseLeave({
	If($CustomRegistry.Text.Trim() -ne "Please input custom registry tweaks here."){
		$CustomRegistry.Text.Trim() | Out-File -Path "$($OO_Root_Path)\Content\CustomRegistry.reg"
	}
});

$Window.FindName("TabControl").Add_SelectionChanged({
	$Window.UpdateLayout()
	If($WindowsAppsTab.IsSelected){
		$Window.FindName("WindowsAppsListView").Focus()
	} Elseif ($SystemAppsTab.IsSelected){
		$Window.FindName("SystemAppsListView").Focus()
	} Elseif ($CapabilitiesTab.IsSelected){
		$Window.FindName("CapabilitiesListView").Focus()
	} Elseif ($PackagesTab.IsSelected){
		$Window.FindName("PackagesListView").Focus()
	}
})

Save-Configuration

[Void]$Window.ShowDialog()


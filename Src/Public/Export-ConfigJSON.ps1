Function Export-ConfigJSON
{
  [OutputType([PSObject])]
  Param ()

  $JSONTemplate = @"
{
  "_Info": [
    "This is a JSON based Configuration file for Optimize-Offline.",
    "Ensure proper formatting is used when editing the JSON parameter values.",
    "Boolean parameter values use true and false. String parameter values must be enclosed in double-quotes."
  ],
  "SourcePath": `"$([Convert]::ToString($ConfigParams.SourcePath).Replace('\', '\\'))`",
  "WindowsApps": `"$($ConfigParams.WindowsApps)`",
  "SystemApps": $([Convert]::ToString($ConfigParams.SystemApps).ToLower()),
  "Capabilities": $([Convert]::ToString($ConfigParams.Capabilities).ToLower()),
  "Packages": $([Convert]::ToString($ConfigParams.Packages).ToLower()),
  "Features": $([Convert]::ToString($ConfigParams.Features).ToLower()),
  "DeveloperMode": $([Convert]::ToString($ConfigParams.DeveloperMode).ToLower()),
  "WindowsStore": $([Convert]::ToString($ConfigParams.WindowsStore).ToLower()),
  "MicrosoftEdge": $([Convert]::ToString($ConfigParams.MicrosoftEdge).ToLower()),
  "Win32Calc": $([Convert]::ToString($ConfigParams.Win32Calc).ToLower()),
  "Dedup": $([Convert]::ToString($ConfigParams.Dedup).ToLower()),
  "DaRT": `"$($ConfigParams.DaRT)`",
  "Registry": $([Convert]::ToString($ConfigParams.Registry).ToLower()),
  "Additional": $([Convert]::ToString($ConfigParams.Additional).ToLower()),
  "ISO": `"$($ConfigParams.ISO)`"
}
"@
  If (!$ConfigParams.WindowsApps)
  {
    $JSONTemplate = $JSONTemplate.Replace("`"WindowsApps`": `"$($ConfigParams.WindowsApps)`",", $null)
  }
  If (!$ConfigParams.DaRT)
  {
    $JSONTemplate = $JSONTemplate.Replace("`"DaRT`": `"$($ConfigParams.DaRT)`",", $null)
  }
  If (!$ConfigParams.ISO)
  {
    $JSONTemplate = $JSONTemplate.Replace("`"ISO`": `"$($ConfigParams.ISO)`"", $null)
    $JSONTemplate = $JSONTemplate | ForEach-Object -Process { If ($PSItem -match '"Additional": true,') { $PSItem -replace '"Additional": true,', '"Additional": true' } }
  }
  $JSONTemplate = $JSONTemplate -creplace '(?m)^\s*\r?\n', ''
  $JSONTemplate
}
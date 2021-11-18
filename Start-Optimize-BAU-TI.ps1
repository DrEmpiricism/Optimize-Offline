<#
  .SYNOPSIS
    Start-Optimize is a configuration call script for the Optimize-Offline module.

  .DESCRIPTION
    Start-Optimize automatically imports the configuration JSON file into the Optimize-Offline module.

  .EXAMPLE
    .\Start-Optimize.ps1

    This command will import all values set in the configuration JSON file into the Optimize-Offline module and begin the optimization process.

  .NOTES
    Start-Optimize requires that the configuration JSON file is present in the root path of the Optimize-Offline module.
#>
[CmdletBinding()]
Param (
  [Parameter(Mandatory = $false)] [switch]$populateLists,
  [Parameter(Mandatory = $false)] [switch]$populateTemplates
)

$Global:Error.Clear()

# Ensure we are running with full administrative permissions via RunAsTI function.
function RunAsTI ($cmd) { $id='RunAsTI'; $sid=((whoami /user)-split' ')[-1]; $code=@'
$ti=(whoami /groups)-like"*1-16-16384*"; $DM=[AppDomain]::CurrentDomain."DefineDynamicAss`embly"(1,1)."DefineDynamicMod`ule"(1)
$D=@(); 0..5|% {$D+=$DM."DefineT`ype"("M$_",1179913,[ValueType])}; $I=[int32];$P=$I.module.gettype("System.Int`Ptr"); $U=[uintptr]
$D+=$U; 4..6|% {$D+=$D[$_]."MakeB`yRefType"()};$M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal");$Z=[uintptr]::size
$S=[string]; $F="kernel","advapi","advapi",($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]),($U,$S,$I,$I,$D[9]),($U,$S,$I,$I,[byte[]],$I)
0..2|% {$9=$D[0]."DefinePInvokeMeth`od"(("CreateProcess","RegOpenKeyEx","RegSetValueEx")[$_],$F[$_]+'32',8214,1,$S,$F[$_+3],1,4)}
$DF=0,($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
1..5|% {$k=$_;$n=1;$AveYo=1; $DF[$_]|% {$9=$D[$k]."DefineFie`ld"('f'+$n++,$_,6)}}; $T=@(); 0..5|% {$T+=$D[$_]."CreateT`ype"()}
0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -force}; function F ($1,$2) {$T[0]."GetMeth`od"($1).invoke(0,$2)};
if (!$ti) { $g=0; "TrustedInstaller","lsass"|% {if (!$g) {net1 start $_ 2>&1 >$null; $g=@(get-process -name $_ -ea 0|% {$_})[0]}}
 function M($1,$2,$3){$M."GetMeth`od"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H+=M "AllocHG`lobal" $I $_};
 M "WriteInt`Ptr" ($P,$P) ($H[0],$g.Handle); $A1.f1=131072;$A1.f2=$Z;$A1.f3=$H[0];$A2.f1=1;$A2.f2=1;$A2.f3=1;$A2.f4=1;$A2.f6=$A1
 $A3.f1=10*$Z+32;$A4.f1=$A3;$A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false); $w=0x0E080600
 $out=@($null,"powershell -win 1 -nop -c iex `$env:A",0,0,0,$w,0,$null,($A4 -as $T[4]),($A5 -as $T[5])); F "CreateProcess" $out
} else { $env:A=''; $PRIV=[uri].module.gettype("System.Diagnostics.Process")."GetMeth`ods"(42) |? {$_.Name -eq "SetPrivilege"}
 "SeSecurityPrivilege","SeTakeOwnershipPrivilege","SeBackupPrivilege","SeRestorePrivilege" |% {$PRIV.Invoke(0, @("$_",2))}
 $HKU=[uintptr][uint32]2147483651; $LNK=$HKU; $reg=@($HKU,"S-1-5-18",8,2,($LNK -as $D[9])); F "RegOpenKeyEx" $reg; $LNK=$reg[4]
 function SYM($1,$2){$b=[Text.Encoding]::Unicode.GetBytes("\Registry\User\$1");@($2,"SymbolicLinkValue",0,6,[byte[]]$b,$b.Length)}
 if (!$cmd) {$cmd='cmd'}; $r="start `"$id`" /high /w"; F "RegSetValueEx" (SYM $(($key-split'\\')[1]) $LNK)
 start cmd -args ("/q/x/d/r title $id && $r",$cmd) -wait -win 1; F "RegSetValueEx" (SYM ".Default" $LNK)
} # lean and mean snippet by AveYo, 2018-2021
'@; $key="Registry::HKEY_USERS\$sid\Volatile Environment"; $a1="`$id='$id';`$key='$key';";$a2="`$cmd='$($cmd-replace"'","''")';`n"
sp $key $id $($a1,$a2,$code) -type 7 -force; $arg="$a1 `$env:A=(gi `$key).getvalue(`$id)-join'';rp `$key `$id -force; iex `$env:A"
start powershell -args "-win 1 -nop -c $arg" -verb runas }

$arguments = @()
foreach ($param in $PSBoundParameters.GetEnumerator()) {
  $arguments += "-"+[string]$param.Key+$(If ($param.Value -notin @("True", "False")) {"="+$param.Value} Else {""})
}
if ((whoami)-ne"nt authority\system") {RunAsTI "powershell -c . ""$($MyInvocation.MyCommand.Path)"" $arguments; pause"; return}

# Ensure the configuration JSON file exists.
If (!(Test-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath Configuration.json))) {
  Write-Warning ('The required configuration JSON file does not exist: "{0}"' -f (Join-Path -Path $PSScriptRoot -ChildPath Configuration.json))
  Start-Sleep 3
  Exit
}

# If the configuration JSON or ordered collection list variables still exists from a previous session, remove them.
If ((Test-Path -Path Variable:\ContentJSON) -or (Test-Path -Path Variable:\ConfigParams)) {
  Remove-Variable -Name ContentJSON, ConfigParams -ErrorAction Ignore
}

# Use a Try/Catch/Finally block in case the configuration JSON file URL formatting is invalid so we can catch it, correct its formatting and continue.
Try {
  $ContentJSON = Get-Content -Path (Join-Path -Path $PSScriptRoot -ChildPath Configuration.json) -Raw | ConvertFrom-Json
}
Catch [ArgumentException] {
  $ContentJSON = (Get-Content -Path (Join-Path -Path $PSScriptRoot -ChildPath Configuration.json) -Raw).Replace('\', '\\') | Set-Content -Path (Join-Path -Path $Env:TEMP -ChildPath Configuration.json) -Encoding UTF8 -Force -PassThru
  $ContentJSON = $ContentJSON | ConvertFrom-Json
  Move-Item -Path (Join-Path -Path $Env:TEMP -ChildPath Configuration.json) -Destination $PSScriptRoot -Force
  $Global:Error.Remove($Error[-1])
}
Finally {
  $ContentJSON.PSObject.Properties.Remove('_Info')
}

# Convert the JSON object into a nested ordered collection list. We use the PSObject.Properties method to retain the JSON object order.
$ConfigParams = [Ordered]@{
  populateLists     = $populateLists
  populateTemplates = $populateTemplates
}
ForEach ($Name In $ContentJSON.PSObject.Properties.Name) {
  $Value = $ContentJSON.PSObject.Properties.Item($Name).Value
  If ($Value -is [PSCustomObject]) {
    $ConfigParams.$Name = [Ordered]@{ }
    ForEach ($Property in $Value.PSObject.Properties) {
      $ConfigParams.$Name[$Property.Name] = $Property.Value
    }
  }
  Else {
    $ConfigParams.$Name = $Value
  }
}

# Import the Optimize-Offline module and call it by passing the JSON configuration.
If ($PSVersionTable.PSVersion.Major -gt 5) {
  Try {
    Import-Module Dism -SkipEditionCheck -Force -WarningAction Ignore -ErrorAction Stop
  }
  Catch {
    Write-Warning 'Failed to import the required Dism module.'
    Start-Sleep 3
    Exit
  }
  Try {
    Import-Module (Join-Path -Path $PSScriptRoot -ChildPath Optimize-Offline.psm1) -SkipEditionCheck -Force -WarningAction Ignore -ErrorAction Stop
  }
  Catch {
    Write-Warning ('Failed to import the Optimize-Offline module: "{0}"' -f (Join-Path -Path $PSScriptRoot -ChildPath Optimize-Offline.psm1))
    Start-Sleep 3
    Exit
  }
}
Else {
  Try {
    Import-Module (Join-Path -Path $PSScriptRoot -ChildPath Optimize-Offline.psm1) -Force -WarningAction Ignore -ErrorAction Stop
  }
  Catch {
    Write-Warning ('Failed to import the Optimize-Offline module: "{0}"' -f (Join-Path -Path $PSScriptRoot -ChildPath Optimize-Offline.psm1))
    Start-Sleep 3
    Exit
  }
}

Optimize-Offline @ConfigParams

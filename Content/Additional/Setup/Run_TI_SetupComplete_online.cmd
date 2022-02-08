@ECHO OFF
TITLE Run SetupComplete.cmd online as TrustedInstaller

:: RunAsTI (part 1 of 2) - lean and mean snippet by AveYo  Source: https://github.com/AveYo/LeanAndMean
whoami|findstr /i /c:"nt authority\system" >nul || ( call :RunAsTI "%~f0" %* & exit/b )

pushd "%~dp0"

CALL "%~dp0SetupComplete.cmd"

EXIT

:: RunAsTI (part 2 of 2) - lean and mean snippet by AveYo  Source: https://github.com/AveYo/LeanAndMean
#:RunAsTI: #1 snippet to run as TI/System, with /high priority, /priv ownership, explorer and HKCU load
set ^ #=& set "0=%~f0"& set 1=%*& powershell -nop -c iex(([io.file]::ReadAllText($env:0)-split':RunAsTI\:.*')[1])& exit/b
$_CAN_PASTE_DIRECTLY_IN_POWERSHELL='^,^'; function RunAsTI ($cmd) { $id='RunAsTI'; $sid=((whoami /user)-split' ')[-1]; $code=@'
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
 F "RegSetValueEx" (SYM $(($key-split'\\')[1]) $LNK); $EXP="HKLM:\Software\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}"
 $r="explorer"; if (!$cmd) {$cmd='C:\'}; $dir=test-path -lit ((($cmd -split '^("[^"]+")|^([^\s]+)') -ne'')[0].trim('"')) -type 1
 if (!$dir) {$r="start `"$id`" /high /w"}; sp $EXP RunAs '' -force; start cmd -args ("/q/x/d/r title $id && $r",$cmd) -wait -win 1
 do {sleep 7} while ((gwmi win32_process -filter 'name="explorer.exe"'|? {$_.getownersid().sid -eq "S-1-5-18"}))
 F "RegSetValueEx" (SYM ".Default" $LNK); sp $EXP RunAs "Interactive User" -force } # lean and mean snippet by AveYo, 2018-2021
'@; $key="Registry::HKEY_USERS\$sid\Volatile Environment"; $a1="`$id='$id';`$key='$key';";$a2="`$cmd='$($cmd-replace"'","''")';`n"
sp $key $id $($a1,$a2,$code) -type 7 -force; $arg="$a1 `$env:A=(gi `$key).getvalue(`$id)-join'';rp `$key `$id -force; iex `$env:A"
$_PRESS_ENTER='^,^'; start powershell -args "-win 1 -nop -c $arg" -verb runas }; <#,#>  RunAsTI $env:1;  #:RunAsTI:

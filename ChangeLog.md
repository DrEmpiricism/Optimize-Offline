# ChangeLog #

## Build 3.2.7.4 (10-122-2019) ##

- Created a custom Win32Calc.wim that replaces the official cabinet files for builds 17663+ for the integration of the Win32 Calculator.
- The custom Win32Calc.wim fixes an issue that is present in the OEM Win32Calc cabinet packages which cause the Win32 Calculator to crash when the conversion type is changed.
- Updated the registry optimizations applied when the -Registry switch is used.
- A custom LockScreen can now be applied to the image using the -Additional switch and its associated Config.ini by adding the custom LockScreen image to the new 'Content\Additional\LockScreen' folder.
- Updated multiple functions used with the OfflineProcessing module.

## Build 3.2.7.3 (10-08-2019) ##

- Removed the disabling of the Clipboard feature with the -Registry switch.
- Updated the Start Menu layout clean-up.
- Updated the Windows Store bundle packages with their latest versions.
- Removed a redundant line of code.

## Build 3.2.7.2 (09-17-2019) ##

- The Offline Processing Module has been renamed and restructured.
- Updated multiple functions.
- Corrected an issue preventing the WIM metadata log from being saved.
- Added a Refresh-Explorer.ps1, RebootToRecovery_MyPC.reg, SetupComplete.cmd and OOBE.cmd in the 'Additional\Setup' folder.
- Updated the 'Additional Tweaks.reg' file in the 'Additional\RegistryTemplates' folder.
- Made some minor updates and adjustments to the primary script.

## Build 3.2.7.1 (09-08-2019) ##

- Windows Photo Viewer is now only restored if the Windows Photos App is removed.
- When optimizing the file structure of the ISO media, the '\sources\sxs' folder is now only removed if the .NET Framework 3 (NetFx3) has been integrated into the image.
- Updated multiple functions in the Functions module.
- Made some minor but necessary adjustments to the primary script.

## Build 3.2.7.0 (09-03-2019) ##

- Corrected an issue that affected users who only supplied a WIM file for optimizing. An error occurred when the variable assigned to the mount path of the boot image was being returned to the main script despite a boot image not even being present. This would have resulted in failed DaRT integration and image dismount.
- Converted certain variables to dynamic parameters.
- Improved string creation by incorporating the StringBuilder .NET class which significantly reduces script overhead and load.
- Made some minor adjustments and optimizations to both the primary script and the functions module.

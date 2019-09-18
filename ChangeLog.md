# ChangeLog #

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

## Build 3.2.6.9 (08-30-2019) ##

- When supplying a WIM as the source image, it no longer has to be named as 'install.wim' as to accommodate users who catalog their individual WIM files by version, build, edition, etc.
- The mounting and dismounting order of any images has been optimized.
- All additional primary script variables have been moved to the Functions module.
- If the CallingShellApp System Application or YourPhone Appx Package is removed, its associated Immersive Control Panel Settings link will also be removed.
- Enabled .NET strong cryptography in the Registry Optimizations that ensures current SSL protocols are used for .NET application communication and not outdated and vulnerable SSL protocols.
- Optimized how logs are generated and saved.
- Updated the C# code in the Functions module for access token privileges and ISO creation.
- Updated the Windows Store bundle packages with their latest versions.
- Additional script and module code enhancements and changes.

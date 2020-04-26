# ChangeLog #

## Build 4.0.0.10 (04-25-2020) ##

- Added additional subscribed content that will be disabled when the ContentDeliveryManager system application is removed.
- Added the disabling of the Get More out of Windows notification that displays during OOBE and during reboots for builds 18362+.
- Updated registry values applied to the image registry hives.
- Updated the Get-OfflineHives function.
- Updated the Windows Store bundle packages.

## Build 4.0.0.9 (04-15-2020) ##

- Added the Developer Mode package for Windows 10 build 19041.
- Originally multiple package summary logs would be created and overwritten. This has been fixed.
- Removed a registry setting that applied a telemetry registry value to the WOW6432Node offline hive causing some UAC functionality issues.
- Corrected a typo in the external help files.

## Build 4.0.0.8 (04-14-2020) ##

- Added support for Windows 10 build 19041 (20H1).
- Multiple Resource Functions and optimization processes have been updated to support build 19041.
- Added a new -Additional hashtable parameter named 'LayoutModification' and its corresponding folder to the 'Content\Additional' directory. Enabling the 'LayoutModification' hashtable value will apply a user-specific custom Start layout XML added to the 'Content\Additional\LayoutModification' folder to the image. Additionally, the optimization process that creates and applies a custom Start layout XML will be bypassed.
- The custom Start layout XML that Optimize-Offline creates and applies to the image has been updated to support build 19041. Also, the regular Control Panel pinned application has been replaced by the Master Control Panel (God Mode) application.
- The creation of the Package Summary Log now first checks for specific dynamic parameters before compiling the log file. This prevents an empty log file from being created and saved if no package integrations were processed.
- Created a Microsoft DaRT 10 integration WIM file for Windows 10 build 19041.
- Updated the Windows Store bundle packages.
- This list is not exhaustive of all changes made to Optimize-Offline or its Resource Functions, but outlines the major ones.
**NOTE: Because the Data Deduplication and Developer Mode packages are not yet available for Windows 10 19041, they cannot be integrated into build 19041. When these packages are available, they will be added to Optimize-Offline. Likewise, Windows 10 build 19041 is still an Insider Preview, so more optimizations will be added in future Optimize-Offline builds.**

## Build 4.0.0.7 (03-17-2020) ##

- Updated multiple Resource Functions.
- Updated the firewall registry settings that get applied when the Deduplication packages are integrated into the image.
- Removed unsupported language packages from the 'Packages' directory. These will be re-added if/when additional languages are supported by Optimize-Offline.
- Optimized and trimmed down multiple module processes.
- This list is not exhaustive of all changes made to Optimize-Offline or its Resource Functions, but outlines the major ones.

## Build 4.0.0.6 (02-17-2020) ##

- Combined and ordered the Optimize-Offline module's initializing and finalizing processes more optimally.
- The clean-up of Xbox integrated content has been modified to eliminate potential errors when trying to run paid apps or games downloaded from the Windows Store.
- Errors are now handled simultaneously when a log entry is written that contains an error record.
- The boot and recovery images will no longer be automatically mounted by default; rather, Optimize-Offline will now only mount them if any parameters for optimization requires their mounting (i.e. applying Microsoft DaRT 10 or integrating drivers to Windows Setup or Windows Recovery environments).
- Simplified multiple processes and Resource Functions to further improve the overall speed of image optimization.
- Updated localized data and external help.
- Updated the Windows Store bundle packages.

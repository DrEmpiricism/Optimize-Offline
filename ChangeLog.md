# ChangeLog #

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

## Build 4.0.0.5 (02-03-2020) ##

- Corrected incorrect key syntax in the -Additional hashtable parameter.
- Corrected an issue where some Resource Functions would try to use the main module's data strings when reporting errors, which could cause an additional incorrect variable error.
- When an ESD is used as the source image, the metadata of the image is now refreshed after it's been exported to a WIM to ensure the image path is accurate.
- Updated necessary Resource Functions to reflect the aforementioned changes.

## Build 4.0.0.4 (01-26-2020) ##

- Optimize-Offline now supports the ESD file format as a source image.
- The Additional.json file has been nested into the Configuration.json, as having a separate JSON file for additional user content was redundant.
- Incorporated better methods for numerous removal processes.
- Improved the Start-Optimize.ps1 call script functionality.
- Updated multiple Resource Functions.
- Updated the Windows Store bundle packages.
- Updated localized data and external help.
- This update list is not exhaustive of all changes and updates, but outlines the major ones.

## Build 4.0.0.3 (01-08-2020) ##

- Updated the Start-Optimize.ps1 call script.
- Updated multiple Resource Functions.
- Added additional error-handling for Resource Function processes.
- Fixed an error that would prevent the use of solid compression for the final image.
- Localized data has been updated.

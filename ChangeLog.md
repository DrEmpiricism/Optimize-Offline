# ChangeLog #

## Build 4.0.1.2 (07-02-2020) ##

- The Microsoft Edge Chromium browser can now be integrated into Windows 10 builds 18362+
- Following the integration of the Microsoft Edge Chromium package, Optimize-Offline will also apply all administrative policy templates to the image and a custom 'master_preferences' file for Microsoft Edge Chromium updates.
- Additional registry settings specific to Microsoft Edge Chromium have been added.
- The -DaRT parameter value 'All' has been removed. The -DaRT parameter now accepts one or both of the 'Setup' and 'Recovery' values.
- The Configuration.json file has been updated to incorporate the change to the -DaRT parameter.
- The Start-Optimize call script and Resource Functions have been updated.
- The MAML XML external help file and manifest data have been updated.
- There have been additional offline process code changes to reflect the aforementioned updates.

## Build 4.0.1.1 (06-12-2020) ##

- Updated multiple Resource Functions.
- Added a requirement check for PowerShell version 5.
- Updated the registry settings that restore the default Windows Photo Viewer.
- Updated the Windows Store bundle packages.

## Build 4.0.1.0 (05-19-2020) ##

- Corrected an issue where some users had an error when integrating Microsoft DaRT 10.
- Corrected an issue for Windows 10 build 19041 where Windows Store Apps would be unresponsive in a runtime (online) environment if any Windows Store Apps were deprovisioned in the offline optimization process.

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

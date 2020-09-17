# ChangeLog #

## Build 4.0.1.5 (09-17-2020) ##

- Fixed an error where the metadata for the image would not be returned if both the -DaRT and -Additional parameters were omitted.
- Updated the Win32Calc integration image package to correct a bug where selecting 'Unit Conversion' from its drop-down list would cause the Win32Calc.exe to close immediately.
- Updated the Resource Function that returns the metadata for any images being optimized.
- Additional Optimize-Offline code improvements.

## Build 4.0.1.4 (08-23-2020) ##

- Added support for Windows 10 build 19042 (20H2).
- Added the new 20H2 Start Menu Experience to the applied registry settings.
- Corrected an issue for Windows 10 builds 19041+ where it occasionally would be returned as an unsupported image build.
- Updated the Windows Store bundle packages.
- Updated the optional Set-Additional runtime script.
- Multiple code improvements across the framework.

## Build 4.0.1.3 (08-07-2020) ##

- Added the clean-up of any directories for Windows Apps that were deprovisioned.
- Added additional disabling of Microsoft Edge telemetry and tracking.
- Updated the custom App Associations .xml that gets imported.
- Updated the 'Additional Tweaks.reg' file in the 'Content\Additional\RegistryTemplates' directory.
- Updated the Windows Store bundle packages.
- Added two scripts in the 'Content\Additional\Setup' directory named 'Remove-OneDrive.ps1' and 'Set-Additional.ps1' that can be run during system runtime (when the image is in an online state). These two scripts are copied to the image's 'Windows\Setup\Scripts' directory.
- Remove-OneDrive.ps1 will completely and thoroughly remove Microsoft OneDrive.
- Set-Additional.ps1 uses the included ScheduledTasks.json and Services.json files to disable any scheduled tasks or system services that have 'SetState' value to 'Disable.' Additionally runtime-specific privacy and system settings are also applied.

**NOTE: Make sure you evaluate the contents of the Set-Additional.ps1 script, and its associated ScheduledTasks and Services .json files, before running the script. Though there are no ill effects of running it as-is, and before disabling any scheduled tasks or services it makes backup files of their default states, make sure no scheduled tasks or system services are set to be disabled that will be required by the system. Lastly, if you do not intend to use either of these scripts, you can remove them from the 'Content\Additional\Setup' directory.**

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

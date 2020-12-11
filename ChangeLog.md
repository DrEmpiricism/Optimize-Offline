# ChangeLog #

## Build 4.0.1.7 (11-13-2020 and 12-11-2020) ##

- Optimize-Offline now supports PowerShell Core 7.
- Updated required Resource Functions for PowerShell Core 7 compatibility.
- Updated the Start-Optimize call script for PowerShell Core 7 compatibility.
- Corrected a non-terminating error that could occur for a null value when no DaRT parameters were passed when processing the boot.wim and/or winre.wim.
- Added the Deduplication integration packages for Windows 10 builds 19041+. **added 12-11-2020**
- Updated the Edge Chromium integration package for Windows 10 builds 19041+.
- Updated the Edge Chromium integration process.
- Updated the Windows Store bundle packages.
- If the removal of System Applications returns an error, it will now continue to the next System Application selected in the Gridview list instead of returning to the caller scope.
- Added the 20H2 Enablement package to the exclusion list when outputting a Gridview list of Windows Cabinet Packages available for removal.
- The Windows Cabinet Packages are now output to its Gridview list sorted in order by their package names instead of package type. This way all packages for a specific feature are in order to make selecting all of them easier without potentially skipping one.
- Improved the exported package log formatting.

**Note: If creating bootable ISO media using PowerShell Core 7, Optimize-Offline must be able to resolve the path to the oscdimg.exe premastering tool included in the Windows 10 ADK, as its default API function wrapper contains code that is not yet fully supported by PowerShell versions higher than 5.**

## Build 4.0.1.6 (10-06-2020) ##

- Added support for the SWM (split Windows image) file type.
- If the source image is a SWM file, only the first SWM file needs passed to Optimize-Offline. It will recursively copy all additional SWM files. Likewise, the SWM files do not need to be named 'install.swm,' etc. Do note that in order to use a SWM file as the source image, all of the SWM files must be in their own directory. For example, if there are three SWM files named 'test.swm,' 'test2.swm,' 'test3.swm,' then all three of these SWM files must be in their own directory in order for Optimize-Offline to recognize them as split images from the same WIM file.
- Corrected some registry vales that contained an invalid hive mount point.
- Updated the Microsoft Edge Chromium package for Windows 10 builds 19041+.
- Updated the Windows Store bundle packages.
- The MAML XML external help file and manifest data have been updated.
- Multiple code improvements across the framework.

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

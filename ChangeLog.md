# ChangeLog #

## Build 4.0.1.9 (09-12-2021) ##

- Optimize-Offline's native ISO creation function has been re-written and now supports PowerShell 6+.
- The names of the Biometric FOD packages that are automatically removed when the BioEnrollment System Application has been removed are now displayed and logged.
- Added the disabling of Windows Taskbar Interests and News.
- Additional framework code changes and other core module updates.

**NOTE: A very small update was added on 09-16-2021 that adds 21H2 to the Get-ImageData function as well as the module manifest.**

## Build 4.0.1.8 (06-22-2021) ##

**NOTE: Updates should resume with the same frequency as before.**

- Optimize-Offline now supports Windows 10 build 19043 (21H1)
- When it is detected that the BioEnrollment System Application has been removed, Optimize-Offline will not automatically remove its associated Capability Packages.
- A -ComponentCleanup switch has been added that will compress all superseded components, thus reducing the size of the Component Store.
- The DaRT 20H1/21H1 WIM file has been updated.
- External help files have been updates.
- Additional framework code changes to support Windows 10 21H1 and other core module updates.

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

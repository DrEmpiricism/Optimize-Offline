# ChangeLog #

## Build 4.0.1.10 (02-16-2023) ##

- Corrected the improper formatting of the output WimFileInfo.xml file when running Optimize-Offline with PowerShell 7+
- Windows 10 22H2 will now display properly in the output WimFileInfo.xml file.
- Added additional telemetry disabling registry entries.
- Disabled Interests and News and Meet Now taskbar registry entries.
- Updated the Win32Calc integration WIM file.
- Updated the integrated Microsoft Edge Administrative Policy Templates WIM file to the latest versions.
- Updated the integrated CustomAppsAssociations.xml
- Updated the 'Additional Tweaks' registry template.
- Updated the Set-Additional.ps1 post-setup script.
- Added a Remove-DefaultUser0.ps1 post-setup script.
- The Get-DeploymentTool function has been replaced with the Get-DISMPath function.
- Removed redundancies in the Invoke-Cleanup function.
- Additional framework code changes and other core module updates.

**NOTE: Windows 11 compatibility will be coming with build 4.0.2. Furthermore, the reason for the fairly long hiatus with updates has been due to the passing of my father and the subsequent birth of a little bundle of joy. Though my personal life is not anyone's business on the internet, I also do not think it's fair to let those who use this framework to sit in the dark about its current state. Conclusively, I will try to get to the Troubleshooting/Bug reports as soon as I'm available to do so. Thank you for your understanding and patience.**

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

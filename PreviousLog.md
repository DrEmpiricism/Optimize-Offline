# Previous Version Log #

## Build 3.1.3.0 (updated on 12-14-2019) ##

- Made multiple changes and removals to registry settings applied, as many of them have changed and are not applicable to older builds. As such, Optimize-Offline no longer supports builds lower than RS4 (17134).
- The -Registry parameter has been changed to a switch.
- Many registry settings that modified the layout of the desktop and GUI have been removed as to allow for pure end-user customization.
- Removed multiple Helper Functions that are no longer applicable to the new registry changes.
- There is no longer a SetupComplete.cmd script that is generated and added to the image allowing for its inclusion using a distribution share (i.e. OEM folder added to the installation media).
- The -NoISO switch has been removed.
- There is a new -ISO switch that can be used to remaster a new ISO if an ISO was used at the source image.
- Updated the Windows Store Appx Packages.
- Additional optimization process and code changes.

## Build 3.1.2.9 (updated on 11-29-2019) ##

- Updated multiple helper functions.
- Updated Microsoft Store and Dependency Packages.
- Created a new helper function, with a small C# wrapper, to detect whether a system is running on UEFI firmware.
- Optimize-Offline now checks whether the running system is UEFI. If a system is NOT detected as UEFI, the string data adding the UEFI Firmware icon, and its associated custom link, will be omitted from the custom Start Menu and Taskbar Layout and link creation object process.
- Using the -Features switch will now also display all disabled Windows Features in a Gridview list where they can be enabled.
- The -Registry parameter no longer has "Default" automatically set as a value and must be explicitly entered (like other parameters) when calling Optimize-Offline.
- Fixed two areas in the SetupComplete here-string that included duplicate closing brackets.
- Added a -NoISO switch that will prevent the automatic creation of a bootable Windows Installation ISO when Windows Installation Media is used as the source image.
- Corrected a few benign error returns on some property values.
- Corrected a few missplaced variables within the script and a helper function.
- Optimized and reduced some process and helper function code.

## Build 3.1.2.8 (11-13-2018) ##

- Added a -Win32Calc switch that will now control whether the traditional Calculator gets applied or not, as opposed to having it automatically apply if the UWP Calculator is found to be removed. This allows full control for those who want either no calculator or both the UWP Calculator and the traditional Calculator.
- Made a small update to the Win32Calc process.

## Build 3.1.2.7 (11-10-2018) ##

- Updated the Debugging Tools for Windows 10 to version 17763.107
- There is a new "Whitelist" value that can be used with the -MetroApps parameter. In the Resources directory there is an AppxPackageWhitelist.xml file where one can add Provisioned Appx Packages by their DisplayName.  The removal process will then remove all Provisioned Appx Packages that are NOT whitelisted. This is convenient for those who do not want to remove all Appx Packages nor want to constantly select the same Appx Packages each time they optimize an image.
- The Win32Calc has been updated with its Feature Package CAB file(s) version 17763.1
- Registry values have been updated and some new ones added.
- A handful of processes have been changed around and include additional Try/Catch blocks for error-handling.
- Made multiple code changes to processes, variables and methods for handling the WIM file.

## Build 3.1.2.6 (11-04-2018) ##

- Some helper function and process code have been changed and updated.
- Updated and added some additional registry settings.
- Tweaked the logfile header and footer.

**Displays the previous 5 version updates of Optimize-Offline.**
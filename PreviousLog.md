# Previous Version Log #

## Build 3.1.3.7 (02-04-2019) ##

- Updated offline registry hive settings and added the inclusion of the Classic Personalization screen.
- Updated the disabling and removal of default tasks and services for Windows Defender.

## Build 3.1.3.6 (01-17-2019) ##

- Combined and updated multiple helper functions.
- Improved error reporting and error records' output format.
- Updated multiple registry values that get set in the offline image hives using the -Registry switch.
- Improved initializtion and finalization clean-up procedures.
- Assorted other code and contextual changes.
- Corrected a mutex synchronization primative the logging function uses.

## Build 3.1.3.5 (updated on 01-05-2019) ##

- Updated multiple helper functions and processes
- Removed registry settings that no longer applied to the most current Windows 10 builds and those that were being applied to both the current user and local machine hives simultaneously.
- Updated the context menu customization registry settings.
- Improved variable handling.

## Build 3.1.3.4 (updated on 12-29-2018) ##

- Removed the registry setting that prevented Windows Update from searching for default system drivers. Enabling this setting offline can prevent the online system from detecting multiple OEM drivers during Windows Setup.
- The old -NetFx3 and -Drivers parameters have been converted to switches and no longer require the paths to the integration packages. Instead, drivers to integrate into the image can be added to the Resources > Drivers folder in Optimize-Offline's root directory. Likewise, the .NET Framework 3 payload packages are now present in the Resources > NetFx3 folder.

## Build 3.1.3.3 (updated on 12-27-2018) ##

- Updated some entries added to the offline registry hives.
- Some very minor contextual changes to the overall code.

## Build 3.1.3.2 (updated on 12-24-2018) ##

- Changed the optimizations of the registry and Start Menu to process after all packages, features and additional content has been applied or integrated into the image.
- Incorporated Data Deduplication using the new -Dedup switch. Using the -Dedup switch will apply the Data Deduplication and File Server packages (located in the Resources directory) into the image and enable the "Dedup-Core" Windows Feature. Full details about Data Deduplication can be found on [Microsoft's Online Document](https://docs.microsoft.com/en-us/windows-server/storage/data-deduplication/overview)
- A custom image object is now used to return image data as opposed to variables.

## Build 3.1.3.1 (updated on 12-23-2018) ##

- Replaced the LayoutModification.xml with a simpler version that does not include a Taskbar layout and only includes links to the Control Panel and Windows Explorer. Moreover, Optimize-Offline no longer creates the custom UWP Explorer and UEFI Firmware Reboot icons as both can be easily added in a live environment.
- Removed the disabling of the Windows Insider Program in the registry settings.
- Added the prevention of automatic device driver downloads through Windows Update.
- Enabled strong .NET Framework cryptography in the registry settings.
- Updated the "Take Ownership" context menu feature code.
- Added a Distribution Share resource directory. This directory acts just like a distribution share added to Windows installation media except that it applies all contents offline as opposed to during the Windows 10 installation process. The end-user must use the typical distribution share file structure hierarchy when adding files and/or folders to be implemented into the offline image. One can add their own custom setup scripts (SetupComplete.cmd, OOBE.cmd, etc.), custom wallpapers and logos, an unattend.xml answer file, etc. Be aware that any custom images, logos, lockscreens or themes added must also be added to an autounattend.xml or unattend.xml in order for the system to recognize and apply them at boot-up. More info on distribution shares can be found [here](https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/wsim/distribution-shares-and-configuration-sets-overview)
- Multiple registry settings have been updated and a few have been removed for example the Insider's Program is no longer disabled and is again fully functional, etc.
- Improved some Helper Functions' process procedures, error recording and handling.
- The default Hosts file is backed-up and then replaced with the latest Steven Black master hosts file.  These are generally updated once a week on GitHub.  You can read about his Host files in detail [here](https://github.com/StevenBlack/hosts)
- The ISO creation process has been updated.
- Windows Store packages have been updated.
- The Win32Calc packages have been updated.

## Build 3.1.3.0 (updated on 12-14-2018) ##

- Made multiple changes and removals to registry settings applied, as many of them have changed and are not applicable to older builds. As such, Optimize-Offline no longer supports builds lower than RS4 (17134).
- The -Registry parameter has been changed to a switch.
- Many registry settings that modified the layout of the desktop and GUI have been removed as to allow for pure end-user customization.
- Removed multiple Helper Functions that are no longer applicable to the new registry changes.
- There is no longer a SetupComplete.cmd script that is generated and added to the image allowing for its inclusion using a distribution share (i.e. OEM folder added to the installation media).
- The -NoISO switch has been removed.
- There is a new -ISO switch that can be used to remaster a new ISO if an ISO was used at the source image.
- Updated the Windows Store Appx Packages.
- Additional optimization process and code changes.

## Build 3.1.2.9 (updated on 11-29-2018) ##

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

**Displays the previous 10 version updates of Optimize-Offline.**
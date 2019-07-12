# Optimize-Offline #

Optimize-Offline is a Windows Image (WIM) optimization script designed for Windows 10 versions 1803-to-1903 64-bit architectures.

## About Optimize-Offline ##

- Primary focus' are the removal of unnecessary bloat, privacy and security enhancements, cleaner aesthetics, increased performance and a significantly better user experience.
- Accepts either a full Windows 10 installation ISO, or a Windows 10 install.wim file.
- Does not perform any changes to an installed or live system nor can it optimize a live system.
- Makes multiple changes to both the offline system and registry hives to enhance security, usability and privacy while also improving performance.
- Checks the health of the image both before and after the script runs to ensure the image retains a healthy status.
- Detects what System Applications were removed, and further removes any associated drivers or services associated with them.
- Allows offline removal of Provisioned Application Packages, System Applications and Windows OnDemand Packages.
- Allows offline disabling and offline enabling of Windows Features.
- Allows for the offline integration of drivers, Microsoft DaRT 10, Windows Store, Microsoft Edge, Setup content, Data Deduplication and more.
- All optimization processes are done silently and properly with proper error-handling.

## Script disclaimer ##

- It is the responsibility of the end-user to be aware of what each parameter and switch does. These are well detailed in Optimize-Offline's header.
- Optimize-Offline is designed to optimize OEM images and not images already optimized by another script/program.
- Properties, features, packages, etc. can and often do change between builds.  This means that when optimizing an image, the script could warn of an error during the optimization process that did not occur before. The best recourse for errors is to post them - and any log files - in the 'Issues' section of this repository.
- Just because something can be removed does not mean it should be removed. Haphazard removal of System Applications can cause erros during Windows 10 setup.
- Help will not be given to users who attempt to optimize unsupported builds.

## About the -Registry switch ##

The -Registry switch applies an array of entries and values to the image registry hives designed to further enhance both the security of the default image as well as its usability and aesthetics.
The script only applies those registry entries and values applicable to the image build being optimized and bypasses those that are unsupported. Conversely, Optimize-Offline will apply additional entries and values to accommodate any application removal or integration. Optimize-Offline does not apply any Group Policy entries that are not available in the specific image by default, as this would just add unnecessary bloat to the registry itself with zero functionality.

A short list of some of the optimizations include:

- Completely disables Cortana without removing the default search feature.
- Disables a significant amount of telemetry, logging, tracking, monitoring and background feedback submission.
- Prevents bloatware link creation and disables a plethora of annoying default features.
- Disables Windows' annoying pop-up notifications and tips.
- Disables non-explicit application and system location sensor access.
- Disables background error reporting and automatic syncronization to Microsoft.
- Disables Cortana's intrusiveness during the OOBE component pass.
- Disables the automatic creation of tabs and icons for Microsoft Edge.
- Disables intrusive Microsoft feedback and notification queries.
- Cleans-up the default Context Menu options and integrates custom options.

## About the -Additional switch ##

The -Additional script allows the end-user to add specific content to the image during Optimize-Offline's automated processes instead of having to re-mount the image or use an external Distribution Share.
Within the '\Resources\Additional' directory are five folders: 'Drivers', 'Logo', 'Setup', 'Unattend' and 'Wallpaper'. The script automatically checks each folder to ensure the file-types are valid for the type of content being uploaded. Aside from the Drivers folder, content validation is based on Microsoft's deployment guidelines. For example, only bitmap (.bmp) images will be uploaded in the 'Logo' folder and only image files will be uploaded in the 'Wallpaper' folder. Moreover, only an answer file named 'unattend.xml' will be uploaded in the 'Unattend' folder and any others will be omitted. Conversely, any content located in the 'Setup' folder will be uploaded because what a user implements during the setup of their machine can be an array of different container types - files, directories, executables, etc.

All content is copied to the image in locations that are in accordance with Microsoft's deployment guidelines. For example, any system logo is uploaded to '\Windows\System32\oobe\info\logo', wallpaper is uploaded to '\Windows\Web\Wallpaper', scripts are uploaded to '\Windows\Setup\Scripts' and an unattend.xml is uploaded to '\Windows\Panther' (this is detailed more below).

All content can be either folders or directories themselves, or individual files. If, for example, you want a wallpaper directory called 'Custom', Optimize-Offline will copy the added 'Custom' directory - and all contents therein - to the '\Windows\Web\Wallpaper' directory. Optimize-Offline will not just copy all content over haphazardly and create a massive mess of files or completely omit a specific file structure.

**Optimize-Offline does NOT add any script to the registry to be automatically executed during new user log-in and all content is ONLY copied to the image. Only default setup scripts like SetupComplete.cmd, OOBE.cmd and ErrorHandler.cmd will run automatically as they're designed to do by default.**

## Driver integration ##

Any driver or driver package to be integrated into the offline image must be placed in the '\Resources\Additional\Drivers' folder when using the -Additional switch. Either single .inf files or full driver package directories are supported.

## unattend.xml Answer File ##

When an unattend.xml answer file is added to the 'Unattend' folder with the -Additional switch enabled, Optimize-Offline creates the '\Windows\Panther' directory within the image and copies the answer file to it. "Panther" was the code-name for a servicing and setup engine that began with Windows Vista. Addtionally, Optimize-Offline will check the contents of the unattend.xml to see if it includes offlineServicing or package servicing passes. If it does, it will apply the answer file directly to the image as well as copy it to the '\Windows\Panther' directory.

During Windows installation, Windows Setup automatically looks for answer files for custom installations in certain locations.  %WINDIR%\Panther is the first directory checked for an answer file including the installation media. An unattend.xml located in the %WINDIR%\Panther directory will act just like an autounattend.xml does and can contain all the same content. This is an alternative way to run a custom answer file for Windows Setup automatically as opposed to setting an autounattend.xml to the root of the installation media type being used.

An unattend.xml answer file can be created using the Windows System Image Manager that is including in the Windows ADK, or use some of the multiple online generators to create one. A word of caution, though, having incorrect or incomplete values in your answer file could prevent Windows from completing its setup or even starting its setup. If a custom disk layout is included for installation, make certain you enter the proper drive index numbers, GPT partition sizes and type IDs.

## Script process and settings danger ##

None of the automatic processes or settings are dangerous; however one must be careful when selecting what System Applications are removed.

## About System Applications ##

System Applications are a lot like Provisioned Application Packages (Windows Apps) in respect that they are provisioned and installed during the setup of Windows. During the Windows Setup component pass, setup looks for these System Applications in the default registry and provisions them for installation only if their entries are present. By removing these entries, Windows Setup does not provision them for installation.

This method is safer than force removing the System Application using its component package because it retains the default file structure. Furthermore, the force removal of System Applications' component packages can trip the dreaded "STATUS_SXS_COMPONENT_STORE_CORRUPT" flag. This is a critical component store corruption flag that will then be detected by any servicing command and Windows Update and prevent both the servicing and updating of the Operating System. The only way to remedy and fix this error is to re-install or reset the Operating System.

Four System Applications use a GUID namespace instead of a package name:

* 1527c705-839a-4832-9118-54d4Bd6a0c89 = Microsoft.Windows.FilePicker
* c5e2524a-ea46-4f67-841f-6a9465d9d515 = Microsoft.Windows.FileExplorer
* E2A4F912-2574-4A75-9BB0-0D023378592B = Microsoft.Windows.AppResolverUX
* F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE = Microsoft.Windows.AddSuggestedFoldersToLibraryDialog

## System Applications universally safe, and recommended, to remove ##

This can vary, depending on the end-user's final image requirements, but SecHealthUI (Windows Defender), ParentalControls, ContentDeliveryManager, MicrosoftEdge, MicrosoftEdgeDevelopmentTools, PPIProjection, HolographicFirstRun, BioEnrollment (if no Biometrics will be used), SecureAssessmentBrowser and (optionally) XboxGameCallableUI are all safe to remove. XboxGameCallableUI should only be removed if all Xbox Provisioned Application Packages are also removed and will not be used. Moreover, Cortana can also be removed; however, doing so will render the default search feature inoperable so its removal is only recommended if the end-user will be using a 3rd party search program like ClassicShell.

**Some System Applications are required during the OOBE setup pass and their removal can cause setup to fail. Do not remove any System Application if you're unsure of it's effect on a live system.**

## Microsoft DaRT 10 and Windows 10 Debugging Tools ##

> Microsoft Diagnostics and Recovery Toolset (DaRT) 10 lets you diagnose and repair a computer that cannot be started or that has problems starting as expected. By using DaRT 10, you can recover end-user computers that have become unusable, diagnose probable causes of issues, and quickly repair unbootable or locked-out computers. When it is necessary, you can also quickly restore important lost files and detect and remove malware, even when the computer is not online. [Microsoft Document](https://docs.microsoft.com/en-us/microsoft-desktop-optimization-pack/dart-v10/)

## Win32Calc ##

Starting in Windows 8.1, Microsoft introduced a Metro-style calculator to replace its traditional Calculator.  In Windows 10 non-LTSB/LTSC/Server editions, the traditional Calculator was entirely removed and replaced with a UWP (Universal Windows Platform) App version.  This new UWP Calculator introduced a fairly bloated UI many users were simply not fond of and much preferred the simplicity of the traditional Calculator (now labeled Win32Calc.exe).  Unfortunately, Microsoft never added the ability to revert back to the traditional Calculator nor released a downloadable package to install the traditional Calculator.

For Windows builds 17763, the OEM cabinet packages extracted from Windows 10 Enterprise LTSC 2019 are applied to the image. For higher Windows builds, a custom Win32Calc.wim that incorporates the latest Win32Calc components and strict security descriptors (SDDL) is expanded into the image. This allows for proper system management and user control. Optimize-Offline then adds the Win32Calc link to the appropriate .ini system file (this is a hidden system file located in every directory that has a list of all the linked programs within said directory).

## Data Deduplication ##

> Data Deduplication, often called Dedup for short, is a feature of Windows Server 2016 that can help reduce the impact of redundant data on storage costs. When enabled, Data Deduplication optimizes free space on a volume by examining the data on the volume by looking for duplicated portions on the volume. Duplicated portions of the volume's dataset are stored once and are (optionally) compressed for additional savings. Data Deduplication optimizes redundancies without compromising data fidelity or integrity. [Microsoft Document](https://docs.microsoft.com/en-us/windows-server/storage/data-deduplication/overview)

With Optimize-Offline, the Data Deduplication packages and Dedup-Core Windows Feature can be integrated into the offline image. PowerShell can then be used to enable and manage Data Deduplication using its storage cmdlets. More information is available from the [Microsoft Document](https://docs.microsoft.com/en-us/powershell/module/deduplication/?view=win10-ps)

## Windows Store integration ##

For Windows 10 Enterprise LTSC 2019, the latest Windows Store package bundle and dependency packages can be integrated into the image, as this flavor of Windows (like Windows 10 Enterprise LTSB 2015-2016) does not contain any Windows Apps in its OEM state. There is no additional procedure required once the optimized Windows 10 LTSC 2019 is installed, and the Windows Store will be displayed in the Start Menu.

## Microsoft Edge integration ##

For Windows 10 Enterprise LTSC 2019, Microsoft's flagship browser - Microsoft Edge - can be integrated into the image since this flavor of Windows (like Windows 10 Enterprise LTSB 2015-2016) does not contain Microsoft Edge in its OEM state.

## Solid image compression ##

Solid image compression uses the undocumented LZMS compression format to concatenate all file data within a regular WIM file into a solid WIM archive (ESD file). By doing this, a 4GB WIM file is able to be compressed to a size of 2GB or less. However, as with other forms of high-ratio compression, LZMS compression can take quite a while to complete and should NOT be selected as the final image compression type if the end-user is impatient or requires the optimized image quickly.

## ISO File Strucuture Optimization ##

This is a process that occurrs automatically when a Windows Installation ISO is used as the source image for optimization. In short, it removes all unnecessary media files used to install Windows 10 from a live system, thus reducing the total size of the installation media. The order in which files are removed and moved is critical to proper file structure optimization for bootup installation.

## ISO Remastering and Creation ##

When a Windows Installation ISO is used as the source image for optimization, Optimize-Offline expands the entire media content of the ISO. Using the -ISO switch will tell Optimize-Offline to automatically create a new Windows Installation Media ISO once all optimizations have been processed if the Windows ADK (Assessment and Deployment Kit) is installed on the system. If the Windows ADK is not installed on the system and the -ISO switch was used, a Windows Dialog Form will display allowing the end-user to select the oscdimg.exe premastering tool Optimize-Offline will use to create the bootable ISO.

Optimize-Offline queries specific registry keys that contain the path to the ADK's installed root location and then joins the absolute paths to the ADK boot files. Once it tests that the Oscdimg location exists, it silently passes the appropriate command-line arguments to the oscdimg executable that apply the proper bootcode and switches to create a new bootable Windows Installation Media ISO. Optimize-Offline queries the registry for the path to the ADK, as opposed to setting a static string for it, because many users install programs on different drives (i.e. SSD users). Likewise, these are the same registry keys various Microsoft software also queries when tools from the ADK are required, for example in the creation of the Windows 10 DaRT bootable media.

Optimize-Offline uses the Edition ID of the image that was optimized as the name of the ISO and the Display Name as its label.

## About the Defaultuser0 ghost account ##

Any time an OEM Windows Image is modified offline, or the System Preparation, Reset and Provisioning Package deployment features are used, there is a chance this ghost account will surface.
defaultuser0 is not a real account, however, and is a bug that has been present in Windows through countless flavors and variations. It is not added to any user groups nor does it even have a profile.
Conversely, failing to remove the defaultuser0 account immediately after Windows Installation completes can lead to future headaches.  As an example, if you reset Windows with the defaultuser0 ghost account still present, upon the restart of the device, Windows will force you to log into the defaultuser0 account to continue.

In earlier versions of Optimize-Offline, a specific registry key was appended to allow for elevated control over the defaultuser0 account which allowed for its manual removal, as well as a SetupComplete.cmd script code that automatically removed it. However, with the newer builds (17134+), this is no longer required and simply rebooting the newly installed OS will automatically remove the defaultuser0 account from the 'Users' directory without having to manually remove it.

## Optimize-Offline best practices ##

- Only OEM images should be used for optimization and not images that have already been modified by other scripts and/or programs.
- If maintaining fully updated OEM images, it's best to integrate offline updates into the image and then run Optimize-Offline.  It is not recommended to optimize an image and then integrate offline updates.
- Do not run any other programs or scripts - or manually run commands - that can interact with either the working directories of the script or the registry while the script is optimizing.
- Do not manually meddle in either the working directories nor the registry while it's optimizing an image.

## How to call Optimize-Offline ##

The easist way to call Optimize-Offline is by using the provided [Start.cmd script](https://github.com/DrEmpiricism/Optimize-Offline/blob/master/Start.cmd). Right-click the script and 'Open with Notepad,' then edit any variables to accommodate your optimization requirements. Once finished, save any changes and right click the Start.cmd script and select 'Run as Administrator' and it will call Optimize-Offline and pass all the variables, parameters and switches to the PowerShell script. This allows the end-user to quickly call Optimize-Offline without having to manually input the paths, parameters and switches each time an image is to be optimized.

The second way is to open an elevated PowerShell console shell and navigate to the root directory of the Optimize-Offline script and then dot source the script, followed by the paths, parameters and switches required for optimization:

- .\Optimize-Offline.ps1 -SourceImage "D:\Win ISO Files\Win10Pro_Full.iso" -WindowsApps "Select" -SystemApps -Packages -Features -Registry -Win32Calc -Dedup -DaRT -Additional -ISO
- .\Optimize-Offline.ps1 -SourceImage "D:\WIM Files\LTSC 2019\install.wim" -SystemApps -Packages -Features -WindowsStore -MicrosoftEdge

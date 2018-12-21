# Optimize-Offline #

Optimize-Offline is a Windows Image (WIM) optimization script designed for Windows 10 builds RS4 to RS5 64-bit architectures.

## About Optimize-Offline ##

- Primary focus' are the removal of unnecessary bloat, privacy and security enhancements, cleaner aesthetics, increased performance and a significantly better user experience.
- Accepts either a full Windows 10 installation ISO, or a Windows 10 install.wim file.
- Does not perform any changes to an installed or live system nor can it optimize a live system.
- Makes multiple changes to both the offline system and registry hives to enhance security, usability and privacy while also improving performance.
- Checks the health of the image both before and after the script runs to ensure the image retains a healthy status.
- Detects what System Applications were removed, and further removes any associated drivers or services associated with them.
- Allows offline removal of default Windows Packages and the disabling of Windows Features.

## Script disclaimer ##

- It is the responsibility of the end-user to be aware of what each parameter and switch does.
- Optimize-Offline is designed to optimize OEM images and not images already optimized by another script/program.
- Properties, features, packages, etc. can and often do change between builds.  This means that when optimizing an image, the script may warn of an error during the optimization process that did not occur before or stop the optimization process entirely.

## About the -Registry switch ##

The -Registry parameter applies an array of entries and values to the image's registry hives designed to further enhance both the security of the default image as well as its usability and aesthetics.
The script only applies those registry entries and values applicable to the image build being optimized and bypasses those that are unsupported.
A few of the switch settings:

- Completely disables Cortana without removing the default search feature.
- Disables a significant amount of telemetry, logging, tracking, monitoring and background feedback submission.
- Prevents bloatware link creation and disables a plethora of annoying default features.
- Disables Windows' annoying pop-up notifications and tips.
- Disables non-explicit application and system sensor access.
- Disables error reporting and automatic syncronization.
- etc.

## Script process and settings danger ##

None of the automatic processes or settings are dangerous; however one must be careful when selecting what System Applications are removed.

## About System Applications ##

System Applications are a lot like Provisioned Application Packages (Metro Apps) in respect that they are provisioned and installed during the setup of Windows. During the Windows Setup component pass, setup looks for these System Applications in the default registry and provisions them for installation only if their entries are present. By removing these entries, Windows Setup does not provision them for installation.

This method is safer than force removing the System Application using its component package because it retains the default file structure. Furthermore, the force removal of System Applications' component packages can trip the dreaded "STATUS_SXS_COMPONENT_STORE_CORRUPT" flag. This is a critical component store corruption flag that will then be detected by any servicing command and Windows Update and prevent both the servicing and updating of the Operating System. The only way to remedy and fix this error is to re-install or reset the Operating System.

*The upcoming GUI version of Optimize-Offline has full component package removal by both changing the permanency values of packages and using the DISM.API to allocate them and then remove them*.

## System Applications universally safe, and recommended, to remove ##

This can vary, depending on the end-user's final image requirements, but SecHealthUI (Windows Defender), ParentalControls, ContentDeliveryManager, MicrosoftEdge, MicrosoftEdgeDevelopmentTools, PPIProjection, HolographicFirstRun, BioEnrollment (if no Biometrics will be used), SecureAssessmentBrowser and (optionally) XboxGameCallableUI are all safe to remove. XboxGameCallableUI should only be removed if all Xbox Provisioned Application Packages are also removed and will not be used (see below). Moreover, Cortana can also be removed; however, doing so will render the default search feature inoperable so its removal is only recommended if the end-user will be using a 3rd party search program like ClassicShell.

**ShellExperienceHost should never be removed**.

## Provisioned Application Packages (Metro Apps) removal ##

The removal of Xbox.TCUI and Xbox.IdentityProvider will prevent the Windows Store Apps Troubleshooter from working properly and likewise affect the Windows Store. It is not recommended to remove these if the Windows Store is required.

## Microsoft DaRT 10 and Windows 10 Debugging Tools ##

> Microsoft Diagnostics and Recovery Toolset (DaRT) 10 lets you diagnose and repair a computer that cannot be started or that has problems starting as expected. By using DaRT 10, you can recover end-user computers that have become unusable, diagnose probable causes of issues, and quickly repair unbootable or locked-out computers. When it is necessary, you can also quickly restore important lost files and detect and remove malware, even when the computer is not online. [Microsoft Document](https://docs.microsoft.com/en-us/microsoft-desktop-optimization-pack/dart-v10/)

*The supplied WIMs used for applying MS DaRT 10 and associated debugging tools are compressed using recovery compression.  This type of compression cannot be viewed in a GUI by some ISO image programs.*

## Win32Calc ##

Starting in Windows 8.1, Microsoft introduced a Metro-style calculator to replace its traditional Calculator.  In Windows 10 non-LTSB/LTSC/Server editions, the traditional Calculator was entirely removed and replaced with a UWP (Universal Windows Platform) App version.  This new UWP Calculator introduced a fairly bloated UI many users were simply not fond of and much preferred the simplicity of the traditional Calculator (now labeled Win32Calc.exe).  Unfortunately, Microsoft never added the ability to revert back to the traditional Calculator nor released a downloadable package to install the traditional Calculator.

What Optimize-Offline does to remedy this:

For Windows builds 17763 and above, the OEM cabinet packages extracted from Windows 10 Enterprise LTSC 2019 are applied to the image. For builds lower than 17763, a custom created cabinet package, incorporating the latest win32calc.exe and language file, is expanded into the image and the ACL SSDLs (security descriptors) are edited so they're identical to the SSDLs applied by the OEM cabinet packages. This allows for proper system management and user control. Optimize-Offline then creates the proper Win32Calc link and adds the Win32Calc link to the appropriate .ini system file (this is a hidden system file located in every directory that has a list of all the linked programs within said directory).

Optimize-Offline can implement the traditional Calculator using the latest Win32Calc.exe, language files and Package Features found in the Windows 10 Enterprise LTSC 2019 edition.

## ISO File Strucuture Optimization ##

This is a process that occurrs automatically when a Windows Installation ISO is used as the source image for optimization. In short, it removes all unnecessary media files used to install Windows 10 from a live system, thus reducing the total size of the installation media. The steps that it takes to optimize the file structure should NOT be changed, as the order they're written are critical to proper file structure optimization for bootup installation.

## ISO Remastering and Creation ##

When a Windows Installation ISO is used as the source image for optimization, Optimize-Offline expands the entire media content of the ISO. Using the -ISO switch will tell Optimize-Offline to automatically create a new Windows Installation Media ISO once all optimizations have been processed but only if the Windows ADK (Assessment and Deployment Kit) is installed on the system. If the Windows ADK is not installed on the system, Optimize-Offline will simply bypass the creation of the ISO without displaying an error or producing any optimization failures.

Optimize-Offline does this without any end-user input by querying specific registry keys that contain the path to the ADK's installed location and then joins the absolute paths to the ADK boot files. Once it tests that the Oscdimg location exists, it silently passes the appropriate command-line arguments to the oscdimg executable that apply the proper bootcode and switches to create a new bootable Windows Installation Media ISO.

Optimize-Offline uses the Edition ID of the image that was optimized as the name of the ISO and the Display Name as its label.

## About the Defaultuser0 ghost account ##

Any time an OEM Windows Image is modified offline, or the System Preparation, Reset and Provisioning Package deployment features are used, there is a chance this ghost account will surface.
defaultuser0 is not a real account, however, and is a bug that has been present in Windows through countless flavors and variations. It is not added to any user groups nor does it even have a profile.
Conversely, failing to remove the defaultuser0 account immediately after Windows Installation completes can lead to future headaches.  As an example, if you reset Windows with the defaultuser0 ghost account still present, upon the restart of the device, Windows will force you to log into the defaultuser0 account to continue.

In earlier versions of Optimize-Offline, a specific registry key was appended to allow for elevated control over the defaultuser0 account which allowed for its manual removal, as well as a SetupComplete.cmd script code that automatically removed it. However, with the newer builds (17134+), this is no longer required and simply rebooting the newly installed OS will automatically remove the defaultuser0 account from the 'Users' directory without having to manually remove it.

**A reboot is recommended after the first bootup of the optimized image in order to complete the DefaultUser0 ghost account removal**.

## Microsoft Store side-loading ##

For Windows 10 Enterprise LTSC 2019, the Microsoft Store can be side-loaded into the image since this flavor of Windows (like Windows 10 Enterprise LTSB 2015-2016) does not contain any Metro Apps in its OEM state. There is no additional procedure required once the optimized Windows 10 LTSC 2019 is installed, and the Windows Store will be displayed in the Start Menu. Though I try to keep these packages as up-to-date as possible, it's best to update them on the live system to get the absolute latest version of the Windows Store package and any of its dependencies. With this, you can download, install and use any and all Metro Apps all other Windows 10 flavors can.

## Microsoft Edge side-loading ##

For Windows 10 Enterprise LTSC 2019, Microsoft's flagship browser - Microsoft Edge - can be side-loaded into the image since this flavor of Windows (like Windows 10 Enterlrise LTSB 2015-2016) does not contain Microsoft Edge in its default state. Be aware, that one of the System Applications that can be removed are Windows Edge Development Tools, so if you plan to use any tools for Microsoft Edge development, it's recommended to not remove this System Application.

Again, I try to keep these packages up-to-date with their latest packages.

## Optimize-Offline best practices ##

- Only OEM images should be used for optimization and not images that have already been modified by other scripts and/or programs.
- If maintaining fully updated OEM images, it's best to integrate offline updates into the image and then run Optimize-Offline.  It is not recommended to optimize an image and then integrate offline updates.
- Do not run any other programs or scripts - or manually run commands - that can interact with either the working directories of the script or the registry while the script is optimizing.
- Do not manually meddle in either the working directories nor the registry while it's optimizing an image.

## How to call Optimize-Offline ##

The easist way to call Optimize-Offline is by using the provided Start.cmd script. Right-click the script and edit the variables to accommodate your optimization requirements. You can enter the full paths to driver locations, the source image, NetFx3 packets, etc. Then simply add or remove the parameters and switches to the line that calls Optimize-Offline. Once finished, simply right click the Start.cmd script and select "Run as Administrator" and it will call Optimize-Offline and pass all the variables, parameters and switches to the PowerShell script. This allows the end-user to quickly call Optimize-Offline without having to manually input the paths, parameters and switches each time an image is to be optimized.

The second way is to open an elevated PowerShell console shell and navigate to the root directory of the Optimize-Offline script and then dot source the script, followed by the paths, parameters and switches required for optimization:
> .\Optimize-Offline.ps1 -ImagePath "D:\WIM Files\Win10Pro_Full.iso" -MetroApps "Select" -SystemApps -Packages -Features -Registry -Win32Calc -DaRT -Drivers "D:\Driver Packages"
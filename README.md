# Optimize-Offline #

Optimize-Offline is a Windows Image (WIM) optimization script designed for Windows 10 builds RS2 to RS5 64-bit architectures.

## About Optimize-Offline ##

- Primary focus' are the removal of unnecessary bloat, privacy and security enhancements, cleaner aesthetics, increased performance and a significantly better user experience.
- Accepts either a full Windows 10 installation ISO, or a Windows 10 install.wim file.
- Does not perform any changes to an installed or live system nor can it optimize a live system.
- Makes multiple changes to both the offline system and registry hives to enhance security, usability and privacy while also improving performance.
- Checks the health of the image both before and after the script runs to ensure the image retains a healthy status.
- Detects what System Applications were removed, and further removes any associated drivers or services associated with them.
- Generates a SetupComplete.cmd script based on System Application removal, to further disable any Scheduled Tasks and the like that are enabled by default during Windows installation.
- Allows offline removal of default Windows Packages and the disabling of Windows Features.

## Script disclaimer ##

- It is the responsibility of the end-user to be aware of what each parameter and switch does.
- Optimize-Offline is designed to optimize OEM images and not images already optimized by another script/program.
- Properties, features, packages, etc. can and often do change between builds (i.e. RS3 to RS4).  This means that when optimizing an image, the script may warn of an error during the optimization process that did not occur before or stop the optimization process entirely.

## About the -Registry parameter ##

The -Registry parameter applies an array of entries and values to the image's registry hives designed to further enhance both the security of the default image as well as its usability and aesthetics.
The script only applies those registry entries and values applicable to the image build being optimized and bypasses those that are unsupported.
A few of the switch settings:

- Completely disables Cortana without removing the default search feature.
- Disables a significant amount of telemetry, logging, tracking, monitoring and background feedback submission.
- Prevents bloatware link creation and disables a plethora of annoying default features.
- Disables Windows' annoying pop-up notifications and tips.
- Disables non-explicit application and system sensor access.
- Disables error reporting and automatic syncronization.
- Improves the default aesthetics by cleaning-up redundant or unused links in the default Control Panel and Immersive Control Panel.
- etc.

## About the SetupComplete.cmd script ##

The SetupComplete.cmd is a setup script that automatically runs after the OOBE component pass completes during the setup of a new Windows 10 installation. It includes the further automatic disabling of tasks for services or applications that were removed and the implementation of firewall rules to block telemetry. It also includes the automatic detection and removal of the DefaultUser0 ghost account that can often times be created.

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

Optimize-Offline can implement the traditional Calculator using the latest Win32Calc.exe, language files and Package Features found in the Windows 10 Enterprise LTSC 2019 edition.

## About the Defaultuser0 ghost account ##

Any time an OEM Windows Image is modified offline, or the System Preparation, Reset and Provisioning Package deployment features are used, there is a chance this ghost account will surface.
defaultuser0 is not a real account, however, and is a bug that has been present in Windows through countless flavors and variations. It is not added to any user groups nor does it even have a profile.
Conversely, failing to remove the defaultuser0 account immediately after Windows Installation completes can lead to future headaches.  As an example, if you reset Windows with the defaultuser0 ghost account still present, upon the restart of the device, Windows will force you to log into the defaultuser0 account to continue.

Optimize-Offline remedies this issue by first setting the proper key property in the offline registry hives that enables non-elevated removal of the defaultuser0 ghost account, and second by adding a function in the SetupComplete.cmd script that queries the registry for the SID of the defaultuser0 ghost account, and then proceeding to remove the account, registry keys and profile directories automatically if that SID is found.
This ensures the defaultuser0 ghost account, if present, is always entirely removed immediately after the installation of Windows.

**A reboot is recommended after the first bootup of the optimized image in order to complete the DefaultUser0 ghost account removal**.

## Optimize-Offline best practices ##

- Only OEM images should be used for optimization and not images that have already been modified by other scripts and/or programs.
- If maintaining fully updated OEM images, it's best to integrate offline updates into the image and then run Optimize-Offline.  It is not recommended to optimize an image and then integrate offline updates.
- Do not run any other programs or scripts - or manually run commands - that can interact with either the working directories of the script or the registry while the script is optimizing.
- Do not manually meddle in either the working directories nor the registry while it's optimizing an image.
# Optimize-Offline
Optimize-Offline is a Windows Image (WIM) optimization script designed for Windows 10 Creator's Update builds RS2, RS3 and RS4 64-bit architectures.

# What is Optimize-Offline about?
- Primary focus' are the removal of unnecessary bloat, privacy and security enhancements, cleaner aesthetics, increased performance and a significantly better user experience.
- Does not perform any changes to an installed or live system nor can it optimize a live system.
- Makes multiple changes to both the offline system and registry hives to enhance security, usability and privacy while also improving performance.
- Checks the health of the image both before and after the script runs to ensure the image retains a healthy status.
- Detects what System Applications were removed, and further removes any associated drivers or services associated with them.
- Adds removed System Applications' scheduled tasks to the SetupComplete script to be automatically disabled during Windows installation.
- Optional Features and Windows Packages can be removed and/or disabled by adding them to the editable field list and using their respective switches.

# Is this script safe for me?
It is the responsibility of the end-user to be aware of what each parameter and switch does.

# What does the -SetRegistry and -Harden switches do specifically?
The -SetRegistry switch applies an array of registry entries and values designed to further enhance both the security of the default image as well as its usability and aesthetics. For example, it completely disables Cortana without completely disabling the default search feature, disables a significant amount of telemetry and background feedback submission, removes bloatware link creation and disables a plethora of annoying default features.

The -Harden switch introduces a few additional registry entries and values that disable Provisioned Application and System Application access to various device sensors that are not specifically granted.

# What does the SetupComplete.cmd script do?
The SetupComplete.cmd is a setup script that automatically runs after the OOBE component pass completes during the setup of a new Windows 10 installation. It includes further automatically disabling of tasks for services or applications that were removed. It also includes an automatic detection and removal of the "DefaultUser0" ghost account that can often times be created. A reboot is recommended after the first bootup of the optimized image in order to complete the "DefaultUser0" ghost account removal.

# Are any of these settings dangerous?
No, none of the automatic processes are dangerous; however one must be careful when selecting what System Applications are removed, as the removal of some can render undesirable effects.

# How does the System Application removal work?
System Applications are a lot like Provisioned Application Packages in respect that they are provisioned and installed during the setup of Windows. During the WindowsPE component pass, setup looks for these System Applications in the default registry and provisiones them for installation only if their entries are present. By removing their respective registry entries, Windows Setup does not provision them for installation.

This method is safer than force removing the System Application using its component package, as the force removal of numerous System Applications' component packages can trip the dreaded "STATUS_SXS_COMPONENT_STORE_CORRUPT"  flag. This is a critical component store corruption flag that will then be detected by any servicing command and Windows Update and prevent both the servicing and updating of the Operating System. The only way to remedy and fix this error is to re-install the Operating System.

The upcoming GUI version of Optimize-Offline has full component package removal by both changing the permanency values of packages and using the DISM.API to allocate them and then remove them.

# What System Applications are universally safe, and recommended, to remove?
This can vary, depending on the end-user's final image requirements, but SecHealthUI (Windows Defender), ParentalControls, ContentDeliveryManager, MicrosoftEdge, PPIProjection, HolographicFirstRun, BioEnrollment (if no Biometrics will be used), SecureAssessmentBrowser and (optionally) XboxGameCallableUI are all safe to remove. XboxGameCallableUI should only be removed if all Xbox Provisioned Application Packages are also removed and will not be used (see below). Moreover, Cortana can also be removed; however, doing so will render the default search feature inoperable so its removal is only recommended if the end-user will be using a 3rd party search program like ClassicShell.

ShellExperienceHost should never be removed.

# Should any Provisioned Application Packages (Metro Apps) not be removed?
The removal of Xbox.TCUI and Xbox.IdentityProvider will prevent the Windows Store Apps Troubleshooter from working properly and likewise affect the Windows Store. It is not recommended to remove these if the Windows Store is required in the image.

# Will Microsot DaRT 10 be implemented again?
Yes, Microsoft DaRT 10, as well as the Microsoft Debugging Tools, will be implemented into both the script and the GUI version.

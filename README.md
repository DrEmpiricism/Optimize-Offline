# Optimize-Offline #

Optimize-Offline is a Windows Image (WIM) optimization script designed for Windows 10 versions 1803-to-1909 64-bit architectures.

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

## Script Disclaimer ##

- Latest releases of Optimize-Offline can be found [here](https://github.com/DrEmpiricism/Optimize-Offline/releases)
- It is the responsibility of the end-user to be aware of what each parameter and switch does. These are well detailed in Optimize-Offline's header.
- Optimize-Offline is designed to optimize OEM images and not images already optimized by another script/program.
- Not all integrations are available for languages outside of en-US.
- Properties, features, packages, etc. can and often do change between builds. This means that when optimizing an image, the script could warn of an error during the optimization process that did not occur before.
- Just because something can be removed does not mean it should be removed. Haphazard removal of System Applications can cause errors during Windows 10 setup.
- Support will not be given to users who attempt to optimize unsupported builds or previously modified images.

## Optimize-Offline Best Practices ##

- Only OEM images should be used for optimization and not images that have already been modified by other scripts and/or programs.
- If maintaining fully updated OEM images, it's best to integrate offline updates into the image BEFORE running Optimize-Offline.
- To ensure package removals and integrations are retained, it's best to update an offline image with the latest Servicing Stack Update(s) and Monthly Cumulative Update before optimizing it.
- Do not run any other programs or scripts - or manually run commands - that can interact with either the working directories of the script or the registry while the script is optimizing.
- Optimize-Offline requires PowerShell version 5.0 and a 64-bit environment.
- Read the ReadMe files in the 'Content\Additional' directories for important information regarding user-specific content.

## Switches and Parameters ##

### About System Applications ###

System Applications are a lot like Provisioned Application Packages (Windows Apps) in respect that they are provisioned and installed during the setup of Windows. During the Windows Setup component pass, setup looks for these System Applications in the default registry and provisions them for installation only if their entries are present. By removing these entries, Windows Setup does not provision them for installation.

This method is safer than force removing the System Application using its component package because it retains the default file structure. Furthermore, the force removal of System Applications' component packages can trip the dreaded "STATUS_SXS_COMPONENT_STORE_CORRUPT" flag. This is a critical component store corruption flag that will then be detected by any servicing command and Windows Update and prevent both the servicing and updating of the Operating System. The only way to remedy and fix this error is to re-install or reset the Operating System.

Four System Applications use a GUID namespace instead of an identifiable package name:

- 1527c705-839a-4832-9118-54d4Bd6a0c89 = Microsoft.Windows.FilePicker
- c5e2524a-ea46-4f67-841f-6a9465d9d515 = Microsoft.Windows.FileExplorer
- E2A4F912-2574-4A75-9BB0-0D023378592B = Microsoft.Windows.AppResolverUX
- F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE = Microsoft.Windows.AddSuggestedFoldersToLibraryDialog

#### System Applications universally safe to remove ####

The following System Applications are safe to remove:

- BioEnrollment (provided no biometrics will be used)
- CallingShellApp
- MicrosoftEdge
- MicrosoftEdgeDevToolsClient
- SecHealthUI
- ContentDeliveryManager
- ParentalControls
- SecureAssessmentBrowser
- XGpuEjectDialog
- XboxGameCallableUI

Cortana can also be removed, though doing so will render the default search feature inoperable and is only recommended if a 3rd party search program like Classic Shell will be used.

**Some System Applications are required during the OOBE setup pass and their removal can cause setup to fail. Do not remove any System Application if you're unsure of its impact on a live system.**

### About Windows Capabilities and Packages ###

The -Capabilities switch allows for the removal of Features on Demand (FOD) installed in the image and the -Packages switch allows for the removal of Windows Cabinet File Packages.

Like with all removals, care must be taken when using either of these switches, primary the -Packages switch. Do not remove any Capability or Package if you are unaware of its impact on a live installation. It's recommended to read the  [Features on Demand Document](https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-v2--capabilities) to better understand their functions.

### About Registry Optimizations ###

The -Registry switch applies an array of entries and values to the image registry hives designed to further enhance both the security of the default image as well as its usability and aesthetics.
The script only applies those registry entries and values applicable to the image build being optimized and bypasses those that are unsupported. Conversely, Optimize-Offline will apply additional entries and values to accommodate any application removal or integration. Optimize-Offline does not apply any Group Policy entries that are not available in the specific image by default, as this would just add unnecessary bloat to the registry itself with zero functionality.

A short list of some of the optimizations include:

- Completely disables Cortana without disabling the default search feature.
- Disables a significant amount of telemetry, logging, tracking, monitoring and background feedback submission.
- Prevents bloatware link creation and disables a plethora of annoying default features.
- Disables Windows' annoying pop-up notifications and tips.
- Disables non-explicit application and system location sensor access.
- Disables background error reporting and automatic synchronization to Microsoft.
- Disables the automatic creation of tabs and icons for Microsoft Edge.
- Disables intrusive Microsoft feedback and notification queries.
- Cleans-up the default Context Menu.

### About the SMB1 File Sharing Protocol and Windows PowerShell 2.0 Optional Features ###

When optimizing an image with Optimize-Offline, curiosity may arise as to why the SMB1 Protocol and Windows PowerShell 2.0 Optional Features are automatically disabled. In short, Microsoft has labeled both of them a security risk.

- The SMB1 Protocol is vulnerable to [Ransomware propagation](https://techcommunity.microsoft.com/t5/Storage-at-Microsoft/Stop-using-SMB1/ba-p/425858).
- Windows PowerShell 2.0 can be used to run malicious scripts and has been [depreciated since Windows 10 version 1709](https://devblogs.microsoft.com/powershell/windows-powershell-2-0-deprecation/).

### About Additional Content ###

When the -Additional switch it used, any content specified in its configuration file (Config.ini) will be integrated into the image. This eliminates the need to use an external Distribution Share to integrate content.

Within the '\Content\Additional' directory are seven folders: 'Drivers', 'LockScreen', 'RegistryTemplates', 'Setup', 'SystemLogo', 'Unattend' and 'Wallpaper', and one configuration file: Config.ini. The script automatically checks each folder to ensure the file-types are valid for the type of content being added to the image. Aside from the 'Drivers' and 'RegistryTemplates' folders, content validation is based on Microsoft's deployment guidelines. Any content located in the 'Setup' folder will be copied because what a user implements during the setup of their device can be an array of different container types - files, directories, executables, etc.

All content that gets copied to the image are copied to the locations that are in accordance with Microsoft's deployment guidelines. For example, any system logo is copied to '\Windows\System32\oobe\info\logo', wallpaper is copied to '\Windows\Web\Wallpaper', setup content is copied to '\Windows\Setup\Scripts' and an unattend.xml is copied to '\Windows\Panther' after it is applied to the image itself (this is detailed more below).

Content can be in the form of files, folders or directories. If, for example, you want a wallpaper directory called 'Custom', Optimize-Offline will copy the added 'Custom' directory - and all contents therein - to the '\Windows\Web\Wallpaper' directory while keeping its original file structure. Content is NOT copied haphazardly nor are original file structures ignored.

#### Registry Template Integration ####

Any custom registry template (.reg) file to be imported into the offline image's registry hives can be placed in the '\Content\Additional\RegistryTemplates' folder. No editing of these template files is required and Optimize-Offline will copy and edit them accordingly to apply them to the appropriate hives.

#### Adding Drivers ####

Any driver package to be added to the offline image can be placed in its respective folder in the '\Content\Additional\Drivers' directory. Within this directory you can select whether a driver package is added to just the Windows Installation (install.wim), or also to the Windows Setup and Windows Recovery environments. Either single .inf files or full driver package folders are supported.

#### Adding an Answer File ####

When an unattend.xml answer file is added to the '\Content\Additional\Unattend' folder, Optimize-Offline applies the answer file directly to the image, creates the '\Windows\Panther' directory within the image and finally copies the answer file to it. "Panther" was the code-name for a servicing and setup engine that began with Windows Vista and has remained as such since.

During Windows installation, Windows Setup automatically looks for answer files for custom installations in certain locations.  %WINDIR%\Panther and the installation media are the first locations checked for an answer file. An unattend.xml located in the %WINDIR%\Panther directory will act just like an autounattend.xml does and can contain all the same content. This is an alternative way to run a custom answer file for Windows Setup automatically as opposed to setting an autounattend.xml to the root of the installation media type being used. Moreover, you can also use multiple answer files by applying one to the image and adding an autounattend.xml to the bootable media. For example, the unattend.xml applied to the image can contain OOBE and Windows Setup parameters while the autounattend.xml can contain only parameters for the WindowsPE pass that sets up the partitions and disks for installation.

It is recommended to create an unattend.xml using the Windows System Image Manager that is included in the Windows ADK. Though there are some online answer file generators that will "quickly" create an unattend.xml for you, just like with Windows 10 features, answer file variables can change between builds. Likewise, having faulty or unsupported variables in an answer file can prevent Windows Setup from completing.

It is also in good practice to have a good idea what each Configuration Pass does and what actions its child parameters takes during the Windows setup process. All information regarding Configuration Passes can be found in the [Microsoft Document](https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-automation-overview)

**Having incorrect, null or incomplete values in your answer file, most notably the WindowsPE Configuration Pass, WILL prevent Windows from completing its setup or even starting its setup. If a custom disk layout is included for installation, make certain the proper drive index numbers, partition type IDs and sizes are entered.**

### About Microsoft DaRT 10 ###

Integrates the Microsoft 10 Diagnostic and Recovery Toolset with additional debugging tools. Since these tools run in a Preinstallation Environment and are quite powerful, it's wise to be aware of what they do prior to using them and to NOT integrate them into images that will be used by multiple people.

> Microsoft Diagnostics and Recovery Toolset (DaRT) 10 lets you diagnose and repair a computer that cannot be started or that has problems starting as expected. By using DaRT 10, you can recover end-user computers that have become unusable, diagnose probable causes of issues, and quickly repair unbootable or locked-out computers. When it is necessary, you can also quickly restore important lost files and detect and remove malware, even when the computer is not online. [Microsoft Document](https://docs.microsoft.com/en-us/microsoft-desktop-optimization-pack/dart-v10/)

### About Win32Calc ###

Starting in Windows 8.1, Microsoft introduced a Metro-style calculator to replace its traditional Calculator.  In Windows 10 non-LTSB/LTSC/Server editions, the traditional Calculator was entirely removed and replaced with a UWP (Universal Windows Platform) App version.  This new UWP Calculator introduced a fairly bloated UI many users were simply not fond of and much preferred the simplicity of the traditional Calculator (now labeled Win32Calc.exe).  Unfortunately, Microsoft never added the ability to revert back to the traditional Calculator nor released a downloadable package to install the traditional Calculator.

### About Data Deduplication ###

> Data Deduplication, often called Dedup for short, is a feature of Windows Server 2016 that can help reduce the impact of redundant data on storage costs. When enabled, Data Deduplication optimizes free space on a volume by examining the data on the volume by looking for duplicated portions on the volume. Duplicated portions of the volume's dataset are stored once and are (optionally) compressed for additional savings. Data Deduplication optimizes redundancies without compromising data fidelity or integrity. [Microsoft Document](https://docs.microsoft.com/en-us/windows-server/storage/data-deduplication/overview)

With Optimize-Offline, the Data Deduplication packages and Dedup-Core Windows Feature can be integrated into the offline image. PowerShell can then be used to enable and manage Data Deduplication using its storage cmdlets. More information is available from its [Microsoft Document](https://docs.microsoft.com/en-us/powershell/module/deduplication/?view=win10-ps)

### About Developer Mode ###

Developer Mode is a Windows Setting that, when enabled, allows the end-user to test any unsigned UWP app, use the Ubuntu Bash shell environment and offers optimizations for Windows Explorer, Remote Desktop and PowerShell. It is also a requirement when writing certain code in Visual Studio.

Enabling Developer Mode also installs Device Portal and Device Discovery, though they must be manually toggled on in the Settings in order for them to be enabled. Enabling Device Portal will reconfigure the default firewall rules to allow incoming connections, as Device Portal is a feature allowing for the system to act as a local web server for other devices on the local network. This is used for developing, deploying and debugging apps. Enabling Device Discovery allows devices to pair with Device Portal.

Developer Mode should ONLY be enabled on systems that require settings it provides. More information is available from its [Microsoft Document](https://docs.microsoft.com/en-us/windows/uwp/get-started/enable-your-device-for-development)

### Integrating Windows Store ###

For Windows 10 Enterprise LTSC 2019, the latest Windows Store package bundle and dependency packages can be integrated into the image, as this flavor of Windows (like Windows 10 Enterprise LTSB 2015-2016) does not contain any Windows Apps in its OEM state. There is no additional procedure required once the optimized Windows 10 LTSC 2019 is installed, and the Windows Store will be displayed in the Start Menu.

### Integrating Microsoft Edge ###

For Windows 10 Enterprise LTSC 2019, Microsoft's flagship browser - Microsoft Edge - can be integrated into the image since this flavor of Windows (like Windows 10 Enterprise LTSB 2015-2016) does not contain Microsoft Edge in its OEM state.

### Solid Image Compression ###

Solid image compression uses the undocumented LZMS compression format to concatenate all file data within a regular WIM file into a solid WIM archive (ESD file). By doing this, a 4GB WIM file is able to be compressed to a size of 2GB or less. However, as with other forms of high-ratio compression, LZMS compression can take quite a while to complete and should NOT be selected as the final image compression type if the end-user is impatient or requires the optimized image quickly.

### ISO File Structure Optimization ###

This is a process that occurs automatically when a Windows Installation ISO is used as the source image for optimization. In short, it removes all unnecessary media files used to install Windows 10 from a live system, thus reducing the total size of the installation media. The order in which files are removed and moved is critical for proper file structuring.

### ISO Remastering and Creation ###

When a Windows Installation Media ISO is used as the source image for optimizing, Optimize-Offline expands the entire media structure of the ISO into its own directory and allows for the creation of a new bootable Windows Installation Media ISO containing the newly optimized Windows Image after all processes have completed.

The -ISO parameter allows for two values to be passed to it: 'Prompt' and 'No-Prompt.' This value sets the binary bootcode the image will be created with. An ISO created with the 'No-Prompt' bootcode will not require a keypress to begin Windows Setup allowing for a completely unattended Windows installation, while an ISO created with the 'Prompt' bootcode will require a keypress before Windows Setup will start.

Optimize-Offline calls the COM IMAPI2 interface for file system image building and also opens a binary stream that writes a bootfile sector code to the ISO. This allows for bootable Windows Installation Media ISO creation without the need for 3rd party tools like oscdimg.

### About Defaultuser0 ###

Any time an OEM Windows Image is modified offline, or the System Preparation, Reset and Provisioning Package deployment features are used, there is a chance this ghost account will surface.
defaultuser0 is not a real account, however, and is a bug that has been present in Windows through countless flavors and variations. It is not added to any user groups nor does it even have a profile.
Conversely, failing to remove the defaultuser0 account immediately after Windows Installation completes can lead to future headaches.  As an example, if you reset Windows with the defaultuser0 ghost account still present, upon the restart of the device, Windows will force you to log into the defaultuser0 account to continue.

In earlier versions of Optimize-Offline, a specific registry key was appended to allow for elevated control over the defaultuser0 account which allowed for its manual removal, as well as a SetupComplete.cmd script code that automatically removed it. However, with the newer builds (17134+), this is no longer required and simply rebooting the newly installed OS will automatically remove the defaultuser0 account from the 'Users' directory without having to manually remove it.

## Calling Optimize-Offline ##

The easiest way to call Optimize-Offline is by using the provided [Optimize-Offline.cmd script](https://github.com/DrEmpiricism/Optimize-Offline/blob/master/Optimize-Offline.cmd). Right-click the script and 'Open with Notepad,' then edit any variables to accommodate your optimization requirements. Once finished, save any changes and right click the Optimize-Offline.cmd script and select 'Run as Administrator' and it will call Optimize-Offline and pass all the variables, parameters and switches to the PowerShell script. This allows the end-user to quickly call Optimize-Offline without having to manually input the paths, parameters and switches each time an image is to be optimized.

The second way is to open an elevated PowerShell console shell and navigate to the root directory of the Optimize-Offline script and then dot source the script, followed by the paths, parameters and switches required for optimization:

- .\Optimize-Offline.ps1 -SourcePath "D:\ISO Files\Win10Pro_Full.iso" -WindowsApps "Whitelist" -SystemApps -Capabilities -Packages -Features -Registry -Win32Calc -Dedup -DaRT "Setup" -Additional -ISO "No-Prompt"
- .\Optimize-Offline.ps1 -SourcePath "D:\ISO Files\WIN_10_PFW.iso" -WindowsApps "All" -SystemApps -Capabilities -Features -Registry -Win32Calc -Dedup -DaRT "All" -ISO "Prompt"
- .\Optimize-Offline.ps1 -SourcePath "D:\WIM Files\LTSC 2019\install.wim" -SystemApps -Capabilities -Packages -Features -DeveloperMode -WindowsStore -MicrosoftEdge -DaRT "Recovery" -Additional

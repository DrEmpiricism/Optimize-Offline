# Optimize-Offline

Optimize-Offline is a Windows Image (WIM/ESD) optimization module designed for Windows 10 versions 1803-to-2009 64-bit architectures.

## About Optimize-Offline

- Expands the user experience by eliminating unnecessary bloat, enhancing privacy, improving aesthetics and increasing system performance.
- Accepts either a full Windows 10 Installation Media ISO, Windows 10 WIM, SWM or ESD file.
- Does not perform any changes to a live system or running environment.
- Checks the integrity and health of the image both before and after optimizations are processed to ensure the image retains a healthy status.
- Allows for the deprovisioning and removal of Provisioned Application Packages, System Applications, Capability Packages, Windows Cabinet Package Files, Optional Features and more.
- Detects what Provisioned and System Applications were removed and further cleans-up any associated drivers, services and integrated content associated with them.
- Allows for the integration of drivers, Microsoft DaRT 10, Windows Store, Microsoft Edge, Developer Mode, Win32 Calculator, Data Deduplication and more.
- All optimization processes are done silently with internal error-handling.
- All images are optimized independently - without the need for 3rd party programs - by utilizing custom module resources.

## Module Disclaimer

- The latest releases of Optimize-Offline can be found [here](https://github.com/DrEmpiricism/Optimize-Offline/releases).
- It is the responsibility of the end-user to be aware of what each parameter value does, which are all well documented in the [Module Help Topics and Optimization Details](docs/Optimize-Offline-help.md).
- Optimize-Offline is designed to optimize OEM images and not images already optimized by another script or program.
- Optimize-Offline is designed for an en-US host environment.
- Just because something can be removed does not mean it should be removed. Haphazard removal of packages or features can prevent Windows 10 Setup from completing or cause runtime errors.
- Support will not be given to users who attempt to optimize unsupported builds, previously modified images or modify the default code to circumvent edition requirements.

## Optimize-Offline Best Practices

- Before optimizing an image, read the [Module Help Topics and Optimization Details](docs/Optimize-Offline-help.md).
- Keep the project file stucture in its default state.
- Only OEM images should be used for optimization and not images that have already been modified by other scripts or programs.
- If maintaining fully updated OEM images, it is best to integrate offline updates into the image BEFORE running Optimize-Offline.
- Do not run any other programs or scripts - or manually run commands - that can interact with either the working directories of the module or the registry while optimizations are processing.

## Parameters

### About System Applications

System Applications are a lot like Provisioned Application Packages (Windows Apps) in respect that they are provisioned and installed during the setup of Windows. During the Windows Setup component pass, setup looks for these System Applications in the default registry and provisions them for installation only if their entries are present. By removing these entries, Windows Setup does not provision them for installation.

This method is safer than force removing the System Application using its component package because it retains the default file structure. Furthermore, the force removal of System Applications' component packages can trip the dreaded "STATUS_SXS_COMPONENT_STORE_CORRUPT" flag. This is a critical component store corruption flag that will then be detected by any servicing command and Windows Update and prevents both the servicing and updating of the Operating System. The only way to remedy and fix this error is to re-install or reset the Operating System.

#### System Applications universally safe to remove

The following System Applications are safe to remove:

- BioEnrollment (provided no biometrics will be used)
- CallingShellApp (provided no mobile phone will be linked to the device)
- MicrosoftEdge (has been replaced by Microsoft Edge Chromium, which is detailed more below)
- MicrosoftEdgeDevToolsClient
- PPIProjection
- SecHealthUI
- ContentDeliveryManager
- FileExplorer
- NarratorQuickStart
- ParentalControls
- SecureAssessmentBrowser
- XGpuEjectDialog
- XboxGameCallableUI (provided no integrated Xbox gaming features will be used)
- UndockedDevKit
- NcsiUwpApp

Cortana can also be removed, though doing so will render the default search feature inoperable and is only recommended if a 3rd party search program like Classic Shell will be used.

**Some System Applications are required during the OOBE setup pass and their removal can cause setup to fail. Do not remove any System Application if you're unsure of its impact on a live system.**

### About Windows Capabilities and Packages

The Capabilities parameter allows for the removal of Features on Demand (FOD) installed in the image and the Packages parameter allows for the removal of Windows Cabinet File Packages.

Like with all removals, care must be taken when using either of these removal parameters, particularly the Packages parameter. Do not remove any Capability or Package if you are unaware of its impact on a live installation. It is recommended to read the [Features on Demand Document](https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-v2--capabilities) to better understand their functions.

### About Registry Optimizations

The Registry parameter applies an array of entries and values to the image registry hives designed to further enhance both the security of the default image as well as its usability and aesthetics.
The module only applies those registry entries and values applicable to the image build being optimized and bypasses those that are unsupported. Likewise, Optimize-Offline will apply additional entries and values to accommodate any application removal or integration. Optimize-Offline does not apply any Group Policy entries that are not available in the specific image edition by default, as this would just add unnecessary bloat to the registry itself with zero functionality.

A short list of some of the optimizations include:

- Completely disables Cortana without disabling the default search feature.
- Disables history collection and Bing Search integration by the default search feature.
- Disables a significant amount of telemetry, logging, tracking, monitoring and background feedback submission.
- Prevents bloatware link creation and disables a plethora of annoying default features.
- Disables Windows' annoying pop-up notifications and tips.
- Disables non-explicit application and system location sensor access.
- Disables background error reporting and its automatic synchronization to Microsoft.
- Disables the automatic creation of tabs and icons for Microsoft Edge.
- Disables intrusive Microsoft feedback and notification queries.
- Cleans-up the default Context Menu.

### About the SMB1 File Sharing Protocol and Windows PowerShell 2.0 Optional Features

When optimizing an image with Optimize-Offline, curiosity may arise as to why the SMB1 Protocol and Windows PowerShell 2.0 Optional Features are automatically disabled. In short, Microsoft has labled both of them a security risk.

- The SMB1 Protocol is vulnerable to [Ransomware propagation](https://techcommunity.microsoft.com/t5/Storage-at-Microsoft/Stop-using-SMB1/ba-p/425858).
- Windows PowerShell 2.0 can be used to run melicous scripts and has been [depreciated since Windows 10 version 1709](https://devblogs.microsoft.com/powershell/windows-powershell-2-0-deprecation/).

### About Additional Content

When the Additional parameter is used, user-specific content added to the "Content/Additional" directory will get integrated into the image when enabled within the hashtable. This eliminates the need to use an external Distribution Share.

All content that gets transfered to the image are copied to locations that are in accordance with Microsoft's deployment guidelines. For example, any system logo is copied to '\Windows\System32\oobe\info\logo', wallpaper is copied to '\Windows\Web\Wallpaper', setup content is copied to '\Windows\Setup\Scripts' and an unattend.xml is copied to '\Windows\Panther' after it is applied to the image itself (this is detailed more below).

Content can be in the form of files, folders or directories, unless a specific filetype is required. Content is NOT copied haphazardly nor are original file structures ignored.

#### Registry Template Integration

Custom registry template (.reg) files placed in the '\Content\Additional\RegistryTemplates' folder are imported by Optimize-Offline into the offline image's appropriate registry hive.

***Note:***
To qualify for Optimize-Offline hive import, all custom registry template additions are constrained to having unrestricted permissions. If any key change included in a custom registry template addition requires restricted access, the entire Optimize-Offline script fails without notice and without any descriptive warning. The solution is to remove any registry key change that requires access to protected registry keys.

> Registry templates that users can add to be automatically imported into the offline registry hives are not granted the token privileges required for access to protected registry keys. Only certain values applied by the script itself are granted these privileges. [GitHub-DrEmpiricism](https://github.com/DrEmpiricism/Optimize-Offline/issues/136#issuecomment-554158335)

#### Adding Drivers

Any driver package to be injected into the offline image can be placed in its respective folder in the '\Content\Additional\Drivers' directory. Within this directory you can select whether a driver package is added to just the Windows Installation, or also to the Windows Setup and Windows Recovery environments. Either single .inf files or full driver packages are supported.

#### Adding an Answer File

When an unattend.xml answer file is added to the '\Content\Additional\Unattend' folder, Optimize-Offline applies the answer file directly to the image, creates the '\Windows\Panther' directory within the image and finally copies the answer file to it. "Panther" was the code-name for a servicing and setup engine that began with Windows Vista and has remained as such since.

During Windows installation, Windows Setup automatically looks for answer files in specific locations for custom installations.  The %WINDIR%\Panther directory and the installation media are the first locations checked for an answer file. An unattend.xml that gets applied directly to the image, and is located in the %WINDIR%\Panther directory, will act identically to an autounattend.xml placed on the installation media does with the exception of the WindowsPE configuration pass. Since the WindowsPE configuration pass configures disk partitions and layouts, an answer file containing these parameters must be placed in an autounattend.xml. Additionally, you can use multiple answer files to setup Windows by applying an unattend.xml to the image and adding an autounattend.xml to the installation media. For example, the unattend.xml applied to the image can contain OOBE and Windows Setup parameters while the autounattend.xml can contain only parameters for the WindowsPE pass that sets up the partitions and disk layouts for installation.

It is highly recommended to create any answer files using the Windows System Image Manager that is included in the Windows ADK. Though there are some online answer file generators that will "quickly" create an answer file for you, answer file parameters and variables can change between builds. Likewise, having faulty or unsupported parameters and/or variables in an answer file can prevent Windows Setup from completing.

It is also in good practice to have a good idea what each configuration pass does and what actions its child parameters takes during the Windows setup process. All information regarding Configuration Passes can be found in the [Microsoft Document](https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-automation-overview)

**Having incorrect, null or incomplete values in your answer file, most notably the WindowsPE Configuration Pass, WILL prevent Windows from completing its setup or even starting its setup. If a custom disk layout is included for installation, make certain the proper drive index numbers, partition type IDs and sizes are entered.**

### About Microsoft DaRT 10

With Optimize-Offline, the Microsoft 10 Diagnostic and Recovery Toolset and the Windows 10 Debugging Tools can be integrated into Windows Setup and/or the Windows Recovery allowing for the troubleshooting of system issues from a Preinstallation Environment. Likewise, it is NOT recommended to integrate Microsoft DaRT 10 into images accessible by multiple people or the default Recovery Environement because any user will be able to attain access to these tools by rebooting the device into Windows Recovery. Only integrate Microsoft DaRT 10 into the default Recovery Environment if the device will require specific credentials to gain access to the Operating System and the ability to reboot into the Recovery Environment is removed from the log-in screen using Group Policy.

It is also recommended to be well versed and aware of all recovery tools Microsoft DaRT 10 supplied prior to integrating it into the image(s) by thoroughly reviewing the Microsoft DaRT 10 [Microsoft Document](https://docs.microsoft.com/en-us/microsoft-desktop-optimization-pack/dart-v10/)

> Microsoft Diagnostics and Recovery Toolset (DaRT) 10 lets you diagnose and repair a computer that cannot be started or that has problems starting as expected. By using DaRT 10, you can recover end-user computers that have become unusable, diagnose probable causes of issues, and quickly repair unbootable or locked-out computers. When it is necessary, you can also quickly restore important lost files and detect and remove malware, even when the computer is not online. [Microsoft Document](https://docs.microsoft.com/en-us/microsoft-desktop-optimization-pack/dart-v10/)

### About Win32Calc

Starting in Windows 8.1, Microsoft introduced a Metro-style calculator to replace its traditional Calculator.  In Windows 10 non-LTSB/LTSC/Server editions, the traditional Calculator was entirely removed and replaced with a UWP (Universal Windows Platform) App version.  This new UWP Calculator introduced a fairly bloated UI many users were simply not fond of and much preferred the simplicity of the traditional Calculator (now labeled Win32Calc.exe).  Unfortunately, Microsoft never added the ability to revert back to the traditional Calculator nor released a downloadable package to install the traditional Calculator.

### About Microsoft Defender

> Microsoft Defender is the built-in antimalware and antivirus protection component of Microsoft Windows. [Microsoft Document](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-antivirus-windows?view=o365-worldwide). Natively, unless replaced by another antivirus, the Defender application always starts with Windows. Optimize-Offline provides methods to regain control over the initial activation and ongoing operation of Microsoft Defender.

***Optimize-Offline supplies two methods to control Microsoft Defender***

- The first method is to remove the SecHealthUI package which totally and permanently disables Defender.
- The second method is to apply the Dormant Defender parameter which provides greater flexibility in controlling Microsoft Defender.

***Option #1 - remove the SecHealthUI package and permanently disable Defender***

- For Windows 10: Remove SecHealthUI from System Applications. See [GitHub-DrEmpiricism](https://github.com/DrEmpiricism/Optimize-Offline#about-system-applications)
- For Windows 11: SecHealthUI removal is handled by your chosen WindowsApps list. See [GitHub-gdeliana](https://github.com/gdeliana/Optimize-Offline/blob/master/README.md#using-component-removal-lists)

***Option #2 - Apply the Dormant Defender parameter to gain full control of Defender***

For all Windows builds. The Dormant Defender parameter applies entries and values to the image registry hives forcing Microsoft Defender into an inactive state.
Dormant Defender fully disables Microsoft Defender, but by leaving the application and folder structure intact, retains the possibility to restore it to full functionality.

To re-enable Defender apply the "Microsoft Defender Enable" script [GitHub-TairikuOokami](https://github.com/TairikuOokami/Windows/blob/main/Microsoft%20Defender%20Enable.bat).

After Microsoft Defender is restored, retain full control by applying the "ToggleDefender" script [GitHub-AveYo](https://github.com/AveYo/LeanAndMean#toggledefender---lean-and-mean-snippet-by-aveyo-2020-2021).

***Note:***

If you apply both methods to control Microsoft Defender e.g. remove the SecHealthUI package and apply the Dormant Defender parameter, then the former removal method takes precedence. Meaning that the outcome of applying both methods is the same as if you only removed the SecHealthUI package.

### About Data Deduplication

> Data Deduplication, often called Dedup for short, is a feature of Windows Server 2016 that can help reduce the impact of redundant data on storage costs. When enabled, Data Deduplication optimizes free space on a volume by examining the data on the volume by looking for duplicated portions on the volume. Duplicated portions of the volume's dataset are stored once and are (optionally) compressed for additional savings. Data Deduplication optimizes redundancies without compromising data fidelity or integrity. [Microsoft Document](https://docs.microsoft.com/en-us/windows-server/storage/data-deduplication/overview)

With Optimize-Offline, the Data Deduplication packages can be integrated into the offline image. PowerShell's storage cmdlets can then be used to enable and manage Data Deduplication after the optimized image has been installed. More information is available from its [Microsoft Document](https://docs.microsoft.com/en-us/powershell/module/deduplication/?view=win10-ps)

### About Developer Mode

Developer Mode is a Windows Setting that, when enabled, allows the end-user to test any unsigned UWP app, use the Ubuntu Bash shell environment and offers optimizations for Windows Explorer, Remote Desktop and PowerShell. It is also a requirement when writing certain code in Visual Studio.

Enabling Developer Mode also installs Device Portal and Device Discovery, though they must be manually toggled on in the Settings in order for them to be enabled. Enabling Device Portal will reconfigure the default firewall rules to allow incoming connections, as Device Portal is a feature allowing for the system to act as a local web server for other devices on the local network. This is used for developing, deploying and debugging apps. Enabling Device Discovery allows devices to pair with Device Portal.

Developer Mode should ONLY be enabled on systems that require settings it provides. More information is available from its [Microsoft Document](https://docs.microsoft.com/en-us/windows/uwp/get-started/enable-your-device-for-development)

### Integrating Windows Store

For Windows 10 Enterprise LTSC 2019, the latest Windows Store package bundles and dependency packages can be integrated into the image, as this flavor of Windows (like Windows 10 Enterprise LTSB 2015-2016) does not contain any Windows Apps in its OEM state. There is no additional procedure required once the optimized Windows 10 LTSC 2019 is installed, and the Windows Store will be displayed in the Start Menu.

### Integrating Microsoft Edge HTML

For Windows 10 Enterprise LTSC 2019, Microsoft's flagship browser - Microsoft Edge (HTML-based) - can be integrated into the image since this flavor of Windows (like Windows 10 Enterprise LTSB 2015-2016) does not contain Microsoft Edge in its OEM state.

### Integrating Microsoft Edge Chromium

Microsoft Edge Chromium was publicly released on January 15, 2020 and runs on the same Chromium web engine as the Google Chrome browser. Microsoft Edge Chromium is designed to replace the Microsoft Edge (HTML-based) system application. Moreover, the Microsoft Edge system application can be removed while still allowing for the usage of Microsoft Edge Chromium.

For Windows 10 builds 18362 and above, the new Microsoft Edge Chromium browser can be integrated into the image. When the Microsoft Edge Chromium browser is integrated into an image, Optimize-Offline will also apply its administrative policy templates for GPO (Group Policy) control of its functions and features.

### Solid Image Compression

Solid image compression uses the undocumented LZMS compression format to concatenate all file data within a regular WIM file into a solid WIM archive (ESD file). By doing this, a 4GB WIM file is able to be compressed to a size of 2GB or less. However, as with other forms of high-ratio compression, LZMS compression can take quite a while to complete and is extremely system intensive. Solid compression should NOT be selected as the final image compression type if the end-user is impatient or has limited system resources.

### ISO File Structure Optimization

This is a process that occurs automatically when a Windows Installation ISO is used as the source image for optimization. In short, it removes all unnecessary media files used to install Windows 10 from a live system, thus reducing the total size of the installation media. The order in which files are removed and moved is critical for proper file structuring.

### ISO Remastering and Creation

When a Windows Installation Media ISO is used as the source image for optimizing, Optimize-Offline expands the entire media structure of the ISO into its own directory and allows for the creation of a new bootable Windows Installation Media ISO containing the newly optimized Windows Image after all processes have completed.

The ISO parameter allows for two values to be passed to it: 'Prompt' and 'No-Prompt.' This value sets the binary bootcode the image will be created with. An ISO created with the 'No-Prompt' bootcode will not require a keypress to begin Windows Setup allowing for a completely unattended Windows installation, while an ISO created with the 'Prompt' bootcode will require a keypress before Windows Setup will start.

Optimize-Offline calls the COM IMAPI2 interface for file system image building and also opens a binary stream that writes a bootfile sector code to the ISO. This allows for bootable Windows Installation Media ISO creation without the need for 3rd party tools like oscdimg.

Also it's possible to pre-define the Compression level with a json key located in Configuration.json file named: CompressionType, it's values can be one of the following: 'Select', 'None', 'Fast', 'Maximum', 'Solid'. Select will show the selection window of the compression type on runtime.

### About Defaultuser0

Any time an OEM Windows Image is modified offline, or the System Preparation, Reset and Provisioning Package deployment features are used, there is a chance this ghost account will surface.
defaultuser0 is not a real account, however, and is a bug that has been present in Windows through countless flavors and variations. It is not added to any user groups nor does it even have a profile.
Conversely, failing to remove the defaultuser0 account immediately after Windows Installation completes can lead to future headaches.  As an example, if you reset Windows with the defaultuser0 ghost account still present, upon the restart of the device, Windows will force you to log into the defaultuser0 account to continue.

In earlier versions of Optimize-Offline, a specific registry key was appended to allow for elevated control over the defaultuser0 account which allowed for its manual removal, as well as a SetupComplete.cmd script code that automatically removed it. However, with the newer builds (17134+), this is no longer required and simply rebooting the newly installed OS will automatically remove the defaultuser0 account from the 'Users' directory without having to manually remove it.

## Using Optimize-Offline

Open the custom configuration JSON file (Configuration.json) in any text editing program and edit any values for your specific optimization requirements. While editing the Configuration.json file, do not change the template structure and make sure its formatting is retained when adding or changing values.

Once you have edited the Configuration.json to your specific optimization requirements, open an elevated PowerShell console in the root directory of the Optimize-Offline project and execute the Start-Optimize call script:

```PowerShell
.\Start-Optimize.ps1
```

## Using Optimize-Offline as TrustedInstaller

Running Optimize-Offline as Trusted Installer enhances every operation it performs including properly unloading the image. This enhanced capability is provided by the "Start-Optimize-BAU-TI.ps1" script. The script is a the custom-made version of the generic "RunAsTI" script [GitHub-AveYo](https://github.com/AveYo/LeanAndMean/blob/main/RunAsTI.bat) and includes a unique solution for providing the power of Trusted Installer, but still correctly loading the HKCU USER hive as opposed to Window's natively loading the TI SYSTEM hive.

Open the custom configuration JSON file (Configuration.json) in any text editing program and edit any values for your specific optimization requirements. While editing the Configuration.json file, do not change the template structure and make sure its formatting is retained when adding or changing values.

Once you have edited the Configuration.json to your specific optimization requirements, open an elevated PowerShell console in the root directory of the Optimize-Offline project and execute the Start-Optimize-BAU-TI call script:

```PowerShell
.\Start-Optimize-BAU-TI.ps1
```

## Using Optimize-Offline GUI

For now there exists also a simple GUI variant that just prepares configuration.json file and is able to launch the script.

To use the GUI version of the script, please run/double click:

```
.\Start-GUI.bat
```

Below you will find a detailed explanation of each of the GUI sections:

* Source select button - Opens a file picker dialog. Choose the source of the modification process.
* Output select button - Opens a file save dialog, where the modified output will be saved. By default the output is saved in a automatically created subfolder of the root directory of the script.
* Refresh lists button - Will obtain all the available items for removal from the selected media. This automatically happens whenver a source file is chosen.
* Process button - Launches the Optimize-Offline script and switches to the output tab, to view the console output of the script.
* Select USB - Select the USB where to flash the modified target file
* UEFI/LEGACY - Select the type of USB to create. Use legacy for older bioses.
* General tab - contains general options that can be found in the configuration.json. By hovering the mouse on each of the options you will get a brief description of what the option does.
* Windows Apps - Select the Windows apps to remove/protect from removal. Blacklist will remove the selected apps, whereas whitelist will remove the not selected.
* System Apps - Select the System inbox apps to remove (some of them may render the installation unbootable). Blacklist will remove the selected system apps, whereas whitelist will remove the not selected.
* Capabilities - Removes windows capabilities. Blacklist will remove the selected capabilities, whereas whitelist will remove the not selected.
* Packages - Removes windows packages. Blacklist will remove the selected packages, whereas whitelist will remove the not selected.
* Features - Sets the windows feature to enable or disable.
* Services - Sets the startup of the windows services. BE CAREFUL!! not all the items listed are windows services. Due to the registry key containing also items such driver services that are not normal windows services.
* Custom registry - Injects registry tweaks into the installation
* Output - Shows an embeded console of the Optimize-Offline script output.

## Using component removal lists

Removal lists can be found in ./Content/Lists. There are 6 basic categories spread out through each of the subfolders. In each subcategory you will find a Whitelist, Blacklist and a template. The template contains all the possible packages to be inserted either in the blacklist or in the whitelist. The features contain only a list json and a template.

- WindowsApps - WindowsAppsWhitelist.json, WindowsAppsBlacklist.json, WindowsAppsTemplate.json
- SystemApps - SystemAppsWhitelist.json, SystemAppsBlacklist.json, SystemAppsTemplate.json
- Capabilities - CapabilitiesWhitelist.json, CapabilitiesBlacklist.json, CapabilitiesTemplate.json
- Packages - PackagesWhitelist.json, PackagesBlacklist.json, PackagesTemplate.json
- FeaturesToEnable - FeaturesToEnableList.json, FeaturesToEnableTemplate.json
- FeaturesToDisable - FeaturesToDisableList.json, FeaturesToDisableTemplate.json

The template files can be filled by launching the script with the populateTemplates parameter

```PowerShell
.\Start-Optimize.ps1 -populateTemplates
```

In configuration.json the list parameters are the following:

- WindowsApps - (All, None, Select, Whitelist, Blacklist), lists are in ./Content/Lists/WindowsApps
- SystemApps - (All, None, Select, Whitelist, Blacklist), lists are in ./Content/Lists/SystemApps
- Capabilities - (All, None, Select, Whitelist, Blacklist), lists are in ./Content/Lists/Capabilities
- Packages - (All, None, Select, Whitelist, Blacklist), lists are in ./Content/Lists/Packages
- FeaturesToEnable - (All, None, Select, List), lists are in ./Content/Lists/FeaturesToEnable
- FeaturesToDisable - (All, None, Select, List), lists are in ./Content/Lists/FeaturesToDisable
- Services - (None, Select, List, Advanced), lists are in ./Content/Lists/ServicesList.json, and in ./Content/Lists/ServicesAdvanced.json when advanced parameter is set in configuration.json

## Generating template component removal lists

The component removal lists mentioned above contain package names that are found in the windows system. Each version of windows may change the names and entries of it's components. For updating the lists or even helping you in generating custom ones according to the windows build you have, use the command:

`.\Start-Optimize -populateTemplates`

This command will find all the available windows apps, system apps and capabilities and will fill the corresponding json located in ./Content/Lists . Afterwards feel free to cherry pick the package names and insert them according to your needs in the removal lists in subfolder ./Content/Lists.

To populate the lists interactively by clicking item in grid guis and as well populating the templates (for later making manual changes to the lists by copying and pasting), use this command:
Code:

`.\Start-Optimize.ps1 -populateLists`

Please note that the interactive filling of lists, will fill the list chosen in configuration.json. So first set up configuration.json with the proper list method!! If no list methods are specified in configuration.json the populateLists will just populate the templates, as it doesn't have info about which lists to fill, so it will be basically the same behaviour like populateTemplates.

## Flashing to USB

In order to flash to an USB device, please set the key FlashToUSB to "UEFI" or "Legacy" value.
The Legacy option uses `\boot\bootsect.exe /nt60` method.
The UEFI method creates a special UEFI partition in the USB drive and then sets it as bootable.
Depending on your bios capabilities and on the boot method, choose the right method for your PC.

## Custom Icons

You can customize the icons of the windows local disk volume and of the ISO/USB volumes.
To set a custom windows local disk icon place it under `Content\Assets\windows.ico`
To set a custom USB drive/ISO disk icon place it under `Content\Assets\setup.ico`

## Windows services removal

***==Services Template==***
Use populateTemplates feature to assign your images available services to ServicesTemplate.json
    Some filtering out of non-service related entries is complete in the provided ServicesTemplate.json, but each OS requires more filtering.

***==List==***
Set the Services parameter in configuration.json: List
Assigns the start behavior of the services listed in ServicesList.json to "Disabled"
    For Services you want to disable, copy the service object "name" . . .
    . . . from     /Content/Lists/Services/ServicesTemplate.json -> /Content/Lists/Services/ServicesList.json
    Alternatively, if you already have a list of services you know you want to disable, add their names following the pattern seen in the provided example ServicesList.json

***==Advanced==***
Set the Services parameter in configuration.json: Advanced
Useful for specifying any type of start behavior (including "4" "Disabled") to the services listed in ServicesAdvanced.json
    Specify the start behavior of each service by copying the object . . .
        Code:
        {
            name: [SERVICE_DISPLAYNAME],
            start: [0,1,2,3,4],
            description?: [optional, not used in the code, but just for you to know more about the services you're including]
        }
    . . . from /Content/Lists/Services/ServicesTemplate.json -> /Content/Lists/Services/ServicesAdvanced.json

## Selecting the output path and filename

You can override the default path for ISO/WIM/SWM/ESD files by entering a specific path with an optional filename in Configuration.json "OutputPath" key. The possible key values are the following:

- default - is the default value for this setting and represents the default behavior of the script
- select - will popup a save file dialog for ISO input and a choose directory dialog for WIM/SWM/ESD inputs
- your specific path - you can as well specify the exact path of the output. For WIM/SWM/ESD files the path will chose only the directory path and any filename will be ignored.
- your specific path with {filename} variable for ISO inputs - The name of the ISO can be left to the script to be specified automatically based on the filename convention: {Windows_Edition}_{Build_nr}.ISO (ex. Professional_22000.ISO)

## Selective registry tweaks

- DisableWindowsUpgrade - Tweak will prevent windows update from receiving cummulative updates and feature updates
- DisableWindowsUpdateMicrosoft - Applies the official developers solution to prevents Windows Update from connecting to Microsoft update services. This includes connecting to the MS Store to download apps. [Microsoft Document] (https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services#bkmk-wu) Easy to turn on an off using a toggle script [GitHub Gist] (https://gist.github.com/espanafly/3041ce74cd2493d349e58c31630f98e5)
- DisableDriverUpdate - Will disable windows update from updating hw drivers
- DormantOneDrive - Disables the startup installation of Onedrive, but allows you to manually install by using the dormant physical setup file
- Disable3rdPartyApps - Will remove the 3rd party apps installed with windows
- W11ClassicContextMenu - Will make the context menu look like in W10 (builds >= 22000)
- ExplorerUIRibbon - Enables the classic explorer UI ribbon (not available on builds >= 22500)
- ClassicSearchExplorer - Tweak is needed in case you uninstall Search app or when applying the /Content/Additional/Setup/Set-Additional.ps1 on an online image. Works only on builds higher than 18363.
- RemoveTaskbarPinnedIcons - Tries to remove based on system version the automatically pinned taskbar icons
- DisableTeamsApp - Will remove Microsoft Teams from installing at the first logon
- DisableVirtualizationSecurity - Disables Core integrity and Virtualization based security (builds >= 22000)
- RunAsTiContextMenu - Adds Powershell as trusted installer context menu entry
- AmoledBlackTheme - Enables pitch black AMOLED theme on W10 and W11 all builds

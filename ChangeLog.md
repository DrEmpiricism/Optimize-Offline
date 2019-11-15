# ChangeLog #

## Build 3.2.7.8 (11-15-20119) ##

- Corrected an issue where trying to pass both the 'Setup' and 'Recovery' values in the Optimize-Offline.cmd calling script would return an error.
- Changed the validation set for the -DaRT parameter. It now accepts one of three values: 'Setup,' 'Recovery' and 'All.' Passing the value -DaRT "All" will integrate Dart 10 into both Windows Setup and Windows Recovery, while passing -DaRT "Setup" or -DaRT "Recovery" will integrate DaRT 10 into that environment only.
- The AppxWhitelist and Additional config file now use the JSON format instead of Ini and XML.
- A PassedParameters.log file is now generated after the optimized image has been finalized. This log file displays all parameters and values passed to the script that were used in the optimization processes.
- A few function modules have been updated with very small code modifications.
- Updated the CustomAppAssociations.xml file.

## Build 3.2.7.7 (11-10-2019) ##

- Due to the vulnerabilities found in PowerShell 2.0, and the fact it has been depreciated for quite some time, the 'MicrosoftWindowsPowerShellV2Root' Optional Feature is now automatically disabled during the optimization process.
- The primary script and module functions have been updated to use class-defined lists for string and array collections.
- Updated registry values set in the offline registry hives.
- The -DaRT switch has been changed into a parameter and will accept the values 'Setup' and 'Recovery'. This allows the end-user to control the environments Microsoft DaRT is integrated into. It should be noted that integrating Microsoft DaRT into the Windows Recovery environment is not recommended as it will allow anyone with access to the system to reboot into the Recovery Environment and access the Microsoft DaRT toolset.
- The 'Additional Tweaks.reg' template located in the 'Content\Additional\RegistryTemplates' folder has been updated.
- The Win32 Calculator image file has been updated with the latest Win32 Calculator files from Windows Server 2019.
- The Microsoft DaRT image files have been updated.

## Build 3.2.7.6 (10-31-2019) ##

- The removal of Windows Capabilities has been moved to the new -Capabilities switch.
- The -Packages switch now allows for the removal of Feature, OnDemand and Language Packages.
- The Developer Mode Feature Package can now be integrated by using the new -DeveloperMode switch. Before integrating Developer Mode, [read about it](https://docs.microsoft.com/en-us/windows/uwp/get-started/enable-your-device-for-development)!
- Updated process logging and corrected an issue where an error would return when formatting an error record.
- Updated the package summary log creation process.
- Updated and improved the integration of a default LockScreen.
- Optimized the clean-up of any active mount points that are detected prior to the script initializing.
- When disabling Optional Features, their files are now also removed. This further reduces the size of the final optimized image.
- Updated the Data Deduplication firewall rules.
- Optimized and improved a lot of process code in the primary script and the module functions.

## Build 3.2.7.5 (10-23-2019) ##

- Updated multiple OfflineProcessing module functions.
- Added the ability to access protected offline registry keys.
- Updated the offline registry key values set during the integration of the Win32Calc designating as a System Application.

## Build 3.2.7.4 (10-12-2019) ##

- Created a custom Win32Calc.wim that replaces the official cabinet files for builds 17663+ for the integration of the Win32 Calculator.
- The custom Win32Calc.wim fixes an issue that is present in the OEM Win32Calc cabinet packages which cause the Win32 Calculator to crash when the conversion type is changed.
- Updated the registry optimizations applied when the -Registry switch is used.
- A custom LockScreen can now be applied to the image using the -Additional switch and its associated Config.ini by adding the custom LockScreen image to the new 'Content\Additional\LockScreen' folder.
- Updated multiple functions used with the OfflineProcessing module.


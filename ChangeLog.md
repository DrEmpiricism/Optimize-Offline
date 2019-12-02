# ChangeLog #

## Build 4.0.0.0 (12-02-2019) ##

- Optimize-Offline project has been restructured and converted to an advanced PowerShell cmdlet.
- Function and variable control are now done with a nested resources module.
- Data is now imported into the cmdlet using localized data files.
- Optimize-Offline now requires a system culture of en-US.
- The Optimize-Offline.cmd call script has been replaced with the Start-Optimize.ps1 call script.
- Start-Optimize.ps1 allows for Optimize-Offline to be called from the PowerShell console with more control over how parameters are passed to the modules by automatically importing the configuration file (Configuration.json) into the Optimize-Offline cmdlet.
- Once the Configuration.json file has been edited, Start-Optimize.ps1 will execute Optimize-Offline with its content values.
- After an image has been successfully optimized, Optimize-Offline will generate a configuration JSON file (Configuration.json) based on the parameters and values passed for that specific optimization. Users will be able to use this configuration JSON file to replicate future image optimizations, or as a template.
- The System Application removal process has been updated. The four System Applications that use a GUID namespace as their application names are now displayed using their resolved application names.
- There is now a removed package clean-up process that runs after Provisioned and System Apps have been removed instead of being separated within other processes.
- The applying of optimized registry settings has been updated to its own advanced function. Moreover, multiple registry settings have been updated.
- Processing speed has been increased while overhead and load have been decreased.
- Updated and optimized multiple Resource functions and variables.
- Improved and updated run requirements utilizing a custom module manifest data file.
- All bundle and dependency packages for the integration of the Windows Store have been updated.
- Additionally, many other smaller code changes have been committed.

## Build 3.2.7.8 (11-15-2019) ##

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

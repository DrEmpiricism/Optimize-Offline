# ChangeLog #

## Build 3.2.7.1 (09-08-2019) ##

- Windows Photo Viewer is now only restored if the Windows Photos App is removed.
- When optimizing the file structure of the ISO media, the '\sources\sxs' folder is now only removed if the .NET Framework 3 (NetFx3) has been integrated into the image.
- Updated multiple functions in the Functions module.
- Made some minor but necessary adjustments to the primary script.

## Build 3.2.7.0 (09-03-2019) ##

- Corrected an issue that affected users who only supplied a WIM file for optimizing. An error occurred when the variable assigned to the mount path of the boot image was being returned to the main script despite a boot image not even being present. This would have resulted in failed DaRT integration and image dismount.
- Converted certain variables to dynamic parameters.
- Improved string creation by incorporating the StringBuilder .NET class which significantly reduces script overhead and load.
- Made some minor adjustments and optimizations to both the primary script and the functions module.

## Build 3.2.6.9 (08-30-2019) ##

- When supplying a WIM as the source image, it no longer has to be named as 'install.wim' as to accommodate users who catalog their individual WIM files by version, build, edition, etc.
- The mounting and dismounting order of any images has been optimized.
- All additional primary script variables have been moved to the Functions module.
- If the CallingShellApp System Application or YourPhone Appx Package is removed, its associated Immersive Control Panel Settings link will also be removed.
- Enabled .NET strong cryptography in the Registry Optimizations that ensures current SSL protocols are used for .NET application communication and not outdated and vulnerable SSL protocols.
- Optimized how logs are generated and saved.
- Updated the C# code in the Functions module for access token privileges and ISO creation.
- Updated the Windows Store bundle packages with their latest versions.
- Additional script and module code enhancements and changes.

## Build 3.2.6.8 (08-20-2019) ##

- The -ISO switch has been changed to a parameter that will now accept two values: 'Prompt' and 'No-Prompt.' This allows for those who wish to create a final Windows Installation Media ISO to also set the binary bootcode the image will be created with. An ISO created with the No-Prompt bootcode will not require a keypress to begin Windows Setup allowing for a completely unattended Windows installation, while an ISO created with the Prompt bootcode will require a keypress before Windows Setup will start.
- Registry optimizations have been updated to further accommodate the decoupling of the Search and Cortana features in builds 1903+. A few additional registry optimizations have been updated.
- The Functions.psm1 module has been updated.
- Additional primary script code modifications.

## Build 3.2.6.7 (08-14-2019) ##

- The Boot and Recovery images are now automatically mounted at the beginning of the script and remain mounted during the full runtime of the script. The Boot image will only be mounted if a Windows Installation Media ISO is used as the source image for optimization. If only an install.wim is provided, the Recovery image will only be mounted.
- Drivers can now be added to the Boot and Recovery images.
- In the 'Content\Additional\Drivers' directory are three new directories: Install, Boot and Recovery. Driver packages placed in the 'Install' directory will be added to the Install image, those placed in the 'Boot' directory will be added to the Boot image and those place in the 'Recovery' directory will be added to the Recovery image.
- Updated the applied registry optimizations to accommodate the recent decoupling of the Windows Search and Cortana features which could have resulted in a non-functional search function.
- Updated the functions module.
- Optimized and updated additional script and module process code.

# ChangeLog #

## Build 3.2.6.7 (08-14-2019) ##

- The Boot and Recovery images are now automatically mounted at the beginning of the script and remain mounted during the full runtime of the script. The Boot image will only be mounted if a Windows Installation Media ISO is used as the source image for optimization. If only an install.wim is provided, the Recovery image will only be mounted.
- Drivers can now be added to the Boot and Recovery images.
- In the 'Content\Additional\Drivers' directory are three new directories: Install, Boot and Recovery. Driver packages placed in the 'Install' directory will be added to the Install image, those placed in the 'Boot' directory will be added to the Boot image and those place in the 'Recovery' directory will be added to the Recovery image.
- Updated the applied registry optimizations to accommodate the recent decoupling of the Windows Search and Cortana features which could have resulted in a non-functional search function.
- Updated the functions module.
- Optimized and updated additional script and module process code.

## Build 3.2.6.6 (08-09-2019) ##

- Updated both the primary script and the functions module.

## Build 3.2.6.5 (08-06-2019) ##

- Restructured error-handling and module functions.
- Updated the Windows Store bundle package with the latest version.

## Build 3.2.6.4 (08-04-2019) ##

- Updated the Functions module.
- The post-optimization WIM file metadata is now exported and saved to a file for some additional WIM details.
- Some very minor primary script changes.

## Build 3.2.6.3 (08-03-2019) ##

- Added the ability to integrate NetFx3 using the -Additional switch and the Config.ini located in the 'Content\Additional' directory. Integration requires a Windows Media ISO to be used as the source image.
- Fixed a bug in the Functions module where the ISO creation process would fail if the install.wim was over a specific size.
- Removed a duplicate variable in one of the processes.
- Updated the Functions module.

## Build 3.2.6.2 (08-01-2019) ##

- ISO creation now uses a C# wrapper function that utilizes the Interop COM type for image creation and binary reader to set the ISO as EFI bootable. This removes the need for any 3rd party programs such as oscdimg.exe, or end-user input, to create a bootable Windows 10 Media ISO.
- Object ownership is now controlled using a C# wrapper that adjusts privileges on the access token for the running process that it's called for. This eliminates the overhead and additional - albeit small - process resources required to call legacy Takeown and ICACLS.
- What gets applied to the image with the -Additional script is now controlled by an editable Config.ini located in the 'Content\Additional' directory. When using the -Additional switch to call Optimize-Offline, it will check this config file and apply only those parameters set to 'True' and omit those that are 'False'.
- The registry optimizations have been updated with a few being removed because they are no longer applicable and many being combined. Likewise, all optimizations that added Context Menu features have been removed since these can be easily added by the end-user, either by adding their respective registry templates to the 'Content\Additional\RegistryTemplates' folder for integration (which I have included), or by merging them into the live registry after the image is in runtime (an online state).
- The function module has been updated.
- The Windows Store bundle package has been updated.
- Optimize-Offline now clears all variables it sets upon script completion.

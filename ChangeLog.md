# ChangeLog #

## Build 3.2.6.2 (08-01-2019) ##

- ISO creation now uses a C# wrapper function that utilizes the Interop COM type for image creation and binary reader to set the ISO as EFI bootable. This removes the need for any 3rd party programs such as oscdimg.exe, or end-user input, to create a bootable Windows 10 Media ISO.
- Object ownership is now controlled using a C# wrapper that adjusts privileges on the access token for the running process that it's called for. This eliminates the overhead and additional - albeit small - process resources required to call legacy Takeown and ICACLS.
- What gets applied to the image with the -Additional script is now controlled by an editable Config.ini located in the 'Content\Additional' directory. When using the -Additional switch to call Optimize-Offline, it will check this config file and apply only those parameters set to 'True' and omit those that are 'False'.
- The registry optimizations have been updated with a few being removed because they are no longer applicable and many being combined. Likewise, all optimizations that added Context Menu features have been removed since these can be easily added by the end-user, either by adding their respective registry templates to the 'Content\Additional\RegistryTemplates' folder for integration (which I have included), or by merging them into the live registry after the image is in runtime (an online state).
- The function module has been updated.
- The Windows Store bundle package has been updated.
- Optimize-Offline now clears all variables it sets upon script completion.

# ChangeLog #

## Build 3.1.2.3 ##

- If an ISO file is used as the source image, and the Windows ADK is installed, the script will automatically remaster and create a new bootable Windows Installation Media ISO before it finalizes.
- This alieviates the annoyance of having to copy the fully expanded ISO media to another location in order to create a bootable ISO after the script completes.
- If any of the required boot files cannot be located by the script, it will silently skip over the ISO creation process and return the fully expanded ISO media like before.
- Fixed a sintax error within the SetupComplete.cmd script.
- Removed some redundant and unecessary variables.
- Added the SeBackupPrivilege to the File and Folder Ownership functions, as this process privilege allows for system-level recursive nagivation of protected folders and directories.
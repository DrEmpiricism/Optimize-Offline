# ChangeLog #

## Build 3.1.3.2 (updated on 12-24-2019) ##

- Changed the optimizations of the registry and Start Menu to process after all packages, features and additional content has been applied or integrated into the image.
- Incorporated Data Deduplication using the new -Dedup switch. Using the -Dedup switch will apply the Data Deduplication and File Server packages (located in the Resources directory) into the image and enable the "Dedup-Core" Windows Feature.  Full details about Data Deduplication can be found on [Microsoft's Online Document](https://docs.microsoft.com/en-us/windows-server/storage/data-deduplication/overview)
- The script no longer applies a LayoutModification.xml to Windows 10 Enterprise LTSC 2019.
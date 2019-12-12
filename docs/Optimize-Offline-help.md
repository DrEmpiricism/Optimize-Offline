---
external help file: Optimize-Offline-help.xml
Module Name: Optimize-Offline
online version: https://github.com/DrEmpiricism/Optimize-Offline/blob/master/README.md
schema: 2.0.0
---

# Optimize-Offline

## SYNOPSIS
Offline optimization framework for Windows 10 image versions 1803-to-1909 with 64-bit architectures contained within WIM files.

## SYNTAX

```
Optimize-Offline [-SourcePath] <FileInfo> [[-WindowsApps] <String>] [-SystemApps] [-Capabilities] [-Packages]
 [-Features] [-DeveloperMode] [-WindowsStore] [-MicrosoftEdge] [-Win32Calc] [-Dedup] [[-DaRT] <String>]
 [-Registry] [-Additional] [[-ISO] <String>] [<CommonParameters>]
```

## DESCRIPTION
The Optimize-Offline module enables the offline optimization of Windows 10 image (WIM) files to customize runtime environments.

Optimize-Offline expands the user experience by eliminating unnecessary bloat, enhancing privacy, improving aesthetics and increasing system performance.

Image optimization is configurable using the Configuration.json file in the module root directory.

All images are optimized independently - without the need for 3rd party programs - by utilizing custom module resources.

## EXAMPLES

### EXAMPLE 1
```
PS C:\> .\Start-Optimize.ps1

An image will be optimized using the settings within the Configuration.json file.
```

### EXAMPLE 2
```
PS C:\> Optimize-Offline -SourcePath "D:\Win10Pro\Win10Pro_Full.iso" -WindowsApps "Select" -SystemApps -Capabilities -Packages -Features -Win32Calc -Dedup -DaRT "Setup" -Registry -ISO "No-Prompt"

A Windows Installation Media (ISO) file will be optimized using manually passed parameters.
```

### EXAMPLE 3
```
PS C:\> Optimize-Offline -SourcePath "D:\Win Images\install.wim" -WindowsApps "Whitelist" -SystemApps -Capabilities -Features -Dedup -Registry -DaRT "Recovery" -Additional

A Windows Image (WIM) file will be optimized using manually passed parameters.
```

## PARAMETERS

### -SourcePath
The path to a Windows 10 Installation Media ISO or a Windows image install WIM.

```yaml
Type: FileInfo
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -WindowsApps
Removes Provisioned Windows App Packages (.appx) selectively or automatically. The acceptable values for this parameter are: Select, Whitelist and All.

- **Select**: Populates and outputs a Gridview list of all Provisioned App Packages for selective removal.
- **Whitelist**: Automatically removes all Provisioned App Packages NOT found in the AppxWhiteList.json file.
- **All**: Automatically removes all Provisioned App Packages found in the image.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SystemApps
Populates and outputs a Gridview list of System Apps for selective removal.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Capabilities
Populates and outputs a Gridview list of Capability Packages for selective removal.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Packages
Populates and outputs a Gridview list of Windows Cabinet File Packages for selective removal.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Features
Populates and outputs a Gridview list of Windows Optional Features for selective disabling and enabling.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -DeveloperMode
Integrates the Developer Mode Feature into he image.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -WindowsStore
Integrates the Microsoft Windows Store and its required dependencies into the image.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -MicrosoftEdge
Integrates the Microsoft Edge Browser into the image.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Win32Calc
Integrates the traditional Win32 Calculator into the image.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Dedup
Integrates the Windows Server Data Deduplication Feature into the image.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -DaRT
Integrates the Microsoft Diagnostic and Recovery Toolset (DaRT 10) and Windows 10 Debugging Tools into Windows Setup and Windows Recovery. The acceptable values for this parameter are: Setup, Recovery and All.

- **Setup**: Integrates DaRT 10 and Windows 10 Debugging Tools into Windows Setup only.
- **Recovery**: Integrates DaRT 10 and Windows 10 Debugging Tools into Windows Recovery only.
- **All**: Integrates DaRT 10 and Windows 10 Debugging Tools into both Windows Setup and Windows Recovery.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Registry
Applies optimized settings into the image registry hives.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Additional
Integrates user-specific content in the "Content/Additional" directory based on the values set in the Additional.json file.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -ISO
Creates a new bootable Windows Installation Media ISO. The acceptable values for this parameter are: Prompt and No-Prompt.

- **Prompt**: The efisys.bin binary bootcode is written to the ISO which requires a key press when booted to begin Windows Setup.
- **No-Prompt**: The efisys_noprompt.bin binary bootcode is written to the ISO which does not require a key press when booted and will begin Windows Setup automatically.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.IO.FileInfo
### System.Collections.Specialized.OrderedDictionary
## OUTPUTS

### System.String
## NOTES
Integration of Microsoft Windows Store and Microsoft Edge are only applicable to Windows 10 Enterprise LTSC 2019.
Bootable ISO media creation is only applicable if a Windows Installation Media ISO is used as the source image.

## RELATED LINKS

[https://github.com/DrEmpiricism/Optimize-Offline/blob/master/README.md](https://github.com/DrEmpiricism/Optimize-Offline/blob/master/README.md)


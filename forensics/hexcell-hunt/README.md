# HexCell Hunt

**Category**: forensics

**Author**: \_dark_darkl0rd\_

## Description

Description: You have been tasked to recover the Skew1 part of the Windows BootKey (key for SysKey decryption). The bad news is that you need to submit not just the registry Cell Data but the entire Cell, as a continuous hex string.
Flag format ECSC{0102030405060708090A0B0C0D0E0F...}

### Hint 1: Looking at the Windows registry file format specification on Github could be useful
### Hint 2: The cell size is part of the cell, just like the cell data

The Flag submission/handler script should convert the data to upper or lowercase and remove spaces.


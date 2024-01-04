# Useful tools for Windows

## Process tools

### pstools

[Windows documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/pstools)

#### PsExec64.exe
This program allows us to run programs as SYSTEM

`C:\<location of pstools> > PsExec64.exe -i -s regedit`

This will open up regedit under a SYSTEM account.
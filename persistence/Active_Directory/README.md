# Active Directory Persistence

## DC Sync
### Credentials to look for
Since privileged credentials are those that are likely to be rotated often, they aren't always the best long term choice.

* **Credentials that have local administrator rights on several machines.** Usually organisations have a group or two with local admin rights on almost all computers. Usually split between one group for workstations and one for servers.

* **Service accounts that have delegation permissions.** With these accounts you would be able to force golden and silver tickets to perform Kerberos delegation attacks.

* **Accounts used for privileged AD services.** With privileged services such as Exchange, Windows Server Update Services (WSUS), or System Center Configuration Manager (SCCM), we could leverage AD exploitation to once again gain a privileged foothold.

### DCSync All
We can use [mimikatz.exe](../../useful_tools/Windows/README.md#mimikatz) to harvest some credentials! 

After placing mimikatz on the host machine we can run it, then use the following command to get information on a single user:

`mimikatz # lsadump::dcsync /domain:<ad domain> /user:<AD Username>`

If we want to get all of the credentials we can use the `/all` flag. First we will want to create a log file, so the information will be saved.

`log <filename>`

Then we can run mimikatz again.

`mimikatz # lsadump::dcsync /domain:<ad domain> /all`

You can then exit mimikatz and attempt to download the log file (will be in the current directory). Some helpful searches with the file:

`cat <filename> | grep "SAM Username"`

This will grab all the usernames in AD.

`cat <filename> | grep "Hash NTLM"`

This will dump all the hashes. The username and hashes should match, so by using a little bit of processing you should be able to get usernames:hashes for further spray attacks.
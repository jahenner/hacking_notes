# Connecting remotely to a Windows machine

## From Kali Linux

### RDP
`xfreerdp /u:<username> /p:<password> /v:<host IP>`

### WinRM
`evil-winrm -i <host IP> -u <username> -p <password>`

Can also perform Pass-the-Hash

`evil-winrm -i <host IP> -u <username> -H <password hash>`
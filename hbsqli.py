from socket import timeout
from ssl import SSLError
from urllib.error import URLError
import httpx
import argparse
import rich
from rich.console import Console

# Rich Console
console = Console()

# Argument Parser
parser = argparse.ArgumentParser()

parser.add_argument('-l', '--list', help='To provide list of URLs as an input')
parser.add_argument('-u', '--url', help='To provide single URL as an input')
parser.add_argument('-p', '--payloads', help='To provide payload file having Blind SQL Payloads with delay of 30 sec', required=True)
parser.add_argument('-H', '--headers', help='To provide header file having HTTP Headers which are to be injected', required=True)
parser.add_argument('-v', '--verbose', help='Run on verbose mode', action='store_true')
parser.add_argument('-a', '--approve', help='Pause and wait for approval if a vulnerability is found', action='store_true')
args = parser.parse_args()

# Open a file to save vulnerable URLs
vulnerable_file = open('vulnerable_urls.txt', 'a')

# Header Payload Creation

# Open the Payloads file and read its contents into a list
try:
    with open(args.payloads, 'r') as file:
        payloads = [line.strip() for line in file]
except FileNotFoundError as e:
    print(str(e))
except PermissionError as e:
    print(str(e))
except IOError as e:
    print(str(e))

# Open the Headers file and read its contents into a list
try:
    with open(args.headers, 'r') as file:
        headers = [line.strip() for line in file]
except FileNotFoundError as e:
    print(str(e))
except PermissionError as e:
    print(str(e))
except IOError as e:
    print(str(e))

headers_list = []

for header in headers:
    for payload in payloads:
        var = header + ": " + payload
        headers_list.append(var)

headers_dict = {header: header.split(": ")[1] for header in headers_list}

# Function to handle when vulnerability is found
def handle_vulnerability(url, header, res_time):
    console.print("🌐 [bold][cyan]Testing for URL: [/][/]", url)
    console.print("💉 [bold][cyan]Testing for Header: [/][/]", repr(header))
    console.print("⏱️ [bold][cyan]Response Time: [/][/]", repr(res_time))
    console.print("🐞 [bold][cyan]Status: [/][red]Vulnerable[/][/]")
    print()

    # Save the vulnerable URL to the file
    try:
        vulnerable_file.write(f"{url} - {header} - Response Time: {res_time}\n")
        vulnerable_file.flush()  # Ensure the data is written to the file immediately
    except IOError as e:
        console.print(f"[bold red]Error writing to file: {e}[/]")

    # If the approve flag is set, wait for user input to continue
    if args.approve:
        input("Press ENTER to continue...")

# For File as an Input
def onfile():
    # Open the URL file and read its contents into a list
    with open(args.list, 'r') as file:
        urls = [line.strip() for line in file]

    for url in urls:
        skip_domain = False  # Flag to skip the entire domain on error
        for header in headers_dict:
            if skip_domain:
                break  # Skip remaining headers if domain has already encountered an error

            cust_header = {header.split(": ")[0]: header.split(": ")[1]}
            try:
                with httpx.Client(timeout=60) as client:
                    response = client.get(url, headers=cust_header, follow_redirects=True)
                res_time = response.elapsed.total_seconds()

                if 25 <= res_time <= 50:
                    handle_vulnerability(url, header, res_time)

            except (UnicodeDecodeError, AssertionError, TimeoutError, ConnectionRefusedError, SSLError, URLError, ConnectionResetError, httpx.RequestError, timeout) as e:
                print(f"The request was not successful due to: {e}")
                print(f"Skipping the entire domain {url} and moving to the next one...")
                print()
                skip_domain = True  # Set flag to skip remaining headers for this domain
                break  # Break the inner loop to move to the next domain

# For File as an Input-Verbose
def onfile_v():
    # Open the URL file and read its contents into a list
    with open(args.list, 'r') as file:
        urls = [line.strip() for line in file]

    for url in urls:
        skip_domain = False  # Flag to skip the entire domain on error
        for header in headers_dict:
            if skip_domain:
                break  # Skip remaining headers if domain has already encountered an error

            cust_header = {header.split(": ")[0]: header.split(": ")[1]}
            console.print("🌐 [bold][cyan]Testing for URL: [/][/]", url)
            console.print("💉 [bold][cyan]Testing for Header: [/][/]", repr(header))
            try:
                with httpx.Client(timeout=60) as client:
                    response = client.get(url, headers=cust_header, follow_redirects=True)
                console.print("🔢 [bold][cyan]Status code: [/][/]", response.status_code)
                res_time = response.elapsed.total_seconds()
                console.print("⏱️ [bold][cyan]Response Time: [/][/]", repr(res_time))

                if 25 <= res_time <= 50:
                    handle_vulnerability(url, header, res_time)
                else:
                    console.print("🐞[bold][cyan]Status: [/][green]Not Vulnerable[/][/]")
                    print()

            except (UnicodeDecodeError, AssertionError, TimeoutError, ConnectionRefusedError, SSLError, URLError, ConnectionResetError, httpx.RequestError, timeout) as e:
                print(f"The request was not successful due to: {e}")
                print(f"Skipping the entire domain {url} and moving to the next one...")
                print()
                skip_domain = True  # Set flag to skip remaining headers for this domain
                break  # Break the inner loop to move to the next domain

# For URL as an Input
def onurl():
    # Save URL as Variable
    url = args.url

    for header in headers_dict:
        cust_header = {header.split(": ")[0]: header.split(": ")[1]}
        try:
            with httpx.Client(timeout=60) as client:
                response = client.get(url, headers=cust_header, follow_redirects=True)
            res_time = response.elapsed.total_seconds()

            if 25 <= res_time <= 50:
                handle_vulnerability(url, header, res_time)

        except (UnicodeDecodeError, AssertionError, TimeoutError, ConnectionRefusedError, SSLError, URLError, ConnectionResetError, httpx.RequestError, timeout) as e:
            print(f"The request was not successful due to: {e}")
            print(f"Skipping the entire domain {url} and moving to the next one...")
            print()
            break  # Break the loop to move to the next domain

# For URL as an Input-Verbose
def onurl_v():
    # Save URL as Variable
    url = args.url

    for header in headers_dict:
        cust_header = {header.split(": ")[0]: header.split(": ")[1]}
        console.print("🌐 [bold][cyan]Testing for URL: [/][/]", url)
        console.print("💉 [bold][cyan]Testing for Header: [/][/]", repr(header))
        try:
            with httpx.Client(timeout=60) as client:
                response = client.get(url, headers=cust_header, follow_redirects=True)
            console.print("🔢 [bold][cyan]Status code: [/][/]", response.status_code)
            res_time = response.elapsed.total_seconds()
            console.print("⏱️ [bold][cyan]Response Time: [/][/]", repr(res_time))

            if 25 <= res_time <= 50:
                handle_vulnerability(url, header, res_time)
            else:
                console.print("🐞[bold][cyan]Status: [/][green]Not Vulnerable[/][/]")
                print()

        except (UnicodeDecodeError, AssertionError, TimeoutError, ConnectionRefusedError, SSLError, URLError, ConnectionResetError, httpx.RequestError, timeout) as e:
            print(f"The request was not successful due to: {e}")
            print(f"Skipping the entire domain {url} and moving to the next one...")
            print()
            break  # Break the loop to move to the next domain

if args.url is not None:
    if args.verbose:
        onurl_v()
    else:
        onurl()
elif args.list is not None:
    if args.verbose:
        onfile_v()
    else:
        onfile()
else:
    print("Error: One out of the two flag -u or -l is required")

# Close the file after the script finishes
vulnerable_file.close()

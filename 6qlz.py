import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import socket
import os
import signal
import shutil
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Function to center text in terminal
def center_text(text):
    terminal_width = shutil.get_terminal_size().columns
    return "\n".join(line.center(terminal_width) for line in text.split("\n"))

# ASCII Art
ASCII_ART = f"""
{Fore.RED}
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣤⣤⣶⣶⣶⣶⣶⣶⣠⣤⣤⣀⣀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣀⣴⣾⠿⠟⠛⠛⠉⠉⠉⠉⠉⠛⠛⠛⠿⠿⡿⠛⢿⣿⣷⣤
⠀⠀⠀⣠⡾⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⠉⠁
⠀⢀⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡟⠀⠀
⢠⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⠁⠀⠀
⠋⠀⠀⠀⠀⠀⠀⠀⢀⣤⣤⣤⣶⣶⣆⢤⣤⣀⣀⠀⠀⠀⠀⣸⡟⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢸⡿⠋⠙⢿⣿⣿⣿⣻⣿⣿⡇⠀⠀⠀⣿⠇⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⢀⠐⢻⣿⣻⣷⡽⣿⣷⠀⠀⢸⣿⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠿⣃⠹⠿⠗⣿⣷⣻⣿⡽⣿⣧⠀⣼⡇⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⡏⣁⢀⠲⣿⣿⣷⢻⣿⡽⣿⢀⣿⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠁⣉⣡⣿⣿⣿⣏⣿⣿⣿⣼⡿⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢰⡿⣿⣿⣿⣿⣿⣿⣿⣿⣽⣿⣿⣿⡇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⠟⠛⠛⠛⠛⠛⠆⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠛⠘⠛⠛⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                       v1.1
  ____      __    ____                          
 / __/___ _/ /__ / __/______ ____  ___  ___ ____
/ _ \/ _ `/ /_ /_\ \/ __/ _ `/ _ \/ _ \/ -_) __/
\___/\_, /_//__/___/\__/\_,_/_//_/_//_/\__/_/  
      /_/                                       

----------- Made by @6qlz ------------

[1] Probe multiple domains from a file
[2] Probe a single domain 
 [3] Exit{Style.RESET_ALL} 
 
"""

ASCII_ART = center_text(ASCII_ART)
# Configure logging
logging.basicConfig(format='%(message)s', level=logging.INFO)

# Configure logging
logging.basicConfig(format='%(message)s', level=logging.INFO)

def signal_handler(sig, frame):
    print(f"\n{Fore.LIGHTRED_EX}[{Fore.WHITE}!{Fore.RED}]{Fore.RED} Exiting...{Style.RESET_ALL}")
    exit(0)

# Register SIGINT (Ctrl+C) handler
signal.signal(signal.SIGINT, signal_handler)

class DomainProbe:
    def __init__(self, max_workers=200, timeout=5, retries=3):
        self.max_workers = max_workers
        self.timeout = timeout
        self.retries = retries
        self.live_domains = []

    def detect_technologies(self, headers):
        """Detects technologies based on response headers."""
        tech_stack = []
        if 'server' in headers:
            tech_stack.append(headers['server'])
        if 'x-powered-by' in headers:
            tech_stack.append(headers['x-powered-by'])
        return tech_stack if tech_stack else []

    def probe_domain(self, domain):
        protocols = ['http://', 'https://']
        results = []
        for protocol in protocols:
            port = 443 if protocol == 'https://' else 80
            port_color = Fore.CYAN
            url = f"{protocol}{domain}:{port}"
            for attempt in range(1, self.retries + 1):
                try:
                    response = requests.get(url, timeout=self.timeout, allow_redirects=True)
                    ip = socket.gethostbyname(domain)
                    tech_stack = self.detect_technologies(response.headers)

                    if 100 <= response.status_code < 200:
                        status_color = Fore.MAGENTA
                        link_color = Fore.GREEN
                    elif 200 <= response.status_code < 300:
                        status_color = Fore.GREEN
                        link_color = Fore.GREEN
                        status_text = f"{Fore.GREEN}Success{Style.RESET_ALL}"
                    elif 300 <= response.status_code < 400:
                        status_color = Fore.YELLOW
                        link_color = Fore.GREEN
                        status_text = f"{Fore.YELLOW}Redirects{Style.RESET_ALL}"
                    else:
                        status_color = Fore.LIGHTRED_EX
                        link_color = Fore.RED
                        status_text = f"{Fore.RED}Failed{Style.RESET_ALL}"

                    tech_display = f"[{Fore.MAGENTA}{', '.join(tech_stack)}{Style.RESET_ALL}]" if tech_stack else ""
                    logging.info(f"[{status_text}] {link_color}{protocol}{domain}{Style.RESET_ALL} [{status_color}{response.status_code}{Style.RESET_ALL}] [{Fore.BLUE}{ip}{Style.RESET_ALL}] [{port_color}{port}{Style.RESET_ALL}] {tech_display}")

                    if response.status_code < 400:
                        self.live_domains.append(url)

                    results.append({
                        'domain': domain,
                        'url': url,
                        'status_code': response.status_code,
                        'ip': ip,
                        'headers': dict(response.headers),
                        'technologies': tech_stack,
                        'port': port
                    })
                    break

                except (requests.RequestException, socket.gaierror) as e:
                    if attempt == self.retries:
                        logging.info(f"[{Fore.RED}Failed{Style.RESET_ALL}] {Fore.RED}{protocol}{domain}{Style.RESET_ALL} [{Fore.LIGHTRED_EX}FAILED{Style.RESET_ALL}] [Unresolved] [{port_color}{port}{Style.RESET_ALL}]")
                        results.append({
                            'domain': domain,
                            'url': url,
                            'status_code': None,
                            'ip': 'Unresolved',
                            'headers': {},
                            'technologies': [],
                            'port': port
                        })
        return results

    def probe_domains(self, domains):
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_domain = {executor.submit(self.probe_domain, domain): domain for domain in domains}
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    results.extend(future.result())
                except Exception as e:
                    logging.error(f"Error probing {domain}: {e}")
        return results


def main():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(ASCII_ART)

    while True:
        choice = input(f"{Fore.RED}[{Fore.WHITE}!{Fore.LIGHTRED_EX}]{Fore.RED} Choose an option: {Fore.WHITE}").strip()

        if choice == "1":
            file_path = input(f"{Fore.LIGHTRED_EX}[{Fore.WHITE}!{Fore.RED}] Enter the file path: {Fore.WHITE}").strip()
            try:
                with open(file_path, 'r') as file:
                    domains = [line.strip() for line in file if line.strip()]
                probe = DomainProbe()
                probe_results = probe.probe_domains(domains)  # Capture the results

                save_choice = input(f"\n{Fore.RED}[{Fore.WHITE}!{Fore.LIGHTRED_EX}]{Fore.RED} Do you want to save live domains to a file? (y/n): {Fore.WHITE}").strip().lower()

                if save_choice == 'y':
                    save_file = input(f"{Fore.RED}[{Fore.WHITE}!{Fore.LIGHTRED_EX}]{Fore.RED} Enter filename to save live domains: {Fore.WHITE}").strip()
                    with open(save_file, 'w') as file:
                        file.write("\n".join(probe.live_domains))  # Access live_domains from probe
                    print(f"\n{Fore.RED}[!{Fore.LIGHTRED_EX}]{Fore.RED} Live domains saved successfully to {save_file}!{Style.RESET_ALL}")  # Include filename in the success message
                    break  # Terminate the loop after saving

                else:
                    print(f"\n{Fore.RED}[!{Fore.LIGHTRED_EX}]{Fore.RED} Live domains not saved.{Style.RESET_ALL}")
                    break  # Terminate the loop after not saving

            except FileNotFoundError:
                logging.error(f"{Fore.RED}[{Fore.WHITE}!{Fore.LIGHTRED_EX}]{Fore.RED} File not found: {file_path}{Style.RESET_ALL}")
                break # Terminate the loop after file not found

        elif choice == "2":
            domain = input(f"{Fore.LIGHTRED_EX}[{Fore.WHITE}!{Fore.RED}] Enter the domain: {Fore.WHITE}").strip()
            probe = DomainProbe()
            probe.probe_results = probe.probe_domains([domain]) # Capture the results

            save_choice = input(f"\n{Fore.RED}[{Fore.WHITE}!{Fore.LIGHTRED_EX}]{Fore.RED} Do you want to save live domains to a file? (y/n): {Fore.WHITE}").strip().lower()

            if save_choice == 'y':
                save_file = input(f"{Fore.RED}[{Fore.WHITE}!{Fore.LIGHTRED_EX}]{Fore.RED} Enter filename to save live domains: {Fore.WHITE}").strip()
                with open(save_file, 'w') as file:
                    file.write("\n".join(probe.live_domains))  # Access live_domains from probe
                print(f"\n{Fore.RED}[!{Fore.LIGHTRED_EX}]{Fore.RED} Live domains saved successfully to {save_file}!{Style.RESET_ALL}") # Include filename in the success message
                break  # Terminate the loop after saving
            else:
                print(f"\n{Fore.RED}[{Fore.WHITE}!{Fore.LIGHTRED_EX}]{Fore.RED} Live domains not saved.{Style.RESET_ALL}")
                break  # Terminate the loop after not saving

        elif choice == "3":
            print(f"{Fore.LIGHTRED_EX}[{Fore.WHITE}!{Fore.RED}]{Fore.RED} Exiting...{Style.RESET_ALL}")
            break # Correctly terminate the loop

if __name__ == '__main__':
    main()

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import socket
import os
import signal
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# ASCII Art
ASCII_ART = f"""
{Fore.LIGHTRED_EX}
  ____      __    ____ {Fore.LIGHTRED_EX}
 / __/___ _/ /__ / __/______ ____ ___ ___ ____ {Fore.LIGHTRED_EX}
/ _ \/ _ `/ /_ /_\ \/ __/ _ `/ _ \/ _ \/ -_) __/ {Fore.RED}
\___/\_, /_//__/___/\__/\_,_/_//_/_//_/\__/_/ v1.0 {Fore.RED}
      /_/
----------- {Fore.RED}M{Fore.LIGHTRED_EX}a{Fore.RED}d{Fore.LIGHTRED_EX}e {Fore.RED}b{Fore.LIGHTRED_EX}y @{Fore.RED}6q{Fore.LIGHTRED_EX}l{Fore.RED}z ------------{Fore.RED}
{Style.RESET_ALL}
"""

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
                except (requests.RequestException, socket.gaierror):
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
        
        if len(domains) > 1 and self.live_domains:
            save_choice = input(f"\n{Fore.RED}[{Fore.WHITE}!{Fore.LIGHTRED_EX}]{Fore.RED} Do you want to save live domains to a file? (y/n): {Fore.WHITE}").strip().lower()
            if save_choice == 'y':
                save_file = input(f"{Fore.RED}[{Fore.WHITE}!{Fore.LIGHTRED_EX}]{Fore.RED} Enter filename to save live domains: {Fore.WHITE}").strip()
                with open(save_file, 'w') as file:
                    file.write("\n".join(self.live_domains))
                print(f"\n{Fore.RED}[!{Fore.LIGHTRED_EX}]{Fore.RED} Live domains saved successfully!{Style.RESET_ALL}")
        
        return results

def print_menu():
    print(f"{Fore.LIGHTRED_EX} [{Fore.WHITE}1{Fore.RED}]{Style.RESET_ALL} {Fore.WHITE}Probe multiple domains from a file{Style.RESET_ALL}")
    print(f"{Fore.RED} [{Fore.WHITE}2{Fore.LIGHTRED_EX}]{Style.RESET_ALL} {Fore.WHITE}Probe a single domain{Style.RESET_ALL}")
    print(f"{Fore.LIGHTRED_EX} [{Fore.WHITE}3{Fore.RED}]{Style.RESET_ALL} {Fore.WHITE}Exit{Style.RESET_ALL}")
    print()
    print()
    print()

def main():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(ASCII_ART)
    while True:
        print_menu()
        choice = input(f"{Fore.RED}[{Fore.WHITE}!{Fore.LIGHTRED_EX}]{Fore.RED} Choose an option: {Fore.WHITE}").strip()
        if choice == "1":
            file_path = input(f"{Fore.LIGHTRED_EX}[{Fore.WHITE}!{Fore.RED}] Enter the file path: {Fore.WHITE}").strip()
            try:
                with open(file_path, 'r') as file:
                    domains = [line.strip() for line in file if line.strip()]
                probe = DomainProbe()
                probe.probe_domains(domains)
                exit()
            except FileNotFoundError:
                logging.error(f"{Fore.RED}[{Fore.WHITE}!{Fore.LIGHTRED_EX}]{Fore.RED} File not found: {file_path}{Style.RESET_ALL}")
        elif choice == "2":
            domain = input(f"{Fore.LIGHTRED_EX}[{Fore.WHITE}!{Fore.RED}] Enter the domain: {Fore.WHITE}").strip()
            probe = DomainProbe()
            probe.probe_domains([domain])
            exit()
        elif choice == "3":
            print(f"{Fore.LIGHTRED_EX}[{Fore.WHITE}!{Fore.RED}]{Fore.RED} Exiting...{Style.RESET_ALL}")
            break

if __name__ == '__main__':
    main()

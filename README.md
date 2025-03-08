# 6qlzScanner 

6qlzScanner is a high-performance, multithreaded domain reconnaissance tool designed for security researchers, penetration testers, and bug bounty hunters. It efficiently probes domains, detects web technologies, and categorizes responses using color-coded output. Built with automation in mind, it streamlines the reconnaissance process, making it faster and more efficient for large-scale scanning.

## Key Features 🗝️
- **Multithreaded Scanning** – Scan multiple domains simultaneously for maximum efficiency.
- **Technology Detection** – Extracts web technologies from HTTP response headers.
- **Structured Output** – Provides detailed status codes, IP addresses, and open ports.
- **Color-Coded Results** – Easily identify successful, redirected, and failed requests.
- **Custom Wordlists Support** – Works seamlessly with custom subdomain and endpoint wordlists.

![6qlzScanner Output](https://i.imgur.com/IJSHsFS.png)



## Installation 🔧
Ensure you have Python installed, then clone the repository and install dependencies:
```sh
git clone https://github.com/6qlz/6qlzScanner.git
cd 6qlzScanner
pip install -r requirements.txt
```

## Usage 🛠
Run the script and follow the menu options to scan a single domain or multiple domains from a file:
```sh
python3 6qlz.py
```

## Disclaimer ⚠️
This tool is intended for **authorized security testing and research purposes only**. Misuse of this tool for unauthorized access or illegal activities is strictly prohibited. The author is not responsible for any misuse or legal consequences resulting from its usage. Always obtain **explicit permission** before testing any system or domain.


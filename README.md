# Website Information Gathering Script

`advanced_website_scan.sh` is a comprehensive bash script designed to gather and analyze various types of information about a specified website. It performs network diagnostics, security scans, and system monitoring, with results available in JSON or text format based on user preference.

## Features
Basic Domain Information: Collects IP address and DNS records.
Traceroute: Traces the path packets take to the target website.
Nmap Scan: Scans open ports and services on the target website.
MTR Network Diagnostic: Provides network diagnostic information.
Netstat: Displays active connections and protocols.
HTTP Headers: Fetches and analyzes HTTP headers and protocol version.
SSL/TLS Certificate Information: Gathers details about SSL/TLS certificates if HTTPS is available.
Process Monitoring: Monitors web-related processes (e.g., nginx, apache).
System Resource Usage: Reports on CPU and memory usage.

## Usage
To run the script, use the following command:
``` bash
sudo ./advanced_website_scan.sh  <website> [json|text] [verbose|quiet]
```

`<website>:` The target domain you want to analyze.

`[json|text]` (optional): The output format. Defaults to json if not specified.

`[verbose|quiet]` (optional): Logging level. Defaults to quiet if not specified.

### Requirements
The script must be run as root due to the use of nmap, netstat, and ps commands.
jq must be installed for JSON formatting.
Ensure necessary network diagnostic tools (ping, dig, traceroute, nmap, mtr, netstat, curl, openssl, ps, top, free) are installed.

#### Script Breakdown

Initial Setup:

Defines the target website and output format.
Checks for root privileges.
Creates a directory for results and sets up logging.
Basic Domain Information:

Uses ping and dig to collect basic domain info and saves it.

`Traceroute:`
Runs traceroute to trace the path to the target and saves the results.

`Nmap Scan:`
Executes an nmap scan to find open ports and services.

`MTR Network Diagnostic:`
Runs mtr to provide network diagnostic information.

`Netstat:`
Gathers active connections and protocols information using netstat.

`HTTP Headers:`
Fetches HTTP headers and identifies the HTTP protocol version.

`SSL/TLS Certificate Information:`
If the target uses HTTPS, it collects SSL/TLS certificate details.

`Process Monitoring:`
Monitors web-related processes (e.g., nginx, apache) using ps.

`System Resource Usage:`
Reports CPU and memory usage.

`Completion:`
Logs the end of the script execution and stores all logs.

### Output
Results are saved in the scan_results directory.
Logs of the script execution are stored in scan_log.txt within the scan_results directory.
Output files are named according to the type of information collected (e.g., basic_info.json, nmap_scan.txt).
##### Example
```bash
sudo ./advanced_website_scan.sh  example.com json verbose
```
This command will analyze example.com, output results in JSON format, and use verbose logging.

### Notes
Ensure that all required tools are installed and available in your system PATH.
Adjust script permissions if necessary: chmod +x script.sh.

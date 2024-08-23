# Subdomain Hijacker

## Overview

This **Subdomain Hijacker** is a Python-based tool designed to automate the discovery of vulnerable subdomains that are susceptible to takeover. By checking CNAME records and response patterns, it identifies common services like AWS, GitHub, Heroku, and others that may have dangling DNS records, leading to security vulnerabilities.

The script supports the use of the **Tor network** for anonymity, multi-threading for performance, and various configurations for speed, verbosity, and output formats.

## Features

- **CNAME Pattern Matching**: Automatically identifies common vulnerable services based on CNAME records.
- **Error Response Matching**: Scans for specific error messages in the HTTP responses that indicate potential takeovers.
- **Tor Support**: Route requests through the Tor network to anonymize scanning.
- **Multi-threading**: Utilize multiple threads for fast and efficient scanning of large subdomain lists.
- **Configurable Speed**: Adjust the time delay between requests for faster or slower scanning.
- **Verbose and Silent Modes**: Choose between detailed output and minimal reporting.
- **Output to File**: Save results to a file for further analysis.

## Supported Services

The script checks for the following common services that could be vulnerable to subdomain takeover:
- AWS (S3)
- GitHub Pages
- Heroku
- Unbounce
- Bitbucket
- WordPress
- Shopify
- CloudFront

## Requirements

- Python 3.x
- `requests`
- `dnspython`
- `socks` (if using Tor)
- `stem` (if using Tor)
- `concurrent.futures` (built-in for multi-threading)

To install the required Python libraries, run:

```bash
pip install requests dnspython pysocks stem
```

## Usage

You can run the scanner by providing a file with a list of subdomains to check and configure the various options to suit your needs.

### Command-line Options:

```bash
python3 exploitpickle.py --d <subdomains_file> [options]
```

### Options:

- `--d <file>`: **Required**. Path to the file containing the list of subdomains.
- `-v`: **Optional**. Enable verbose output, showing detailed information for each subdomain check.
- `-t <seconds>`: **Optional**. Set the delay between requests (in seconds). Default is 0.1 seconds.
- `-T`: **Optional**. Use the **Tor network** to anonymize the requests.
- `-o <output_file>`: **Optional**. Output the vulnerable subdomains to a file.
- `-s`: **Optional**. Silent mode: only show vulnerable subdomains.

### Example Usage:

1. **Basic Scan**:

   ```bash
   python3 exploitpickle.py --d subdomains.txt
   ```

2. **Verbose Scan with Tor**:

   ```bash
   python3 exploitpickle.py --d subdomains.txt -v -T
   ```

3. **Save Results to File**:

   ```bash
   python3 exploitpickle.py --d subdomains.txt -o results.txt
   ```

4. **Adjust Speed (Delay Between Requests)**:

   ```bash
   python3 exploitpickle.py --d subdomains.txt -t 0.5
   ```

## How It Works

1. **CNAME Lookup**: The script queries DNS to obtain the CNAME record for each subdomain.
2. **Pattern Matching**: The CNAME record is checked against a set of known vulnerable services (e.g., AWS, GitHub, Heroku, etc.).
3. **Response Validation**: If the CNAME matches a vulnerable service, the script sends a request to the subdomain and checks the response for specific error patterns that indicate a potential takeover.
4. **Tor Network**: If the `-T` option is enabled, requests are routed through the Tor network for anonymity.

## Tor Setup

To use the Tor network, ensure you have Tor running on your machine. You can start Tor using the following command:

```bash
sudo service tor start
```

Make sure that the Tor control port is listening on `127.0.0.1:9051` (default).

## Output

- **Verbose Mode (`-v`)**: Prints detailed information about each subdomain, including CNAME records, identified services, and potential vulnerabilities.
- **Silent Mode (`-s`)**: Prints only vulnerable subdomains.
- **File Output (`-o <file>`)**: Saves results to a specified file for further review.

## Disclaimer

This tool is for educational and research purposes only. The developers are not responsible for any misuse or damage caused by this tool. Ensure you have permission before scanning any domains.


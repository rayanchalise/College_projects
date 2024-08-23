import requests
import dns.resolver
import re
import argparse
import time
import socks
import socket
from stem import Signal
from stem.control import Controller
from concurrent.futures import ThreadPoolExecutor, as_completed

# Define common CNAME patterns that can indicate vulnerable subdomains
VULNERABLE_SERVICES = {
    'aws': 'amazonaws.com',
    'github': 'github.io',
    'heroku': 'herokuapp.com',
    'unbounce': 'unbouncepages.com',
    'bitbucket': 'bitbucket.io',
    'wordpress': 'wordpress.com',
    'shopify': 'myshopify.com',
    'cloudfront': 'cloudfront.net',
}

# Define error messages for different services that indicate potential takeover
ERROR_PATTERNS = {
    'aws': r'The specified bucket does not exist',
    'github': r'There isn\'t a GitHub Pages site here',
    'heroku': r'No such app',
    'unbounce': r'The requested URL was not found on this server',
    'bitbucket': r'This repository does not exist',
    'wordpress': r'Doesn\'t look like a site',
    'shopify': r'Store not available',
    'cloudfront': r'404 Not Found',
}

# Establish connection through Tor network
def connect_tor():
    try:
        with Controller.from_port(port=9051) as controller:
            controller.authenticate()
            controller.signal(Signal.NEWNYM)
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
            socket.socket = socks.socksocket
            print("[*] Connected to Tor network")
    except Exception as e:
        print(f"[ERROR] Failed to connect to Tor: {e}")

# Check the CNAME record of a subdomain
def get_cname(subdomain, dns_timeout=5):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = dns_timeout
        resolver.lifetime = dns_timeout
        answers = resolver.resolve(subdomain, 'CNAME')
        for rdata in answers:
            return str(rdata.target).strip('.')
    except dns.resolver.NoAnswer:
        return None
    except dns.resolver.NXDOMAIN:
        return None
    except Exception as e:
        return None

# Check if the subdomain's CNAME is vulnerable
def check_vulnerable_cname(cname):
    for service, pattern in VULNERABLE_SERVICES.items():
        if pattern in cname:
            return service
    return None

# Check if the subdomain responds with a vulnerable error page
def check_vulnerable_response(subdomain, service, timeout):
    if service not in ERROR_PATTERNS:
        return False

    try:
        response = requests.get(f'http://{subdomain}', timeout=timeout)
        if re.search(ERROR_PATTERNS[service], response.text, re.IGNORECASE):
            return True
    except requests.exceptions.Timeout:
        return False
    except requests.exceptions.RequestException:
        return False
    return False

def check_subdomain_takeover(subdomains, verbose, speed, use_tor, output_file, silent):
    if use_tor:
        connect_tor()

    # Set a minimum timeout to avoid invalid timeouts
    if speed <= 0:
        speed = 0.1  # Minimum allowed timeout

    results = []

    def process_subdomain(subdomain):
        result = ""
        cname = get_cname(subdomain)
        if cname:
            vulnerable_service = check_vulnerable_cname(cname)
            if vulnerable_service:
                if check_vulnerable_response(subdomain, vulnerable_service, timeout=speed):
                    result = f'[!!] Vulnerable: {subdomain}'
                else:
                    if verbose and not silent:
                        print(f'  [OK] No vulnerability detected on {subdomain}')
            else:
                if verbose and not silent:
                    print(f'  [OK] No vulnerable CNAME patterns found for {subdomain}')
        else:
            if verbose and not silent:
                print(f'  [ERROR] Failed to retrieve CNAME for {subdomain}')
        return result

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_subdomain = {executor.submit(process_subdomain, subdomain): subdomain for subdomain in subdomains}
        for future in as_completed(future_to_subdomain):
            result = future.result()
            if result:
                results.append(result)
                if not silent:
                    print(result)

    if output_file:
        with open(output_file, 'w') as f:
            for result in results:
                f.write(result + '\n')
        print(f'[*] Results saved to {output_file}')

# Main entry point
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Subdomain Takeover Scanner')
    
    parser.add_argument('--d', required=True, help='File containing subdomains')
    parser.add_argument('-v', action='store_true', help='Verbose output')
    parser.add_argument('-t', type=float, default=0, help='Packet speed (delay between requests)')
    parser.add_argument('-T', action='store_true', help='Use Tor for requests')
    parser.add_argument('-o', help='Output results to file')
    parser.add_argument('-s', action='store_true', help='Silent mode (only show vulnerable subdomains)')
    
    args = parser.parse_args()

    # Read subdomains from the provided file
    with open(args.d, 'r') as f:
        subdomains = [line.strip() for line in f.readlines()]
    
    # Start subdomain takeover check
    check_subdomain_takeover(subdomains, args.v, args.t, args.T, args.o, args.s)


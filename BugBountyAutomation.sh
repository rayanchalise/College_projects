#!/bin/bash

# Advanced Bug Bounty Automation Script - Optimized with Pre-Checks

# Variables
TARGET=$1
SUBDOMAIN_OUTPUT="subdomains.txt"
DIRECTORY_OUTPUT="directories.txt"
PARAMETER_OUTPUT="parameters.txt"
VULN_REPORT="vulnerabilities_report.txt"
PAYLOADS_DIR="./payloads"

# Check if target is provided
if [ -z "$TARGET" ]; then
  echo "Usage: $0 <target-domain>"
  exit 1
fi

# Check if the domain resolves
resolve_domain() {
  if ! nslookup $TARGET &>/dev/null; then
    echo "Domain resolution failed for $TARGET. Exiting."
    exit 1
  fi
}

# Check if the HTTP service is running
check_http_service() {
  if ! curl -s -o /dev/null -w "%{http_code}" http://$TARGET | grep -q '^2'; then
    echo "HTTP service check failed for $TARGET. Exiting."
    exit 1
  fi
}

# Function to handle errors
handle_error() {
  echo "Error: $1"
  exit 1
}

# Function for subdomain enumeration
enumerate_subdomains() {
  echo "Enumerating subdomains..."
  sublist3r -d $TARGET -o $SUBDOMAIN_OUTPUT || handle_error "Subdomain enumeration failed."
  echo "Subdomains enumerated and saved to $SUBDOMAIN_OUTPUT"
}

# Function for directory and file enumeration
enumerate_directories() {
  echo "Enumerating directories and files..."
  gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirb/common.txt -o $DIRECTORY_OUTPUT || handle_error "Directory enumeration failed."
  echo "Directories and files enumerated and saved to $DIRECTORY_OUTPUT"
}

# Function for parameter discovery
discover_parameters() {
  echo "Discovering parameters..."
  ffuf -u http://$TARGET/FUZZ -w /usr/share/wordlists/ffuf/parameters.txt -o $PARAMETER_OUTPUT || handle_error "Parameter discovery failed."
  echo "Parameters discovered and saved to $PARAMETER_OUTPUT"
}

# Function to verify the presence of parameters
check_parameters() {
  if [ ! -s $PARAMETER_OUTPUT ]; then
    echo "No parameters found. Skipping vulnerability checks."
    exit 1
  fi
}

# Function for SQL Injection testing
test_sql_injection() {
  echo "Testing for SQL Injection vulnerabilities..."
  sqlmap -m $PARAMETER_OUTPUT --batch --output-dir=sqlmap_results || handle_error "SQL Injection testing failed."
  echo "SQL Injection testing completed. Results saved in sqlmap_results."
}

# Function for XSS testing
test_xss() {
  echo "Testing for XSS vulnerabilities..."
  xsstrike -u http://$TARGET -p $PARAMETER_OUTPUT --crawl || handle_error "XSS testing failed."
  echo "XSS testing completed."
}

# Function for SSRF testing
test_ssrf() {
  echo "Testing for SSRF vulnerabilities..."
  while IFS= read -r param; do
    curl -X GET -G "http://$TARGET/$param?url=http://internal-service" -H "Host: $TARGET" -o ssrf_results.txt || handle_error "SSRF testing failed for $param."
  done < $PARAMETER_OUTPUT
  echo "SSRF testing completed. Results saved in ssrf_results.txt."
}

# Function for custom payload injection
inject_payloads() {
  echo "Injecting custom payloads..."
  while IFS= read -r url; do
    for payload in $PAYLOADS_DIR/*; do
      curl -X GET -G "$url?payload=$(cat $payload)" -H "Host: $TARGET" -o payload_results.txt || handle_error "Payload injection failed for $url with $payload."
    done
  done < $PARAMETER_OUTPUT
  echo "Custom payload injection completed. Results saved in payload_results.txt."
}

# Function for comprehensive vulnerability scanning
scan_vulnerabilities() {
  echo "Performing comprehensive vulnerability scanning..."
  nmap -p- --script vuln $TARGET -oN nmap_vuln_scan.txt || handle_error "Nmap vulnerability scan failed."
  echo "Vulnerability scan completed. Results saved in nmap_vuln_scan.txt."
}

# Function for generating the report
generate_report() {
  echo "Generating report..."
  {
    echo "Vulnerability Report for $TARGET"
    echo "Subdomains:"
    cat $SUBDOMAIN_OUTPUT
    echo "Directories and Files:"
    cat $DIRECTORY_OUTPUT
    echo "Parameters:"
    cat $PARAMETER_OUTPUT
    echo "SQL Injection Results:"
    cat sqlmap_results/*
    echo "XSS Results:"
    cat xsstrike_results/*
    echo "SSRF Results:"
    cat ssrf_results.txt
    echo "Custom Payload Injection Results:"
    cat payload_results.txt
    echo "Nmap Vulnerability Scan Results:"
    cat nmap_vuln_scan.txt
  } > $VULN_REPORT || handle_error "Report generation failed."
  echo "Report generated and saved to $VULN_REPORT"
}

# Main execution flow
resolve_domain
check_http_service

enumerate_subdomains &
enumerate_directories &
discover_parameters &
wait

check_parameters

test_sql_injection &
test_xss &
test_ssrf &
inject_payloads &
scan_vulnerabilities &
wait

generate_report

echo "Bug bounty automation script completed."


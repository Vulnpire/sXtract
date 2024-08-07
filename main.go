package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
)

func main() {
	// Define flags
	ipRangeFlag := flag.Bool("ir", false, "Fetch IPs from IP ranges")
	ipDomainFlag := flag.Bool("ip", false, "Fetch IPs from domains")
	queryFlag := flag.Bool("q", false, "Fetch IPs from query strings")

	// Parse flags
	flag.Parse()

	if !*ipRangeFlag && !*ipDomainFlag && !*queryFlag {
		log.Fatalf("Please specify one of -ir, -ip, or -q flags")
	}

	// Read from stdin
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		input := scanner.Text()
		if *ipRangeFlag {
			fetchIPsFromRange(input)
		} else if *ipDomainFlag {
			fetchIPsFromDomain(input)
		} else if *queryFlag {
			fetchIPsFromQuery(input)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading input: %v", err)
	}
}

func fetchIPsFromRange(ipRange string) {
	encodedRange := url.QueryEscape(ipRange)

	// Make the request to Shodan
	shodanURL := fmt.Sprintf("https://www.shodan.io/search/facet?query=Net%%3A%s&facet=ip", encodedRange)
	resp, err := http.Get(shodanURL)
	if err != nil {
		log.Fatalf("Failed to fetch data from Shodan: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}

	// Extract IPs using regex
	re := regexp.MustCompile(`<strong>([^<]+)</strong>`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	// Print the IPs
	for _, match := range matches {
		if len(match) > 1 {
			fmt.Println(match[1])
		}
	}
}

func fetchIPsFromDomain(domain string) {
	encodedDomain := url.QueryEscape(domain)

	// Make the request to Shodan
	shodanURL := fmt.Sprintf("https://www.shodan.io/search/facet?query=ssl.cert.subject.cn%%3A%%22*.%s%%22&facet=ip", encodedDomain)
	resp, err := http.Get(shodanURL)
	if err != nil {
		log.Fatalf("Failed to fetch data from Shodan: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}

	// Extract IPs using regex
	re := regexp.MustCompile(`<strong>([^<]+)</strong>`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	ipRe := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)

	// Print the IPs
	for _, match := range matches {
		if len(match) > 1 {
			ip := match[1]
			if ipRe.MatchString(ip) {
				fmt.Println(ip)
			}
		}
	}
}

func fetchIPsFromQuery(query string) {
	encodedQuery := url.QueryEscape(query)

	// Make the request to Shodan
	shodanURL := fmt.Sprintf("https://www.shodan.io/search/facet?query=%s&facet=ip", encodedQuery)
	resp, err := http.Get(shodanURL)
	if err != nil {
		log.Fatalf("Failed to fetch data from Shodan: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}

	// Extract IPs using regex
	re := regexp.MustCompile(`<strong>([^<]+)</strong>`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	ipRe := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)

	// Print the IPs
	for _, match := range matches {
		if len(match) > 1 {
			ip := match[1]
			if ipRe.MatchString(ip) {
				fmt.Println(ip)
			}
		}
	}
}

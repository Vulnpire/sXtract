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
	"strings"
)

func main() {
	// Define flags
	ipRangeFlag := flag.Bool("ir", false, "Fetch IPs from IP ranges")
	ipDomainFlag := flag.Bool("ip", false, "Fetch IPs from domains")
	queryFlag := flag.Bool("q", false, "Fetch IPs from query strings")
	queryFileFlag := flag.String("qf", "", "Fetch additional dork queries from a file")

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
			additionalQueries := getAdditionalQueries(*queryFlag, *queryFileFlag)
			fetchIPsFromDomain(input, additionalQueries)
		} else if *queryFlag {
			additionalQueries := getAdditionalQueries(*queryFlag, *queryFileFlag)
			fetchIPsFromQuery(input, additionalQueries)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading input: %v", err)
	}
}

// Function to get additional queries from flag or file
func getAdditionalQueries(queryFlag bool, queryFile string) string {
	if queryFlag && queryFile != "" {
		file, err := os.Open(queryFile)
		if err != nil {
			log.Fatalf("Failed to open query file: %v", err)
		}
		defer file.Close()

		var queries []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			queries = append(queries, scanner.Text())
		}

		if err := scanner.Err(); err != nil {
			log.Fatalf("Error reading query file: %v", err)
		}

		return strings.Join(queries, "+")
	} else if queryFlag {
		return strings.Join(flag.Args(), "+")
	}
	return ""
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

func fetchIPsFromDomain(domain string, additionalQueries string) {
	encodedDomain := url.QueryEscape(domain)
	query := fmt.Sprintf("ssl.cert.subject.cn%%3A%%22%s%%22", encodedDomain)

	if additionalQueries != "" {
		query = fmt.Sprintf("%s+%s", query, additionalQueries)
	}

	// Make the request to Shodan
	shodanURL := fmt.Sprintf("https://www.shodan.io/search/facet?query=%s&facet=ip", query)
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

func fetchIPsFromQuery(query string, additionalQueries string) {
	encodedQuery := url.QueryEscape(query)
	if additionalQueries != "" {
		encodedQuery = fmt.Sprintf("%s+%s", encodedQuery, additionalQueries)
	}

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

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1 Safari/605.1.15",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1",
}

// Function to get a random user agent
func getRandomUserAgent() string {
	rand.Seed(time.Now().UnixNano())
	return userAgents[rand.Intn(len(userAgents))]
}

// Function to add a delay between requests
func rateLimit() {
	time.Sleep(time.Duration(rand.Intn(5)+1) * time.Second) // Random delay between 1 to 5 seconds
}

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

		rateLimit() // Add delay after each request
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

	// Build the Shodan URL
	shodanURL := fmt.Sprintf("https://www.shodan.io/search/facet?query=Net%%3A%s&facet=ip", encodedRange)
	resp := makeRequest(shodanURL)
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

	// Build the Shodan URL
	shodanURL := fmt.Sprintf("https://www.shodan.io/search/facet?query=%s&facet=ip", query)
	resp := makeRequest(shodanURL)
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

	// Build the Shodan URL
	shodanURL := fmt.Sprintf("https://www.shodan.io/search/facet?query=%s&facet=ip", encodedQuery)
	resp := makeRequest(shodanURL)
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

// Helper function to make HTTP requests through AllOrigins with a random User-Agent
func makeRequest(targetURL string) *http.Response {
	encodedTargetURL := url.QueryEscape(targetURL)
	allOriginsURL := fmt.Sprintf("https://api.allorigins.win/get?url=%s", encodedTargetURL)

	client := &http.Client{}
	req, err := http.NewRequest("GET", allOriginsURL, nil)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	// Set a random User-Agent
	req.Header.Set("User-Agent", getRandomUserAgent())

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Failed to fetch data: %v", err)
	}

	// Parse the AllOrigins response (which contains JSON)
	var allOriginsResponse struct {
		Contents string `json:"contents"`
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}
	if err := json.Unmarshal(body, &allOriginsResponse); err != nil {
		log.Fatalf("Failed to parse AllOrigins response: %v", err)
	}

	// Create a new response with the Shodan contents
	return &http.Response{
		Body: ioutil.NopCloser(strings.NewReader(allOriginsResponse.Contents)),
	}
}

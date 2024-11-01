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
	"sync"
	"time"
)

var (
	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1 Safari/605.1.15",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1",
	}
	concurrency int
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// Function to get a random user agent
func getRandomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

func main() {
	// Define flags
	ipRangeFlag := flag.Bool("ir", false, "Fetch IPs from IP ranges")
	ipDomainFlag := flag.Bool("ip", false, "Fetch IPs from domains")
	queryFlag := flag.String("q", "", "Fetch IPs from query strings")
	hashFlag := flag.Bool("hs", false, "Fetch IPs from favicon hash")
	queryFileFlag := flag.String("qf", "", "Fetch additional dork queries from a file")
	sslFlag := flag.Bool("ssl", false, "Include SSL certificate search for domain")
	flag.IntVar(&concurrency, "c", 5, "Number of concurrent workers")

	flag.Parse()

	if !*ipRangeFlag && !*ipDomainFlag && !*hashFlag {
		log.Fatalf("Please specify one of -ir, -ip, or -hs flags")
	}

	// Create a buffered channel to limit concurrency
	inputCh := make(chan string, concurrency)
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go worker(inputCh, &wg, *ipRangeFlag, *ipDomainFlag, *hashFlag, *sslFlag, *queryFlag, *queryFileFlag)
	}

	// Read input from stdin and send to channel
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		inputCh <- scanner.Text()
	}

	close(inputCh) // Close the channel to signal workers to stop
	wg.Wait()      // Wait for all workers to finish

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading input: %v", err)
	}
}

// Worker function to process each input line concurrently
func worker(inputCh <-chan string, wg *sync.WaitGroup, ipRangeFlag, ipDomainFlag, hashFlag, sslFlag bool, queryFlag, queryFileFlag string) {
	defer wg.Done()
	for input := range inputCh {
		additionalQueries := getAdditionalQueries(queryFlag != "", queryFileFlag)
		if ipRangeFlag {
			fetchIPsFromRange(input, queryFlag, additionalQueries)
		} else if ipDomainFlag {
			fetchIPsFromDomain(input, sslFlag, queryFlag, additionalQueries)
		} else if hashFlag {
			fetchIPsFromFaviconHash(input, queryFlag, additionalQueries)
		}
	}
}


// Function to fetch IPs from favicon hash with an optional query
func fetchIPsFromFaviconHash(hash string, query string, additionalQueries string) {
    encodedHash := url.QueryEscape(hash)

    // Build the base query with the favicon hash
    shodanQuery := fmt.Sprintf("http.favicon.hash%%3A%s", encodedHash)

    // Append the query from the -q flag if provided
    if query != "" {  // Correct dereferencing check
        encodedQuery := url.QueryEscape(query)
        shodanQuery = fmt.Sprintf("%s+%s", shodanQuery, encodedQuery)
    }

    // Append additional queries if any
    if additionalQueries != "" {
        shodanQuery = fmt.Sprintf("%s+%s", shodanQuery, additionalQueries)
    }

    // Build the Shodan URL and make the request
    shodanURL := fmt.Sprintf("https://www.shodan.io/search/facet?query=%s&facet=ip", shodanQuery)
    resp := makeRequest(shodanURL)
    if resp == nil {
        log.Println("Skipping IP extraction due to request failure")
        return
    }
    defer resp.Body.Close()

    // Read the response and extract IPs
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        log.Fatalf("Failed to read response body: %v", err)
    }

    re := regexp.MustCompile(`<strong>([^<]+)</strong>`)
    matches := re.FindAllStringSubmatch(string(body), -1)

    ipRe := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)

    for _, match := range matches {
        if len(match) > 1 {
            ip := match[1]
            if ipRe.MatchString(ip) {
                fmt.Println(ip)
            }
        }
    }
}

// Function to get additional queries from flag or file
func getAdditionalQueries(queryFlag bool, queryFile string) string {
    var queries []string

    // Append the query from the file if -qf is provided
    if queryFile != "" {
        file, err := os.Open(queryFile)
        if err != nil {
            log.Fatalf("Failed to open query file: %v", err)
        }
        defer file.Close()

        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
            queries = append(queries, scanner.Text())
        }

        if err := scanner.Err(); err != nil {
            log.Fatalf("Error reading query file: %v", err)
        }
    }

    // Append the query from the -q flag if provided
    if queryFlag {
        queries = append(queries, flag.Args()...)
    }

    return strings.Join(queries, "+")
}

// Function to fetch IPs from IP ranges with an optional query
func fetchIPsFromRange(ipRange string, query string, additionalQueries string) {
	encodedRange := url.QueryEscape(ipRange)

	// Build the base query with the IP range
	shodanQuery := fmt.Sprintf("Net%%3A%s", encodedRange)

	// Append the query from the -q flag if provided
	if query != "" {
		encodedQuery := url.QueryEscape(query)
		shodanQuery = fmt.Sprintf("%s+%s", shodanQuery, encodedQuery)
	}

	// Append additional queries if any
	if additionalQueries != "" {
		shodanQuery = fmt.Sprintf("%s+%s", shodanQuery, additionalQueries)
	}

	// Build the Shodan URL
	shodanURL := fmt.Sprintf("https://www.shodan.io/search/facet?query=%s&facet=ip", shodanQuery)
	resp := makeRequest(shodanURL)
	if resp == nil {
		log.Println("Skipping IP extraction due to request failure")
		return
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

// Modified fetchIPsFromDomain function with optional sslCertQuery based on -ssl flag
func fetchIPsFromDomain(domain string, sslFlag bool, query string, additionalQueries string) {
	encodedDomain := url.QueryEscape(domain)

	// Prepare the Shodan query for hostname
	hostnameQuery := fmt.Sprintf("hostname%%3A%s", encodedDomain)

	// Prepare the Shodan query for ssl.cert.subject.cn if sslFlag is set
	var sslCertQuery string
	if sslFlag {
		sslCertQuery = fmt.Sprintf("ssl.cert.subject.cn%%3A%%22%s%%22", encodedDomain)
	}

	// Function to append query and additionalQueries to a base Shodan query
	appendQueries := func(baseQuery string) string {
		if query != "" {
			encodedQuery := url.QueryEscape(query)
			baseQuery = fmt.Sprintf("%s+%s", baseQuery, encodedQuery)
		}
		if additionalQueries != "" {
			baseQuery = fmt.Sprintf("%s+%s", baseQuery, additionalQueries)
		}
		return baseQuery
	}

	// Create the full query for hostname
	fullHostnameQuery := appendQueries(hostnameQuery)

	// Function to make request and extract IPs from the response
	extractIPs := func(shodanQuery string) []string {
		shodanURL := fmt.Sprintf("https://www.shodan.io/search/facet?query=%s&facet=ip", shodanQuery)
		resp := makeRequest(shodanURL)
		if resp == nil {
			log.Println("Skipping IP extraction due to request failure")
			return nil
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("Failed to read response body: %v", err)
		}

		re := regexp.MustCompile(`<strong>([^<]+)</strong>`)
		matches := re.FindAllStringSubmatch(string(body), -1)

		ipRe := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
		var ips []string
		for _, match := range matches {
			if len(match) > 1 {
				ip := match[1]
				if ipRe.MatchString(ip) {
					ips = append(ips, ip)
				}
			}
		}
		return ips
	}

	// Extract IPs for hostname query
	hostnameIPs := extractIPs(fullHostnameQuery)

	// Extract IPs for ssl.cert.subject.cn query if sslFlag is true
	var sslCertIPs []string
	if sslFlag {
		fullSslCertQuery := appendQueries(sslCertQuery)
		sslCertIPs = extractIPs(fullSslCertQuery)
	}

	// Combine both results and remove duplicates
	uniqueIPs := make(map[string]struct{})
	for _, ip := range hostnameIPs {
		uniqueIPs[ip] = struct{}{}
	}
	for _, ip := range sslCertIPs {
		uniqueIPs[ip] = struct{}{}
	}

	// Print the unique IPs
	for ip := range uniqueIPs {
		fmt.Println(ip)
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
// Helper function to make HTTP requests through AllOrigins with a random User-Agent and retry until success
func makeRequest(targetURL string) *http.Response {
	encodedTargetURL := url.QueryEscape(targetURL)
	allOriginsURL := fmt.Sprintf("https://api.allorigins.win/get?url=%s", encodedTargetURL)

	for {
		client := &http.Client{}
		req, err := http.NewRequest("GET", allOriginsURL, nil)
		if err != nil {
			log.Fatalf("Failed to create request: %v", err)
		}

		// Set a random User-Agent
		req.Header.Set("User-Agent", getRandomUserAgent())

		resp, err := client.Do(req)
		if err != nil {
			// log.Printf("Failed to fetch data: %v, retrying...", err)
			time.Sleep(2 * time.Second)
			continue // retry
		}

		defer resp.Body.Close()

		// Read the response body
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			// log.Printf("Failed to read response body: %v, retrying...", err)
			time.Sleep(2 * time.Second)
			continue // retry
		}

		// Check if response contains an AllOrigins error
		if strings.Contains(string(body), "Oops") || strings.Contains(string(body), "Request Timeout") {
			// log.Printf("AllOrigins returned an error, retrying: %s", string(body))
			time.Sleep(2 * time.Second)
			continue // retry
		}

		// Check if response is valid JSON (AllOrigins JSON format)
		var allOriginsResponse struct {
			Contents string `json:"contents"`
		}
		if err := json.Unmarshal(body, &allOriginsResponse); err != nil {
			// log.Printf("Failed to parse AllOrigins response: %v, retrying...", err)
			time.Sleep(2 * time.Second)
			continue // retry
		}

		// Successfully parsed response
		return &http.Response{
			Body: ioutil.NopCloser(strings.NewReader(allOriginsResponse.Contents)),
		}
	}
}

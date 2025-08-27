package main

import (
	"bufio"
	"crypto/tls"
	"encoding/csv"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

type Config struct {
	Verbose      bool
	Proxy        string
	CustomHeader string
	Cookies      []string
	UserAgent    string
	Referer      string
	URLFile      string
	URL          string
	CSVName      string
	Threads      int
	Timeout      int
}

type CORSHeaders struct {
	ACAO string // Access-Control-Allow-Origin
	ACAC string // Access-Control-Allow-Credentials
	ACAM string // Access-Control-Allow-Methods
	ACAH string // Access-Control-Allow-Headers
	ACMA string // Access-Control-Max-Age
	ACEH string // Access-Control-Expose-Headers
}

type ScanResult struct {
	URL     string
	Origin  string
	Headers CORSHeaders
}

var (
	config     Config
	results    []ScanResult
	resultsMux sync.Mutex
	bar        *progressbar.ProgressBar
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "cors-scanner",
		Short: "A multi-threaded CORS vulnerability scanner",
		Long:  "A tool to help discover CORS misconfigurations by testing various origin header manipulations",
		Run:   runScanner,
	}

	rootCmd.Flags().BoolVarP(&config.Verbose, "verbose", "v", false, "increase output verbosity")
	rootCmd.Flags().StringVar(&config.Proxy, "proxy", "", "specify a proxy to use (127.0.0.1:8080)")
	rootCmd.Flags().StringVar(&config.CustomHeader, "custom-header", "", "specify a custom header and value, delimited with ~~~")
	rootCmd.Flags().StringSliceVarP(&config.Cookies, "cookies", "c", []string{}, "specify domain(s) and cookie(s) data delimited with ~~~")
	rootCmd.Flags().StringVar(&config.UserAgent, "useragent", "", "specify a User Agent string to use")
	rootCmd.Flags().StringVarP(&config.Referer, "referer", "r", "", "specify a referer string to use")
	rootCmd.Flags().StringVar(&config.URLFile, "url-file", "", "specify a file containing URLs")
	rootCmd.Flags().StringVarP(&config.URL, "url", "u", "", "specify a single URL")
	rootCmd.Flags().StringVar(&config.CSVName, "csv-name", "", "specify a CSV file name")
	rootCmd.Flags().IntVarP(&config.Threads, "threads", "t", 10, "specify number of threads")
	rootCmd.Flags().IntVar(&config.Timeout, "timeout", 10, "specify connection timeout in seconds")

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func runScanner(cmd *cobra.Command, args []string) {
	printBanner()
	
	urls, err := parseURLs()
	if err != nil {
		log.Fatal(err)
	}

	if !config.Verbose {
		bar = progressbar.Default(int64(len(urls)))
	}

	scanURLs(urls)
	
	// Clear progress bar before showing results
	if !config.Verbose && bar != nil {
		fmt.Print("\n")
	}
	printResults()
	writeCSV()
}

func printBanner() {
	banner := "CORS Scanner v1.0"
	author := "Habib0x"
	fmt.Println(strings.Repeat("=", len(banner)))
	fmt.Println(banner)
	fmt.Println(author)
	fmt.Println(strings.Repeat("=", len(banner)))
	fmt.Println()
	
	if config.Verbose {
		fmt.Printf("Threads: %d\n", config.Threads)
		fmt.Printf("Timeout: %d\n", config.Timeout)
		if config.Proxy != "" {
			fmt.Printf("Proxy: %s\n", config.Proxy)
		}
		fmt.Println()
	}
	
	time.Sleep(1 * time.Second)
}

func parseURLs() ([]string, error) {
	if config.URL == "" && config.URLFile == "" {
		return nil, fmt.Errorf("please specify a URL (-u) or an input file containing URLs (--url-file)")
	}
	
	if config.URL != "" && config.URLFile != "" {
		return nil, fmt.Errorf("please specify either a URL or a file, not both")
	}
	
	var urls []string
	
	if config.URLFile != "" {
		file, err := os.Open(config.URLFile)
		if err != nil {
			return nil, fmt.Errorf("cannot open file: %v", err)
		}
		defer file.Close()
		
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				urls = append(urls, line)
			}
		}
		
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading file: %v", err)
		}
	} else {
		if !strings.HasPrefix(config.URL, "http") {
			return nil, fmt.Errorf("please specify a URL in the format proto://address:port")
		}
		urls = []string{config.URL}
	}
	
	return urls, nil
}

func scanURLs(urls []string) {
	var wg sync.WaitGroup
	urlChan := make(chan string, len(urls))
	
	// Start workers
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range urlChan {
				testCORSPolicy(url)
				if !config.Verbose && bar != nil {
					bar.Add(1)
				}
			}
		}()
	}
	
	// Send URLs to workers
	for _, url := range urls {
		urlChan <- url
	}
	close(urlChan)
	
	wg.Wait()
}

func testCORSPolicy(targetURL string) {
	tests := []func(string){
		existingCORSPolicy,
		nullOrigin,
		reflectedOrigin,
		schemeOrigin,
		mangledFrontOrigin,
		mangledRearOrigin,
	}
	
	for _, test := range tests {
		test(targetURL)
	}
}

func getRandomUserAgent() string {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
		"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/43.0",
		"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36",
		"Mozilla/5.0 (X11; Linux i686; rv:30.0) Gecko/20100101 Firefox/42.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.38 Safari/537.36",
		"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)",
	}
	return userAgents[rand.Intn(len(userAgents))]
}

func buildHTTPClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	
	if config.Proxy != "" {
		proxyURL, err := url.Parse("http://" + config.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	
	return &http.Client{
		Transport: transport,
		Timeout:   time.Duration(config.Timeout) * time.Second,
	}
}

func makeRequest(client *http.Client, targetURL, origin string) (*http.Response, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	
	// Set User-Agent
	userAgent := config.UserAgent
	if userAgent == "" {
		userAgent = getRandomUserAgent()
	}
	req.Header.Set("User-Agent", userAgent)
	
	// Set Origin
	req.Header.Set("Origin", origin)
	
	// Set Referer if specified
	if config.Referer != "" {
		req.Header.Set("Referer", config.Referer)
	}
	
	// Set custom header if specified
	if config.CustomHeader != "" {
		parts := strings.Split(config.CustomHeader, "~~~")
		if len(parts) == 2 {
			req.Header.Set(parts[0], parts[1])
		}
	}
	
	// Set cookies if specified
	for _, cookieStr := range config.Cookies {
		parts := strings.Split(cookieStr, "~~~")
		if len(parts) == 2 {
			domain := parts[0]
			cookies := parts[1]
			
			parsedURL, err := url.Parse(targetURL)
			if err == nil && strings.Contains(domain, parsedURL.Host) {
				cookiePairs := strings.Split(cookies, ";")
				for _, pair := range cookiePairs {
					cookieParts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
					if len(cookieParts) == 2 {
						cookie := &http.Cookie{
							Name:  cookieParts[0],
							Value: cookieParts[1],
						}
						req.AddCookie(cookie)
					}
				}
			}
		}
	}
	
	return client.Do(req)
}

func parseCORSHeaders(resp *http.Response) CORSHeaders {
	headers := CORSHeaders{}
	
	if val := resp.Header.Get("Access-Control-Allow-Origin"); val != "" {
		headers.ACAO = strings.ReplaceAll(val, ",", ";")
	}
	if val := resp.Header.Get("Access-Control-Allow-Credentials"); val != "" {
		headers.ACAC = strings.ReplaceAll(val, ",", ";")
	}
	if val := resp.Header.Get("Access-Control-Allow-Methods"); val != "" {
		headers.ACAM = strings.ReplaceAll(val, ",", ";")
	}
	if val := resp.Header.Get("Access-Control-Allow-Headers"); val != "" {
		headers.ACAH = strings.ReplaceAll(val, ",", ";")
	}
	if val := resp.Header.Get("Access-Control-Max-Age"); val != "" {
		headers.ACMA = strings.ReplaceAll(val, ",", ";")
	}
	if val := resp.Header.Get("Access-Control-Expose-Headers"); val != "" {
		headers.ACEH = strings.ReplaceAll(val, ",", ";")
	}
	
	return headers
}

func hasCORSHeaders(headers CORSHeaders) bool {
	return headers.ACAO != "" || headers.ACAC != "" || headers.ACAM != "" ||
		   headers.ACAH != "" || headers.ACMA != "" || headers.ACEH != ""
}

func addResult(targetURL, origin string, headers CORSHeaders) {
	if hasCORSHeaders(headers) {
		resultsMux.Lock()
		results = append(results, ScanResult{
			URL:     targetURL,
			Origin:  origin,
			Headers: headers,
		})
		resultsMux.Unlock()
		
		if config.Verbose {
			fmt.Printf("Origin: %s\n", origin)
			if headers.ACAO != "" {
				fmt.Printf("ACAO: %s\n", headers.ACAO)
			}
			if headers.ACAC != "" {
				fmt.Printf("ACAC: %s\n", headers.ACAC)
			}
			if headers.ACAM != "" {
				fmt.Printf("ACAM: %s\n", headers.ACAM)
			}
			if headers.ACAH != "" {
				fmt.Printf("ACAH: %s\n", headers.ACAH)
			}
			if headers.ACMA != "" {
				fmt.Printf("ACMA: %s\n", headers.ACMA)
			}
			if headers.ACEH != "" {
				fmt.Printf("ACEH: %s\n", headers.ACEH)
			}
			fmt.Println()
		}
	}
}

func existingCORSPolicy(targetURL string) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	
	origin := parsedURL.Host
	client := buildHTTPClient()
	
	resp, err := makeRequest(client, targetURL, origin)
	if err != nil {
		if config.Verbose {
			fmt.Printf("Error making request: %v\n", err)
		}
		return
	}
	defer resp.Body.Close()
	
	headers := parseCORSHeaders(resp)
	addResult(targetURL, origin, headers)
}

func nullOrigin(targetURL string) {
	origin := "null"
	client := buildHTTPClient()
	
	resp, err := makeRequest(client, targetURL, origin)
	if err != nil {
		if config.Verbose {
			fmt.Printf("Error making request: %v\n", err)
		}
		return
	}
	defer resp.Body.Close()
	
	headers := parseCORSHeaders(resp)
	addResult(targetURL, origin, headers)
}

func reflectedOrigin(targetURL string) {
	const charset = "abcdefghijklmnopqrstuvwxyz"
	randomString := make([]byte, 12)
	for i := range randomString {
		randomString[i] = charset[rand.Intn(len(charset))]
	}
	
	origin := string(randomString) + ".com"
	client := buildHTTPClient()
	
	resp, err := makeRequest(client, targetURL, origin)
	if err != nil {
		if config.Verbose {
			fmt.Printf("Error making request: %v\n", err)
		}
		return
	}
	defer resp.Body.Close()
	
	headers := parseCORSHeaders(resp)
	addResult(targetURL, origin, headers)
}

func schemeOrigin(targetURL string) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	
	var origin string
	if parsedURL.Scheme == "https" {
		origin = "http://" + parsedURL.Host
	} else {
		origin = "https://" + parsedURL.Host
	}
	
	client := buildHTTPClient()
	
	resp, err := makeRequest(client, targetURL, origin)
	if err != nil {
		if config.Verbose {
			fmt.Printf("Error making request: %v\n", err)
		}
		return
	}
	defer resp.Body.Close()
	
	headers := parseCORSHeaders(resp)
	addResult(targetURL, origin, headers)
}

func mangledFrontOrigin(targetURL string) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	
	const charset = "abcdefghijklmnopqrstuvwxyz"
	randomString := make([]byte, 12)
	for i := range randomString {
		randomString[i] = charset[rand.Intn(len(charset))]
	}
	
	origin := string(randomString) + parsedURL.Host
	client := buildHTTPClient()
	
	resp, err := makeRequest(client, targetURL, origin)
	if err != nil {
		if config.Verbose {
			fmt.Printf("Error making request: %v\n", err)
		}
		return
	}
	defer resp.Body.Close()
	
	headers := parseCORSHeaders(resp)
	addResult(targetURL, origin, headers)
}

func mangledRearOrigin(targetURL string) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	
	const charset = "abcdefghijklmnopqrstuvwxyz"
	randomString := make([]byte, 12)
	for i := range randomString {
		randomString[i] = charset[rand.Intn(len(charset))]
	}
	
	hostParts := strings.Split(parsedURL.Host, ":")
	domainParts := strings.Split(hostParts[0], ".")
	
	var origin string
	if len(domainParts) > 1 {
		origin = domainParts[0] + "." + string(randomString) + "." + domainParts[len(domainParts)-1]
	} else {
		origin = hostParts[0] + "." + string(randomString) + ".com"
	}
	
	client := buildHTTPClient()
	
	resp, err := makeRequest(client, targetURL, origin)
	if err != nil {
		if config.Verbose {
			fmt.Printf("Error making request: %v\n", err)
		}
		return
	}
	defer resp.Body.Close()
	
	headers := parseCORSHeaders(resp)
	addResult(targetURL, origin, headers)
}

func printResults() {
	if len(results) == 0 {
		fmt.Println("\n[*] No CORS headers found in any responses.")
		return
	}

	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("CORS SCAN RESULTS - Found %d CORS configurations\n", len(results))
	fmt.Println(strings.Repeat("=", 70))

	for i, result := range results {
		fmt.Printf("\n[%d] URL: %s\n", i+1, result.URL)
		fmt.Printf("    Origin: %s\n", result.Origin)
		
		if result.Headers.ACAO != "" {
			fmt.Printf("    ✓ Access-Control-Allow-Origin: %s\n", result.Headers.ACAO)
		}
		if result.Headers.ACAC != "" {
			fmt.Printf("    ✓ Access-Control-Allow-Credentials: %s\n", result.Headers.ACAC)
		}
		if result.Headers.ACAM != "" {
			fmt.Printf("    ✓ Access-Control-Allow-Methods: %s\n", result.Headers.ACAM)
		}
		if result.Headers.ACAH != "" {
			fmt.Printf("    ✓ Access-Control-Allow-Headers: %s\n", result.Headers.ACAH)
		}
		if result.Headers.ACMA != "" {
			fmt.Printf("    ✓ Access-Control-Max-Age: %s\n", result.Headers.ACMA)
		}
		if result.Headers.ACEH != "" {
			fmt.Printf("    ✓ Access-Control-Expose-Headers: %s\n", result.Headers.ACEH)
		}
		
		// Add potential security implications
		if result.Headers.ACAO == "*" {
			fmt.Printf("    ⚠️  WARNING: Wildcard origin allows any domain!\n")
		}
		if result.Headers.ACAO == "null" {
			fmt.Printf("    ⚠️  WARNING: Null origin accepted - potential security risk!\n")
		}
		if result.Headers.ACAO != "" && result.Headers.ACAO != result.Origin && result.Headers.ACAO != "*" {
			fmt.Printf("    ⚠️  INFO: Origin reflection detected\n")
		}
		if result.Headers.ACAC == "true" && result.Headers.ACAO == "*" {
			fmt.Printf("    🚨 CRITICAL: Wildcard origin with credentials - major security flaw!\n")
		}
	}
	
	fmt.Println("\n" + strings.Repeat("-", 70))
	fmt.Printf("Summary: %d total CORS configurations found\n", len(results))
	fmt.Println(strings.Repeat("-", 70))
}

func writeCSV() {
	if len(results) == 0 {
		fmt.Println("\n[*] No CORS headers found in any responses.")
		return
	}
	
	csvName := config.CSVName
	if csvName == "" {
		csvName = "CORS_Results-" + time.Now().Format("02Jan2006150405") + ".csv"
	}
	
	fileExists := false
	if _, err := os.Stat(csvName); err == nil {
		fileExists = true
		fmt.Printf("\n[+] Appending to %s.\n", csvName)
	} else {
		fmt.Printf("\n[+] Writing to %s.\n", csvName)
	}
	
	file, err := os.OpenFile(csvName, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("Error opening CSV file: %v", err)
		return
	}
	defer file.Close()
	
	writer := csv.NewWriter(file)
	defer writer.Flush()
	
	// Write header if new file
	if !fileExists {
		header := []string{"URL", "Origin", "ACAO", "ACAC", "ACAM", "ACAH", "ACMA", "ACEH"}
		writer.Write(header)
	}
	
	// Write results
	for _, result := range results {
		record := []string{
			result.URL,
			result.Origin,
			result.Headers.ACAO,
			result.Headers.ACAC,
			result.Headers.ACAM,
			result.Headers.ACAH,
			result.Headers.ACMA,
			result.Headers.ACEH,
		}
		writer.Write(record)
	}
	
	fmt.Printf("[*] Complete! Found %d CORS configurations.\n", len(results))
}
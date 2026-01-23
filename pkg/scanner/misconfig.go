package scanner

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cyrenus-sec/http-cli/pkg/config"
)

// RunSecurityMisconfigScan implements OWASP API8:2023 - Security Misconfiguration checks
func RunSecurityMisconfigScan(cfg config.RequestConfig) []VulnerabilityResult {
	results := []VulnerabilityResult{}

	fmt.Println("→ Testing Security Misconfiguration (OWASP API8:2023)...")

	// 1. Check for missing security headers
	results = append(results, checkSecurityHeaders(cfg)...)

	// 2. Check for Cache-Control on sensitive endpoints
	results = append(results, checkCacheControl(cfg)...)

	// 3. Check for unnecessary HTTP verbs
	results = append(results, checkHTTPVerbs(cfg)...)

	// 4. Check for Content-Type validation
	results = append(results, checkContentTypeValidation(cfg)...)

	return results
}

func checkSecurityHeaders(cfg config.RequestConfig) []VulnerabilityResult {
	results := []VulnerabilityResult{}

	req, err := http.NewRequest("GET", cfg.URL, nil)
	if err != nil {
		return results
	}

	// Apply user headers
	for key, val := range cfg.Headers {
		req.Header.Set(key, val)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return results
	}
	defer resp.Body.Close()

	// Critical security headers to check
	securityHeaders := map[string]struct {
		severity    string
		description string
	}{
		"X-Content-Type-Options": {
			severity:    "Medium",
			description: "Prevents MIME-sniffing attacks",
		},
		"X-XSS-Protection": {
			severity:    "Low",
			description: "Legacy XSS filter (deprecated but some use it)",
		},
		"Content-Security-Policy": {
			severity:    "High",
			description: "Protects against XSS and injection attacks",
		},
		"Referrer-Policy": {
			severity:    "Low",
			description: "Controls referrer information leakage",
		},
		"Permissions-Policy": {
			severity:    "Low",
			description: "Controls browser feature access",
		},
	}

	for header, info := range securityHeaders {
		if resp.Header.Get(header) == "" {
			result := VulnerabilityResult{
				TestName:   "Security Misconfiguration - Missing Header",
				Payload:    header,
				Vulnerable: true,
				StatusCode: resp.StatusCode,
				Evidence:   fmt.Sprintf("Missing '%s': %s", header, info.description),
				Severity:   info.severity,
			}
			results = append(results, result)
		}
	}

	return results
}

func checkCacheControl(cfg config.RequestConfig) []VulnerabilityResult {
	results := []VulnerabilityResult{}

	req, err := http.NewRequest("GET", cfg.URL, nil)
	if err != nil {
		return results
	}

	for key, val := range cfg.Headers {
		req.Header.Set(key, val)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return results
	}
	defer resp.Body.Close()

	cacheControl := resp.Header.Get("Cache-Control")
	
	// Check if endpoint seems sensitive (contains auth, api, user, profile, etc.)
	urlLower := strings.ToLower(cfg.URL)
	isSensitive := strings.Contains(urlLower, "/api/") ||
		strings.Contains(urlLower, "/auth") ||
		strings.Contains(urlLower, "/admin") ||
		strings.Contains(urlLower, "/user") ||
		strings.Contains(urlLower, "/profile") ||
		strings.Contains(urlLower, "/account") ||
		strings.Contains(urlLower, "/dm") ||
		strings.Contains(urlLower, "/message")

	if isSensitive && cacheControl == "" {
		result := VulnerabilityResult{
			TestName:   "Security Misconfiguration - Missing Cache Control",
			Payload:    "N/A",
			Vulnerable: true,
			StatusCode: resp.StatusCode,
			Evidence:   "Sensitive endpoint missing Cache-Control header (OWASP API8 Scenario #2)",
			Severity:   "Medium",
		}
		results = append(results, result)
	} else if isSensitive && cacheControl != "" {
		// Check for insecure cache directives
		if !strings.Contains(strings.ToLower(cacheControl), "no-store") &&
			!strings.Contains(strings.ToLower(cacheControl), "no-cache") {
			result := VulnerabilityResult{
				TestName:   "Security Misconfiguration - Weak Cache Control",
				Payload:    cacheControl,
				Vulnerable: true,
				StatusCode: resp.StatusCode,
				Evidence:   "Sensitive endpoint allows caching (should use 'no-store' or 'no-cache')",
				Severity:   "Medium",
			}
			results = append(results, result)
		}
	}

	return results
}

func checkHTTPVerbs(cfg config.RequestConfig) []VulnerabilityResult {
	results := []VulnerabilityResult{}

	// Test potentially dangerous or unnecessary HTTP methods
	dangerousMethods := []string{"TRACE", "TRACK", "DEBUG"}
	unnecessaryMethods := []string{"HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"}

	client := &http.Client{Timeout: 5 * time.Second}

	// Test dangerous methods
	for _, method := range dangerousMethods {
		req, err := http.NewRequest(method, cfg.URL, nil)
		if err != nil {
			continue
		}

		for key, val := range cfg.Headers {
			req.Header.Set(key, val)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != 405 && resp.StatusCode != 501 {
			result := VulnerabilityResult{
				TestName:   "Security Misconfiguration - Dangerous HTTP Verb",
				Payload:    method,
				Vulnerable: true,
				StatusCode: resp.StatusCode,
				Evidence:   fmt.Sprintf("Dangerous HTTP method '%s' is enabled (should be disabled)", method),
				Severity:   "High",
			}
			results = append(results, result)
		}

		time.Sleep(100 * time.Millisecond)
	}

	// For unnecessary methods, just log if they're unexpectedly allowed
	allowedCount := 0
	for _, method := range unnecessaryMethods {
		req, err := http.NewRequest(method, cfg.URL, nil)
		if err != nil {
			continue
		}

		for key, val := range cfg.Headers {
			req.Header.Set(key, val)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Skip if properly rejected
		if resp.StatusCode == 405 || resp.StatusCode == 501 {
			continue
		}

		allowedCount++
		time.Sleep(100 * time.Millisecond)
	}

	// If many unnecessary methods are allowed, flag it
	if allowedCount >= 3 {
		result := VulnerabilityResult{
			TestName:   "Security Misconfiguration - Excessive HTTP Verbs",
			Payload:    fmt.Sprintf("%d unnecessary methods allowed", allowedCount),
			Vulnerable: true,
			StatusCode: 0,
			Evidence:   "Multiple unnecessary HTTP methods are enabled (principle of least privilege violation)",
			Severity:   "Low",
		}
		results = append(results, result)
	}

	return results
}

func checkContentTypeValidation(cfg config.RequestConfig) []VulnerabilityResult {
	results := []VulnerabilityResult{}

	// Test if API accepts unexpected content types
	unexpectedContentTypes := []string{
		"text/plain",
		"text/html",
		"application/x-www-form-urlencoded",
		"multipart/form-data",
	}

	client := &http.Client{Timeout: 5 * time.Second}

	for _, contentType := range unexpectedContentTypes {
		// Only test on POST/PUT endpoints
		if cfg.Method != "POST" && cfg.Method != "PUT" && cfg.Method != "PATCH" {
			continue
		}

		req, err := http.NewRequest(cfg.Method, cfg.URL, strings.NewReader("test=data"))
		if err != nil {
			continue
		}

		// Set the unexpected content-type
		req.Header.Set("Content-Type", contentType)

		// Apply other user headers
		for key, val := range cfg.Headers {
			if strings.ToLower(key) != "content-type" {
				req.Header.Set(key, val)
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// If server accepts it (200-299) when it shouldn't, it's a problem
		// But we need to be careful - some APIs legitimately accept multiple types
		// We'll only flag if it seems to process the data
		if resp.StatusCode >= 200 && resp.StatusCode < 300 && len(body) > 0 {
			// This is informational - not always a vulnerability
			result := VulnerabilityResult{
				TestName:   "Security Misconfiguration - Content-Type Flexibility",
				Payload:    contentType,
				Vulnerable: false, // Set to false as this is just informational
				StatusCode: resp.StatusCode,
				Evidence:   fmt.Sprintf("API accepts unexpected Content-Type: %s", contentType),
				Severity:   "Info",
			}
			results = append(results, result)
		}

		time.Sleep(100 * time.Millisecond)
	}

	return results
}

package scanner

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cyrenus-sec/http-cli/pkg/config"
)

func RunZeroTrustScan(cfg config.RequestConfig) []VulnerabilityResult {
	results := []VulnerabilityResult{}

	if cfg.Architecture != "zero-trust" {
		return results
	}

	fmt.Println("→ Testing Zero-Trust Architecture Compliance...")

	// 1. Check for Strict Transport Security (HSTS) - critical for Zero Trust
	results = append(results, checkStrictTransport(cfg)...)

	// 2. Check for weak ciphers (Zero trust requires modern crypto)
	results = append(results, checkStrongCrypto(cfg)...)
    
    // 3. Ubiquitous Authentication check
    // (If we access without auth headers and get 200, it violates "Never Trust, Always Verify")
    results = append(results, checkUbiquitousAuth(cfg)...)

	return results
}

func checkStrictTransport(cfg config.RequestConfig) []VulnerabilityResult {
    // Zero Trust requires HSTS with long duration and includeSubDomains
    
    req, _ := http.NewRequest("GET", cfg.URL, nil)
    
    // Apply user-provided headers
    for key, val := range cfg.Headers {
        req.Header.Set(key, val)
    }
    
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	
    result := VulnerabilityResult{
		TestName:   "Zero-Trust: HSTS Enforcement",
		Payload:    "N/A",
		Severity:   "High",
        Vulnerable: false,
	}

	if err != nil {
        return []VulnerabilityResult{}
    }
    defer resp.Body.Close()

    hsts := resp.Header.Get("Strict-Transport-Security")
    if hsts == "" {
        result.Vulnerable = true
        result.Evidence = "Missing HSTS header"
    } else if !strings.Contains(hsts, "includeSubDomains") {
        result.Vulnerable = true
        result.Evidence = "HSTS missing 'includeSubDomains' directive"
        result.Severity = "Medium"
    }

    return []VulnerabilityResult{result}
}

func checkStrongCrypto(cfg config.RequestConfig) []VulnerabilityResult {
     // Zero Trust requires TLS 1.2 or 1.3
     if !strings.HasPrefix(cfg.URL, "https://") {
         return []VulnerabilityResult{{
             TestName: "Zero-Trust: Encryption",
             Vulnerable: true, 
             Severity: "Critical",
             Evidence: "Plaintext HTTP used (Zero Trust requires encryption in transit)",
         }}
     }
     
     transport := &http.Transport{
         TLSClientConfig: &tls.Config{
             MinVersion: tls.VersionTLS12,
         },
     }
     client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
     _, err := client.Get(cfg.URL)
     
     result := VulnerabilityResult{
		TestName:   "Zero-Trust: Modern TLS",
		Payload:    "N/A",
		Severity:   "High",
        Vulnerable: false,
	}

     if err != nil {
          // If we can't connect with TLS 1.2+, it's bad or network error
          // Assuming bad config for this exercise
          result.Vulnerable = true
          result.Evidence = "Failed to connect using TLS 1.2+"
          return []VulnerabilityResult{result}
     }
     
     return []VulnerabilityResult{result}
}

func checkUbiquitousAuth(cfg config.RequestConfig) []VulnerabilityResult {
     // Try to access without user auth headers, but include other headers like Content-Type
     req, _ := http.NewRequest(cfg.Method, cfg.URL, nil)
     
     // Add non-auth headers only (skip Authorization, Cookie, etc.)
     for key, val := range cfg.Headers {
         lowerKey := strings.ToLower(key)
         if lowerKey != "authorization" && lowerKey != "cookie" {
             req.Header.Set(key, val)
         }
     }
     
     client := &http.Client{Timeout: 5 * time.Second}
     resp, err := client.Do(req)
     
     if err != nil { return []VulnerabilityResult{} }
     defer resp.Body.Close()
     
     if resp.StatusCode >= 200 && resp.StatusCode < 300 {
         return []VulnerabilityResult{{
             TestName: "Zero-Trust: Ubiquitous Authentication",
             Vulnerable: true,
             Severity: "High",
             Evidence: fmt.Sprintf("Publicly accessible endpoint (Status %d). Zero Trust implies 'Verify Explicitly' for all resources.", resp.StatusCode),
             StatusCode: resp.StatusCode,
         }}
     }
     
     return []VulnerabilityResult{}
}

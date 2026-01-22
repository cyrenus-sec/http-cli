package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/cyrenus-sec/http-cli/pkg/config"
)

type RBACRole struct {
	Name    string            `json:"name"`
	Headers map[string]string `json:"headers"`
}

type RBACConfiguration struct {
	Roles []RBACRole `json:"roles"`
}

func RunRBACScan(cfg config.RequestConfig) []VulnerabilityResult {
	results := []VulnerabilityResult{}

	if cfg.RBACConfig == "" {
		return results
	}

	fmt.Println("→ Testing RBAC (Privilege Escalation)...")

	// Load RBAC Configuration
	configFile, err := os.ReadFile(cfg.RBACConfig)
	if err != nil {
		fmt.Printf("  ⚠️ Failed to load RBAC config: %v\n", err)
		return results
	}

	var rbacConfig RBACConfiguration
	if err := json.Unmarshal(configFile, &rbacConfig); err != nil {
		fmt.Printf("  ⚠️ Failed to parse RBAC config: %v\n", err)
		return results
	}

	client := &http.Client{Timeout: 5 * time.Second}

	for _, role := range rbacConfig.Roles {
		req, err := http.NewRequest(cfg.Method, cfg.URL, nil)
		if err != nil {
			continue
		}

		// Set role headers
		for key, val := range role.Headers {
			req.Header.Set(key, val)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Analyze result
		// Logic: If we are scanning a protected resource, unprivileged roles should fail (401/403).
		// If they get 200, it MIGHT be a vulnerability.
		// Since we don't know the expected state, we report 200s for non-admin roles as "Potential".
		
		evidence := fmt.Sprintf("Role '%s' accessed endpoint with status %d", role.Name, resp.StatusCode)
		
		isVuln := false
		severity := "Info"

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// If it's a success code, flag it for manual review
			isVuln = true
			severity = "Medium" // Can't be critical without knowing intent, but worth flagging
            if role.Name == "anonymous" || role.Name == "guest" {
                severity = "High"
            }
		}

		result := VulnerabilityResult{
			TestName:   "RBAC Violation",
			Payload:    role.Name,
			Vulnerable: isVuln,
			StatusCode: resp.StatusCode,
			Evidence:   evidence,
			Severity:   severity,
		}
		results = append(results, result)
        time.Sleep(100 * time.Millisecond)
	}

	return results
}

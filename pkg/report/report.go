package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/cyrenus-sec/http-cli/pkg/scanner"
)

type ComplianceIssue struct {
	Standard    string `json:"standard"`
	Requirement string `json:"requirement"`
	Description string `json:"description"`
}

type ScanReport struct {
	Target          string                        `json:"target"`
	ScanTime        time.Time                     `json:"scan_time"`
	TotalTests      int                           `json:"total_tests"`
	Vulnerabilities []VulnerabilityReportItem     `json:"vulnerabilities"`
	Compliance      map[string][]ComplianceIssue  `json:"compliance_violations"`
}

type VulnerabilityReportItem struct {
	scanner.VulnerabilityResult
	ComplianceTags []ComplianceIssue `json:"compliance_tags"`
}

var pciMapping = map[string]string{
	"SQL Injection":          "PCI DSS 6.5.1 - Injection flaws (SQL, OS Command, etc.)",
	"XSS":                    "PCI DSS 6.5.7 - Cross-site scripting (XSS)",
	"Path Traversal":         "PCI DSS 6.5.8 - Improper access control",
	"Command Injection":      "PCI DSS 6.5.1 - Injection flaws",
	"Authentication Weakness": "PCI DSS 8.2.1 - Strong authentication methods",
	"SSL/TLS Configuration":  "PCI DSS 4.1 - Strong cryptography for sensitive data",
	"Information Disclosure": "PCI DSS 6.5.10 - Broken Authentication and Session Management (Indirectly related)",
	"XXE (XML External Entity)": "PCI DSS 6.5.1 - Injection flaws",
	"SSRF (Server-Side Request Forgery)": "PCI DSS 6.5.1 - Injection flaws",
	"IDOR (Insecure Direct Object Reference)": "PCI DSS 6.5.8 - Improper access control",
    "NoSQL Injection": "PCI DSS 6.5.1 - Injection flaws",
    "LDAP Injection": "PCI DSS 6.5.1 - Injection flaws",
}

var hipaaMapping = map[string]string{
	"SQL Injection":          "HIPAA 164.306(a)(1) - Ensure confidentiality, integrity, availability",
	"XSS":                    "HIPAA 164.306(a)(1) - Protection against malicious software",
	"Authentication Weakness": "HIPAA 164.312(d) - Person or Entity Authentication",
	"SSL/TLS Configuration":  "HIPAA 164.312(e)(1) - Transmission Security",
	"Information Disclosure": "HIPAA 164.312(b) - Audit controls (Leakage of logs/info)",
}

var gdprMapping = map[string]string{
	"SQL Injection":          "GDPR Art. 32 - Security of processing",
	"XSS":                    "GDPR Art. 32 - Security of processing",
	"Authentication Weakness": "GDPR Art. 32 - Security of processing",
	"Information Disclosure": "GDPR Art. 33 - Notification of a personal data breach",
    "SSL/TLS Configuration":  "GDPR Art. 32 - Encryption of personal data",
}

func GenerateReport(target string, results []scanner.VulnerabilityResult, formats []string, standards []string) error {
	report := ScanReport{
		Target:     target,
		ScanTime:   time.Now(),
		TotalTests: len(results),
        Compliance: make(map[string][]ComplianceIssue),
	}

	vulnItems := []VulnerabilityReportItem{}
	
    // Process results and map to compliance
	for _, res := range results {
		if !res.Vulnerable {
			continue
		}

		item := VulnerabilityReportItem{
			VulnerabilityResult: res,
			ComplianceTags:      []ComplianceIssue{},
		}

        // Map to standards
		for _, std := range standards {
			var mapping map[string]string
			switch std {
			case "pci":
				mapping = pciMapping
			case "hipaa":
				mapping = hipaaMapping
			case "gdpr":
				mapping = gdprMapping
			}

			if rule, ok := mapping[res.TestName]; ok {
				issue := ComplianceIssue{
					Standard:    std,
					Requirement: rule,
					Description: fmt.Sprintf("Vulnerability '%s' violates %s requirement: %s", res.TestName, std, rule),
				}
				item.ComplianceTags = append(item.ComplianceTags, issue)
                
                // Add to summary
                report.Compliance[std] = append(report.Compliance[std], issue)
			}
		}
		vulnItems = append(vulnItems, item)
	}
	report.Vulnerabilities = vulnItems

    // Print to stdout (text format)
	if contains(formats, "text") {
		printTextReport(report)
	}

    // JSON file report
    if contains(formats, "json") {
       file, _ := json.MarshalIndent(report, "", "  ")
       _ = os.WriteFile("security_report.json", file, 0644)
       fmt.Println("\n📄 JSON Report saved to security_report.json")
    }

	return nil
}

func printTextReport(report ScanReport) {
    if len(report.Compliance) > 0 {
	    fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	    fmt.Println("📋 COMPLIANCE REPORT")
	    fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        
        for std, issues := range report.Compliance {
            fmt.Printf("\n%s Violations (%d):\n", std, len(issues))
            seen := make(map[string]bool)
            for _, issue := range issues {
                if !seen[issue.Requirement] {
                     fmt.Printf("  - %s\n", issue.Requirement)
                     seen[issue.Requirement] = true
                }
            }
        }
    }
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

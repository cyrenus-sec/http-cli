package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/cyrenus-sec/http-cli/pkg/client"
	"github.com/cyrenus-sec/http-cli/pkg/config"
	"github.com/cyrenus-sec/http-cli/pkg/report"
	"github.com/cyrenus-sec/http-cli/pkg/scanner"
	"github.com/cyrenus-sec/http-cli/pkg/utils"
)

func main() {
	cfg := config.New()

	var headersRaw, formDataRaw, filesRaw string

	flag.StringVar(&cfg.Method, "X", "GET", "HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)")
	flag.StringVar(&cfg.URL, "url", "", "Request URL (required)")
	flag.StringVar(&headersRaw, "H", "", "Headers (format: 'Key1:Value1,Key2:Value2')")
	flag.StringVar(&cfg.Body, "d", "", "Request body data")
	flag.StringVar(&cfg.BodyFile, "data-file", "", "File containing request body")
	flag.StringVar(&formDataRaw, "F", "", "Form data (format: 'key1=value1,key2=value2')")
	flag.StringVar(&filesRaw, "f", "", "Files to upload (format: 'field1=@/path/to/file1,field2=@/path/to/file2')")
	flag.IntVar(&cfg.Timeout, "timeout", 30, "Request timeout in seconds")
	flag.BoolVar(&cfg.Verbose, "v", false, "Verbose output")
	flag.StringVar(&cfg.OutputFile, "o", "", "Save response to file")
	flag.BoolVar(&cfg.SecurityScan, "scan", false, "Run security vulnerability scan")
	flag.StringVar(&cfg.ScanType, "scan-type", "all", "Scan type: sql, xss, path, header, cmd, xxe, ssrf, idor, nosql, ldap, cors, clickjack, ssl, info, auth, all")

	// Enterprise features flags
	var compliance string
	flag.StringVar(&compliance, "compliance", "", "Internal compliance standards (pci, hipaa, gdpr)")
	flag.StringVar(&cfg.ReportFormat, "report-format", "text", "Report format (text, json, html)")
	flag.StringVar(&cfg.RBACConfig, "rbac-config", "", "Path to RBAC roles configuration file")
	flag.StringVar(&cfg.Architecture, "check-architecture", "", "Architecture check mode (e.g., zero-trust)")
	flag.BoolVar(&cfg.Redact, "redact", false, "Mask secrets/PII in outputs")
	flag.BoolVar(&cfg.AuditLog, "audit-log", false, "Generate signed audit log")


	flag.Parse()

	if cfg.URL == "" {
		fmt.Println("Error: URL is required")
		flag.Usage()
		os.Exit(1)
	}

	// Parse headers
	if headersRaw != "" {
		config.ParseKeyValue(headersRaw, cfg.Headers, ":")
	}

	// Parse form data
	if formDataRaw != "" {
		config.ParseKeyValue(formDataRaw, cfg.FormData, "=")
	}

	// Parse files
	if filesRaw != "" {
		config.ParseKeyValue(filesRaw, cfg.Files, "=")
	}
	
	// Parse compliance
	if compliance != "" {
		cfg.Compliance = strings.Split(compliance, ",")
	}

	// Run security scan if requested
	if cfg.SecurityScan {
		results, err := scanner.RunSecurityScan(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Security scan error: %v\n", err)
			os.Exit(1)
		}
		
        // Generate Compliance Report
        if len(cfg.Compliance) > 0 || cfg.ReportFormat != "text" {
            formats := strings.Split(cfg.ReportFormat, ",")
            // Default to text if not configured
            if cfg.ReportFormat == "text" && len(cfg.Compliance) > 0 {
                 formats = append(formats, "text")
            }
            
            report.GenerateReport(cfg.URL, results, formats, cfg.Compliance)
        }
        
        if cfg.AuditLog {
             logEntry := utils.GenerateAuditEntry(cfg.URL, "SCAN", "COMPLETED")
             appendAuditLog(logEntry)
        }
		return
	}

	// Execute request
	if err := client.ExecuteRequest(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        if cfg.AuditLog {
             logEntry := utils.GenerateAuditEntry(cfg.URL, cfg.Method, "ERROR")
             appendAuditLog(logEntry)
        }
		os.Exit(1)
	}
    
    if cfg.AuditLog {
         logEntry := utils.GenerateAuditEntry(cfg.URL, cfg.Method, "SUCCESS")
         appendAuditLog(logEntry)
    }
}

func appendAuditLog(entry string) {
    f, err := os.OpenFile("audit.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error writing to audit log: %v\n", err)
        return
    }
    defer f.Close()
    if _, err := f.WriteString(entry); err != nil {
        fmt.Fprintf(os.Stderr, "Error writing to audit log: %v\n", err)
    }
}

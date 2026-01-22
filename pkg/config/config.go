package config

import (
    "strings"
)

type RequestConfig struct {
	Method       string
	URL          string
	Headers      map[string]string
	Body         string
	BodyFile     string
	FormData     map[string]string
	Files        map[string]string
	Timeout      int
	Verbose      bool
	OutputFile   string
	SecurityScan bool
	ScanType     string
    // New fields for enterprise features
    Compliance   []string
    ReportFormat string
    RBACConfig   string
    Architecture string
    Redact       bool
    AuditLog     bool
}

func New() RequestConfig {
    return RequestConfig{
        Headers:  make(map[string]string),
        FormData: make(map[string]string),
        Files:    make(map[string]string),
    }
}

func ParseKeyValue(raw string, target map[string]string, sep string) {
	pairs := strings.Split(raw, ",")
	for _, pair := range pairs {
		parts := strings.SplitN(strings.TrimSpace(pair), sep, 2)
		if len(parts) == 2 {
			target[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
}

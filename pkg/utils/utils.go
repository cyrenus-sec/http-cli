package utils

import (
    "crypto/sha256"
    "fmt"
    "regexp"
    "time"
)

func Redact(input string) string {
    // Redact Authorization headers (Bearer, Basic)
    reAuth := regexp.MustCompile(`(Authorization:\s*)(Bearer|Basic)(\s+)([^"\s]+)`)
    input = reAuth.ReplaceAllString(input, "$1$2$3[REDACTED]")
    
    // Redact API Keys
    reApiKey := regexp.MustCompile(`(Key|Token|Secret)(\"?\s*[:=]\s*\"?)([^"\s,]+)`)
    input = reApiKey.ReplaceAllString(input, "$1$2[REDACTED]")
    
    return input
}

func GenerateAuditEntry(target string, action string, status string) string {
    timestamp := time.Now().Format(time.RFC3339)
    entry := fmt.Sprintf("[%s] ACTION=%s TARGET=%s STATUS=%s", timestamp, action, target, status)
    
    // Create hash
    hash := sha256.Sum256([]byte(entry))
    return fmt.Sprintf("%s SIGNATURE=%x\n", entry, hash)
}

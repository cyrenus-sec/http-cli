package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cyrenus-sec/http-cli/pkg/config"
	"github.com/cyrenus-sec/http-cli/pkg/utils"
)

func ExecuteRequest(cfg config.RequestConfig) error {
	var body io.Reader
	varcontentType := ""

	// Prepare request body
	if len(cfg.Files) > 0 || len(cfg.FormData) > 0 {
		// Multipart form data
		buf := &bytes.Buffer{}
		writer := multipart.NewWriter(buf)

		// Add form fields
		for key, val := range cfg.FormData {
			if err := writer.WriteField(key, val); err != nil {
				return fmt.Errorf("error writing form field: %w", err)
			}
		}

		// Add files
		for field, filepath := range cfg.Files {
			filepath = strings.TrimPrefix(filepath, "@")
			if err := addFileToMultipart(writer, field, filepath); err != nil {
				return err
			}
		}

		writer.Close()
		body = buf
		varcontentType = writer.FormDataContentType()
	} else if cfg.BodyFile != "" {
		// Read body from file
		data, err := os.ReadFile(cfg.BodyFile)
		if err != nil {
			return fmt.Errorf("error reading body file: %w", err)
		}
		body = bytes.NewReader(data)
	} else if cfg.Body != "" {
		// Use provided body
		body = strings.NewReader(cfg.Body)
	}

	// Create request
	req, err := http.NewRequest(cfg.Method, cfg.URL, body)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	// Set content type for multipart
	if varcontentType != "" {
		req.Header.Set("Content-Type", varcontentType)
	}

	// Add custom headers
	for key, val := range cfg.Headers {
		req.Header.Set(key, val)
	}

	// Create client with timeout
	client := &http.Client{
		Timeout: time.Duration(cfg.Timeout) * time.Second,
	}

	// Verbose output
	// Note: In a real refactor we might pass a logger or printer interface
	if cfg.Verbose {
		printRequest(req, cfg.Redact)
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
	printResponse(resp, respBody, duration, cfg.Verbose, cfg.Redact)

	// Save to file if requested
	if cfg.OutputFile != "" {
		if err := os.WriteFile(cfg.OutputFile, respBody, 0644); err != nil {
			return fmt.Errorf("error writing to file: %w", err)
		}
		fmt.Printf("\n✓ Response saved to: %s\n", cfg.OutputFile)
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

func printRequest(req *http.Request, redact bool) {
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("→ REQUEST\n")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("%s %s\n", req.Method, req.URL.String())
	fmt.Println("\nHeaders:")
	for key, values := range req.Header {
		for _, val := range values {
			line := fmt.Sprintf("  %s: %s", key, val)
			if redact {
				line = utils.Redact(line)
			}
			fmt.Println(line)
		}
	}
	fmt.Println()
}

func printResponse(resp *http.Response, body []byte, duration time.Duration, verbose bool, redact bool) {
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("← RESPONSE\n")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Time: %v\n", duration)

	if verbose {
		fmt.Println("\nHeaders:")
		for key, values := range resp.Header {
			for _, val := range values {
				line := fmt.Sprintf("  %s: %s", key, val)
				if redact {
					line = utils.Redact(line)
				}
				fmt.Println(line)
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

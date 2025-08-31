package checks

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/PrebenVerEecke/omnidocsscanner/internal/session"
)

func init() {
	Register(&HeaderCheck{})
	Register(&CORSCheck{})
	Register(&SecurityHeadersCheck{})
}

// HeaderCheck checks for basic header information and misconfigurations
type HeaderCheck struct{}

func (c *HeaderCheck) ID() string {
	return "headers-basic"
}

func (c *HeaderCheck) Severity() string {
	return SeverityInfo
}

func (c *HeaderCheck) Title() string {
	return "Basic Header Analysis"
}

func (c *HeaderCheck) Run(ctx context.Context, sess *session.Session, baseURL string, cfg interface{}) ([]Finding, error) {
	var findings []Finding

	req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/", nil)
	if err != nil {
		return nil, err
	}

	resp, err := sess.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check for server information disclosure
	if server := resp.Header.Get("Server"); server != "" {
		findings = append(findings, Finding{
			CheckID:   c.ID(),
			Severity:  SeverityLow,
			Title:     "Server Header Disclosure",
			Summary:   fmt.Sprintf("Server header reveals: %s", server),
			Endpoint:  "/",
			Evidence:  fmt.Sprintf("Server: %s", server),
			Remediate: "Remove or obfuscate Server header to prevent information disclosure",
		})
	}

	// Check for X-Powered-By header
	if poweredBy := resp.Header.Get("X-Powered-By"); poweredBy != "" {
		findings = append(findings, Finding{
			CheckID:   c.ID(),
			Severity:  SeverityLow,
			Title:     "X-Powered-By Header Disclosure",
			Summary:   fmt.Sprintf("Technology stack revealed: %s", poweredBy),
			Endpoint:  "/",
			Evidence:  fmt.Sprintf("X-Powered-By: %s", poweredBy),
			Remediate: "Remove X-Powered-By header to prevent technology fingerprinting",
		})
	}

	// Check for version information in headers
	for key, values := range resp.Header {
		for _, value := range values {
			if strings.Contains(strings.ToLower(value), "version") ||
			   strings.Contains(strings.ToLower(value), "v1") ||
			   strings.Contains(strings.ToLower(value), "v2") {
				findings = append(findings, Finding{
					CheckID:   c.ID(),
					Severity:  SeverityInfo,
					Title:     "Version Information in Headers",
					Summary:   fmt.Sprintf("Header %s contains version info: %s", key, value),
					Endpoint:  "/",
					Evidence:  fmt.Sprintf("%s: %s", key, value),
					Remediate: "Consider removing version information from headers",
				})
			}
		}
	}

	return findings, nil
}

// CORSCheck checks for CORS misconfigurations
type CORSCheck struct{}

func (c *CORSCheck) ID() string {
	return "cors-misconfig"
}

func (c *CORSCheck) Severity() string {
	return SeverityHigh
}

func (c *CORSCheck) Title() string {
	return "CORS Misconfiguration Check"
}

func (c *CORSCheck) Run(ctx context.Context, sess *session.Session, baseURL string, cfg interface{}) ([]Finding, error) {
	var findings []Finding

	// Test with Origin header
	req, err := http.NewRequestWithContext(ctx, "OPTIONS", baseURL+"/", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Origin", "https://evil.com")

	resp, err := sess.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check for wildcard CORS
	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowCredentials := resp.Header.Get("Access-Control-Allow-Credentials")

	if allowOrigin == "*" && allowCredentials == "true" {
		findings = append(findings, Finding{
			CheckID:   c.ID(),
			Severity:  SeverityCritical,
			Title:     "Critical CORS Misconfiguration",
			Summary:   "Wildcard origin (*) with credentials enabled allows any site to make authenticated requests",
			Endpoint:  "/",
			Evidence:  fmt.Sprintf("Access-Control-Allow-Origin: %s, Access-Control-Allow-Credentials: %s", allowOrigin, allowCredentials),
			Remediate: "Set specific allowed origins instead of wildcard, or disable credentials for wildcard origin",
		})
	} else if allowOrigin == "*" {
		findings = append(findings, Finding{
			CheckID:   c.ID(),
			Severity:  SeverityMedium,
			Title:     "CORS Wildcard Origin",
			Summary:   "Wildcard origin (*) allows any site to read responses",
			Endpoint:  "/",
			Evidence:  fmt.Sprintf("Access-Control-Allow-Origin: %s", allowOrigin),
			Remediate: "Specify explicit allowed origins instead of using wildcard",
		})
	}

	return findings, nil
}

// SecurityHeadersCheck checks for missing security headers
type SecurityHeadersCheck struct{}

func (c *SecurityHeadersCheck) ID() string {
	return "security-headers"
}

func (c *SecurityHeadersCheck) Severity() string {
	return SeverityMedium
}

func (c *SecurityHeadersCheck) Title() string {
	return "Security Headers Analysis"
}

func (c *SecurityHeadersCheck) Run(ctx context.Context, sess *session.Session, baseURL string, cfg interface{}) ([]Finding, error) {
	var findings []Finding

	req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/", nil)
	if err != nil {
		return nil, err
	}

	resp, err := sess.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	headers := resp.Header

	// Check for X-Frame-Options
	if xfo := headers.Get("X-Frame-Options"); xfo == "" {
		findings = append(findings, Finding{
			CheckID:   c.ID(),
			Severity:  SeverityMedium,
			Title:     "Missing X-Frame-Options Header",
			Summary:   "Application is vulnerable to clickjacking attacks",
			Endpoint:  "/",
			Evidence:  "X-Frame-Options header not present",
			Remediate: "Add X-Frame-Options: DENY or SAMEORIGIN header",
		})
	}

	// Check for X-Content-Type-Options
	if xcto := headers.Get("X-Content-Type-Options"); xcto == "" {
		findings = append(findings, Finding{
			CheckID:   c.ID(),
			Severity:  SeverityMedium,
			Title:     "Missing X-Content-Type-Options Header",
			Summary:   "Browser may perform MIME type sniffing",
			Endpoint:  "/",
			Evidence:  "X-Content-Type-Options header not present",
			Remediate: "Add X-Content-Type-Options: nosniff header",
		})
	}

	// Check for Referrer-Policy
	if rp := headers.Get("Referrer-Policy"); rp == "" {
		findings = append(findings, Finding{
			CheckID:   c.ID(),
			Severity:  SeverityLow,
			Title:     "Missing Referrer-Policy Header",
			Summary:   "Referrer information may be leaked",
			Endpoint:  "/",
			Evidence:  "Referrer-Policy header not present",
			Remediate: "Add Referrer-Policy header (e.g., strict-origin-when-cross-origin)",
		})
	}

	// Check for Content-Security-Policy
	if csp := headers.Get("Content-Security-Policy"); csp == "" {
		findings = append(findings, Finding{
			CheckID:   c.ID(),
			Severity:  SeverityMedium,
			Title:     "Missing Content-Security-Policy Header",
			Summary:   "No CSP protection against XSS attacks",
			Endpoint:  "/",
			Evidence:  "Content-Security-Policy header not present",
			Remediate: "Implement Content-Security-Policy header",
		})
	}

	return findings, nil
}

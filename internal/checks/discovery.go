package checks

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/prebenvereecke/newgenone-pentest/internal/session"
)

func init() {
	Register(&DiscoveryCheck{})
	Register(&APIDocsCheck{})
	Register(&OpenDirCheck{})
}

// DiscoveryCheck performs basic discovery of common endpoints
type DiscoveryCheck struct{}

func (c *DiscoveryCheck) ID() string {
	return "discovery-basic"
}

func (c *DiscoveryCheck) Severity() string {
	return SeverityInfo
}

func (c *DiscoveryCheck) Title() string {
	return "Basic Endpoint Discovery"
}

func (c *DiscoveryCheck) Run(ctx context.Context, sess *session.Session, baseURL string, cfg interface{}) ([]Finding, error) {
	var findings []Finding

	// Common endpoints to check
	endpoints := []struct {
		path     string
		desc     string
		severity string
	}{
		{"/robots.txt", "Robots.txt file", SeverityInfo},
		{"/sitemap.xml", "Sitemap file", SeverityInfo},
		{"/health", "Health check endpoint", SeverityLow},
		{"/status", "Status endpoint", SeverityLow},
		{"/api/health", "API health endpoint", SeverityLow},
		{"/actuator", "Spring Boot actuator", SeverityMedium},
		{"/actuator/health", "Spring Boot health actuator", SeverityMedium},
		{"/metrics", "Metrics endpoint", SeverityMedium},
		{"/version", "Version information", SeverityMedium},
		{"/api/version", "API version information", SeverityMedium},
		{"/manage", "Management endpoint", SeverityMedium},
		{"/admin", "Admin interface", SeverityHigh},
		{"/administrator", "Admin interface", SeverityHigh},
		{"/wp-admin", "WordPress admin", SeverityMedium},
		{"/.git/", "Git repository", SeverityHigh},
		{"/.env", "Environment file", SeverityHigh},
		{"/.DS_Store", "macOS metadata", SeverityLow},
		{"/WEB-INF/", "Java web app internals", SeverityHigh},
		{"/server-status", "Apache server status", SeverityMedium},
		{"/server-info", "Apache server info", SeverityMedium},
	}

	for _, endpoint := range endpoints {
		if err := ctx.Err(); err != nil {
			return findings, err
		}

		fullURL := strings.TrimSuffix(baseURL, "/") + endpoint.path

		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
		if err != nil {
			continue
		}

		resp, err := sess.Client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			findings = append(findings, Finding{
				CheckID:   c.ID(),
				Severity:  endpoint.severity,
				Title:     fmt.Sprintf("Discovered %s", endpoint.desc),
				Summary:   fmt.Sprintf("Found accessible %s at %s", endpoint.desc, endpoint.path),
				Endpoint:  endpoint.path,
				Evidence:  fmt.Sprintf("HTTP %d response", resp.StatusCode),
				Remediate: c.getRemediation(endpoint.path),
			})
		}
	}

	return findings, nil
}

func (c *DiscoveryCheck) getRemediation(path string) string {
	switch {
	case strings.Contains(path, "/.git"):
		return "Remove .git directory from production or restrict access"
	case strings.Contains(path, "/.env"):
		return "Remove .env file from web root or restrict access"
	case strings.Contains(path, "/admin"):
		return "Restrict admin interface access with authentication/authorization"
	case strings.Contains(path, "/actuator"):
		return "Restrict actuator endpoints to internal networks only"
	case strings.Contains(path, "/metrics"):
		return "Restrict metrics endpoints to monitoring systems only"
	case strings.Contains(path, "/WEB-INF"):
		return "WEB-INF directory should not be accessible via HTTP"
	default:
		return "Restrict access to this endpoint or remove if not needed"
	}
}

// APIDocsCheck discovers API documentation endpoints
type APIDocsCheck struct{}

func (c *APIDocsCheck) ID() string {
	return "api-docs-discovery"
}

func (c *APIDocsCheck) Severity() string {
	return SeverityMedium
}

func (c *APIDocsCheck) Title() string {
	return "API Documentation Discovery"
}

func (c *APIDocsCheck) Run(ctx context.Context, sess *session.Session, baseURL string, cfg interface{}) ([]Finding, error) {
	var findings []Finding

	// Common API documentation endpoints
	apiDocs := []struct {
		path     string
		desc     string
		severity string
	}{
		{"/swagger.json", "Swagger/OpenAPI specification", SeverityMedium},
		{"/openapi.json", "OpenAPI specification", SeverityMedium},
		{"/v3/api-docs", "Spring Boot API docs", SeverityMedium},
		{"/api-docs", "API documentation", SeverityMedium},
		{"/swagger-ui.html", "Swagger UI interface", SeverityHigh},
		{"/swagger-ui/", "Swagger UI interface", SeverityHigh},
		{"/api-explorer", "API explorer interface", SeverityHigh},
		{"/graphiql", "GraphQL interface", SeverityHigh},
		{"/graphql", "GraphQL endpoint", SeverityMedium},
		{"/playground", "GraphQL playground", SeverityHigh},
	}

	for _, doc := range apiDocs {
		if err := ctx.Err(); err != nil {
			return findings, err
		}

		fullURL := strings.TrimSuffix(baseURL, "/") + doc.path

		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
		if err != nil {
			continue
		}

		resp, err := sess.Client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			findings = append(findings, Finding{
				CheckID:   c.ID(),
				Severity:  doc.severity,
				Title:     fmt.Sprintf("API Documentation Exposed: %s", doc.desc),
				Summary:   fmt.Sprintf("Found accessible %s at %s", doc.desc, doc.path),
				Endpoint:  doc.path,
				Evidence:  fmt.Sprintf("HTTP %d response", resp.StatusCode),
				Remediate: "Restrict API documentation access to authorized users only, or disable in production",
			})
		}
	}

	return findings, nil
}

// OpenDirCheck checks for open directory listings
type OpenDirCheck struct{}

func (c *OpenDirCheck) ID() string {
	return "open-directory"
}

func (c *OpenDirCheck) Severity() string {
	return SeverityMedium
}

func (c *OpenDirCheck) Title() string {
	return "Open Directory Listing Check"
}

func (c *OpenDirCheck) Run(ctx context.Context, sess *session.Session, baseURL string, cfg interface{}) ([]Finding, error) {
	var findings []Finding

	// Common directories to check
	dirs := []string{
		"/static/",
		"/public/",
		"/uploads/",
		"/files/",
		"/documents/",
		"/assets/",
		"/js/",
		"/css/",
		"/images/",
		"/backup/",
		"/backups/",
		"/tmp/",
		"/temp/",
		"/cache/",
	}

	for _, dir := range dirs {
		if err := ctx.Err(); err != nil {
			return findings, err
		}

		fullURL := strings.TrimSuffix(baseURL, "/") + dir

		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
		if err != nil {
			continue
		}

		resp, err := sess.Client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// Check if response looks like a directory listing
			contentType := resp.Header.Get("Content-Type")
			if strings.Contains(contentType, "text/html") {
				findings = append(findings, Finding{
					CheckID:   c.ID(),
					Severity:  SeverityMedium,
					Title:     "Open Directory Listing",
					Summary:   fmt.Sprintf("Directory %s allows listing", dir),
					Endpoint:  dir,
					Evidence:  fmt.Sprintf("HTTP %d, Content-Type: %s", resp.StatusCode, contentType),
					Remediate: "Disable directory listing in web server configuration or add index file",
				})
			}
		}
	}

	return findings, nil
}

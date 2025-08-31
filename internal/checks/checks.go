package checks

import (
	"context"
	"newgenone-pentest/internal/session"
)

// Severity levels for findings
const (
	SeverityInfo     = "INFO"
	SeverityLow      = "LOW"
	SeverityMedium   = "MEDIUM"
	SeverityHigh     = "HIGH"
	SeverityCritical = "CRITICAL"
)

// Finding represents a security finding
type Finding struct {
	CheckID   string `json:"check_id"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	Summary   string `json:"summary"`
	Endpoint  string `json:"endpoint"`
	Evidence  string `json:"evidence"`
	Remediate string `json:"remediate"`
}

// Check interface that all security checks must implement
type Check interface {
	ID() string
	Severity() string
	Title() string
	Run(ctx context.Context, sess *session.Session, baseURL string, cfg interface{}) ([]Finding, error)
}

// Registry holds all registered checks
var Registry []Check

// Register adds a check to the registry
func Register(check Check) {
	Registry = append(Registry, check)
}

// GetChecksBySeverity returns checks filtered by severity
func GetChecksBySeverity(severity string) []Check {
	var filtered []Check
	for _, check := range Registry {
		if check.Severity() == severity {
			filtered = append(filtered, check)
		}
	}
	return filtered
}

// GetCheckByID returns a check by its ID
func GetCheckByID(id string) Check {
	for _, check := range Registry {
		if check.ID() == id {
			return check
		}
	}
	return nil
}

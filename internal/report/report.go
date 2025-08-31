package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/fatih/color"
	"newgenone-pentest/internal/checks"
)

// Report represents a complete security assessment report
type Report struct {
	Title       string                 `json:"title"`
	Timestamp   time.Time              `json:"timestamp"`
	BaseURL     string                 `json:"base_url"`
	Config      map[string]interface{} `json:"config"`
	Findings    []checks.Finding       `json:"findings"`
	Summary     ReportSummary          `json:"summary"`
}

// ReportSummary provides statistics about the findings
type ReportSummary struct {
	TotalFindings int            `json:"total_findings"`
	SeverityCount map[string]int `json:"severity_count"`
	CheckCount    map[string]int `json:"check_count"`
}

// Writer interface for different output formats
type Writer interface {
	Write(report *Report) error
}

// ConsoleWriter writes to console with colored table
type ConsoleWriter struct {
	Quiet  bool
	Verbose bool
}

func (w *ConsoleWriter) Write(report *Report) error {
	if w.Quiet {
		return nil
	}

	fmt.Printf("\n🔍 NewgenONE Security Assessment Report\n")
	fmt.Printf("Target: %s\n", report.BaseURL)
	fmt.Printf("Generated: %s\n", report.Timestamp.Format(time.RFC3339))
	fmt.Printf("Total Findings: %d\n\n", report.Summary.TotalFindings)

	if len(report.Findings) == 0 {
		fmt.Println("✅ No security issues found!")
		return nil
	}

	// Create table
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleLight)

	// Set header
	t.SetTitle("Security Findings")
	t.AppendHeader(table.Row{"Severity", "Check", "Endpoint", "Title", "Summary"})

	// Sort findings by severity
	sort.Slice(report.Findings, func(i, j int) bool {
		return getSeverityWeight(report.Findings[i].Severity) > getSeverityWeight(report.Findings[j].Severity)
	})

	// Add rows with color coding
	for _, finding := range report.Findings {
		severity := colorSeverity(finding.Severity, finding.Severity)
		checkID := finding.CheckID
		endpoint := finding.Endpoint
		title := finding.Title

		// Truncate summary if too long
		summary := finding.Summary
		if len(summary) > 80 {
			summary = summary[:77] + "..."
		}

		t.AppendRow(table.Row{severity, checkID, endpoint, title, summary})

		if w.Verbose {
			fmt.Printf("\n📋 Evidence: %s\n", finding.Evidence)
			fmt.Printf("🔧 Remediation: %s\n\n", finding.Remediate)
		}
	}

	t.Render()

	// Print summary
	fmt.Printf("\n📊 Summary by Severity:\n")
	for severity, count := range report.Summary.SeverityCount {
		fmt.Printf("  %s: %d\n", colorSeverity(severity, severity), count)
	}

	return nil
}

func colorSeverity(severity, text string) string {
	switch severity {
	case checks.SeverityCritical:
		return color.New(color.FgRed, color.Bold).Sprint(text)
	case checks.SeverityHigh:
		return color.New(color.FgRed).Sprint(text)
	case checks.SeverityMedium:
		return color.New(color.FgYellow).Sprint(text)
	case checks.SeverityLow:
		return color.New(color.FgBlue).Sprint(text)
	case checks.SeverityInfo:
		return color.New(color.FgCyan).Sprint(text)
	default:
		return text
	}
}

func getSeverityWeight(severity string) int {
	switch severity {
	case checks.SeverityCritical:
		return 5
	case checks.SeverityHigh:
		return 4
	case checks.SeverityMedium:
		return 3
	case checks.SeverityLow:
		return 2
	case checks.SeverityInfo:
		return 1
	default:
		return 0
	}
}

// JSONWriter writes findings to JSON file
type JSONWriter struct {
	FilePath string
}

func (w *JSONWriter) Write(report *Report) error {
	if w.FilePath == "" {
		return nil
	}

	file, err := os.Create(w.FilePath)
	if err != nil {
		return fmt.Errorf("failed to create JSON file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("failed to write JSON: %w", err)
	}

	fmt.Printf("📄 Report written to %s\n", w.FilePath)
	return nil
}

// SARIFWriter writes findings in SARIF 2.1.0 format
type SARIFWriter struct {
	FilePath string
}

func (w *SARIFWriter) Write(report *Report) error {
	if w.FilePath == "" {
		return nil
	}

	sarif := w.convertToSARIF(report)

	file, err := os.Create(w.FilePath)
	if err != nil {
		return fmt.Errorf("failed to create SARIF file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(sarif); err != nil {
		return fmt.Errorf("failed to write SARIF: %w", err)
	}

	fmt.Printf("📄 SARIF report written to %s\n", w.FilePath)
	return nil
}

func (w *SARIFWriter) convertToSARIF(report *Report) map[string]interface{} {
	runs := []map[string]interface{}{
		{
			"tool": map[string]interface{}{
				"driver": map[string]interface{}{
					"name":           "newgenone-pentest",
					"version":        "0.1.0",
					"informationUri": "https://github.com/newgenone-pentest",
					"rules":          w.buildRules(report.Findings),
				},
			},
			"results": w.buildResults(report.Findings),
		},
	}

	return map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"runs":    runs,
	}
}

func (w *SARIFWriter) buildRules(findings []checks.Finding) []map[string]interface{} {
	ruleMap := make(map[string]bool)
	var rules []map[string]interface{}

	for _, finding := range findings {
		if ruleMap[finding.CheckID] {
			continue
		}
		ruleMap[finding.CheckID] = true

		rules = append(rules, map[string]interface{}{
			"id": finding.CheckID,
			"name": finding.Title,
			"shortDescription": map[string]interface{}{
				"text": finding.Summary,
			},
			"help": map[string]interface{}{
				"text": finding.Remediate,
			},
			"properties": map[string]interface{}{
				"severity": finding.Severity,
			},
		})
	}

	return rules
}

func (w *SARIFWriter) buildResults(findings []checks.Finding) []map[string]interface{} {
	var results []map[string]interface{}

	for _, finding := range findings {
		result := map[string]interface{}{
			"ruleId": finding.CheckID,
			"level":  w.convertSeverityToLevel(finding.Severity),
			"message": map[string]interface{}{
				"text": finding.Summary,
			},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]interface{}{
							"uri": finding.Endpoint,
						},
					},
				},
			},
		}

		if finding.Evidence != "" {
			result["properties"] = map[string]interface{}{
				"evidence": finding.Evidence,
			}
		}

		results = append(results, result)
	}

	return results
}

func (w *SARIFWriter) convertSeverityToLevel(severity string) string {
	switch severity {
	case checks.SeverityCritical:
		return "error"
	case checks.SeverityHigh:
		return "error"
	case checks.SeverityMedium:
		return "warning"
	case checks.SeverityLow:
		return "note"
	case checks.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}

// GenerateReport creates a report from findings
func GenerateReport(baseURL string, config map[string]interface{}, findings []checks.Finding) *Report {
	report := &Report{
		Title:     "NewgenONE Security Assessment",
		Timestamp: time.Now(),
		BaseURL:   baseURL,
		Config:    config,
		Findings:  findings,
		Summary: ReportSummary{
			TotalFindings: len(findings),
			SeverityCount: make(map[string]int),
			CheckCount:    make(map[string]int),
		},
	}

	// Calculate summary statistics
	for _, finding := range findings {
		report.Summary.SeverityCount[finding.Severity]++
		report.Summary.CheckCount[finding.CheckID]++
	}

	return report
}

// WriteReport writes the report to all specified outputs
func WriteReport(report *Report, consoleWriter *ConsoleWriter, jsonWriter *JSONWriter, sarifWriter *SARIFWriter) error {
	writers := []Writer{consoleWriter}

	if jsonWriter != nil && jsonWriter.FilePath != "" {
		writers = append(writers, jsonWriter)
	}

	if sarifWriter != nil && sarifWriter.FilePath != "" {
		writers = append(writers, sarifWriter)
	}

	for _, writer := range writers {
		if err := writer.Write(report); err != nil {
			return err
		}
	}

	return nil
}

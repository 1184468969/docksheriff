package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/1184468969/docksheriff/internal/audit"
	"github.com/1184468969/docksheriff/internal/safe"
)

// JSON writes one schema-versioned report with no terminal styling.
func JSON(writer io.Writer, report Report) error {
	report = sanitizeReport(report)
	if report.Findings == nil {
		report.Findings = []audit.Finding{}
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	return encoder.Encode(report)
}

func sanitizeReport(report Report) Report {
	report.GeneratedAt = safe.Text(report.GeneratedAt)
	report.Docker.Endpoint = safe.Text(report.Docker.Endpoint)
	report.Docker.ServerVersion = safe.Text(report.Docker.ServerVersion)
	report.Docker.APIVersion = safe.Text(report.Docker.APIVersion)
	report.Findings = append([]audit.Finding(nil), report.Findings...)
	for index := range report.Findings {
		finding := &report.Findings[index]
		finding.RuleID = safe.Text(finding.RuleID)
		finding.Container = safe.Text(finding.Container)
		finding.Image = safe.Text(finding.Image)
		finding.Summary = safe.Text(finding.Summary)
		finding.Risk = safe.Text(finding.Risk)
		finding.Remediation = safe.Text(finding.Remediation)
	}
	return report
}

// Table writes human-oriented finding blocks and a complete summary.
func Table(writer io.Writer, report Report, minimum audit.Severity) error {
	var builder strings.Builder
	builder.WriteString("DockSheriff\n")
	fmt.Fprintf(&builder, "Docker:  %s (server %s, API %s)\n",
		safe.Text(report.Docker.Endpoint),
		fallback(safe.Text(report.Docker.ServerVersion)),
		fallback(safe.Text(report.Docker.APIVersion)),
	)
	fmt.Fprintf(&builder, "Scanned: %d container(s)\n\n", report.ScannedContainers)

	expanded := 0
	for _, finding := range report.Findings {
		severity := audit.Severity(finding.Severity)
		if severity < minimum {
			continue
		}
		expanded++
		fmt.Fprintf(&builder, "%s %s  %s\n",
			strings.ToUpper(severity.String()),
			safe.Text(finding.RuleID),
			safe.Text(finding.Summary),
		)
		if finding.Container != "" {
			fmt.Fprintf(&builder, "Container: %s\n", safe.Text(finding.Container))
		}
		if finding.Image != "" {
			fmt.Fprintf(&builder, "Image:     %s\n", safe.Text(finding.Image))
		}
		fmt.Fprintf(&builder, "Why:      %s\n", safe.Text(finding.Risk))
		fmt.Fprintf(&builder, "Fix:      %s\n\n", safe.Text(finding.Remediation))
	}
	if expanded == 0 {
		fmt.Fprintf(&builder, "No findings at or above %s.\n\n", minimum.String())
	}
	fmt.Fprintf(&builder, "Summary: critical=%d high=%d medium=%d low=%d info=%d total=%d\n",
		report.Summary.Critical,
		report.Summary.High,
		report.Summary.Medium,
		report.Summary.Low,
		report.Summary.Info,
		report.Summary.Total,
	)
	_, err := io.WriteString(writer, builder.String())
	return err
}

// Rules writes stable metadata for all built-in rules.
func Rules(writer io.Writer) error {
	var builder strings.Builder
	for _, rule := range audit.Rules {
		fmt.Fprintf(&builder, "%s %-8s %s\n", rule.ID, rule.Severity.String(), rule.Summary)
	}
	_, err := io.WriteString(writer, builder.String())
	return err
}

// Explain writes the risk and remediation for one rule.
func Explain(writer io.Writer, rule audit.Rule) error {
	_, err := fmt.Fprintf(writer, "%s [%s] %s\nWhy: %s\nFix: %s\n",
		rule.ID, rule.Severity.String(), rule.Summary, rule.Risk, rule.Remediation)
	return err
}

func fallback(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}

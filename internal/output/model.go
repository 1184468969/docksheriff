// Package output defines and renders DockSheriff's public output contracts.
package output

import "github.com/1184468969/docksheriff/internal/audit"

// SchemaVersion changes only when the JSON contract changes incompatibly.
const SchemaVersion = "1"

type DockerMetadata struct {
	Endpoint      string `json:"endpoint"`
	ServerVersion string `json:"server_version"`
	APIVersion    string `json:"api_version"`
}

type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

type Report struct {
	SchemaVersion     string          `json:"schema_version"`
	GeneratedAt       string          `json:"generated_at"`
	Docker            DockerMetadata  `json:"docker"`
	ScannedContainers int             `json:"scanned_containers"`
	Summary           Summary         `json:"summary"`
	Findings          []audit.Finding `json:"findings"`
}

// Summarize counts every finding by severity.
func Summarize(findings []audit.Finding) Summary {
	var summary Summary
	for _, finding := range findings {
		switch audit.Severity(finding.Severity) {
		case audit.Critical:
			summary.Critical++
		case audit.High:
			summary.High++
		case audit.Medium:
			summary.Medium++
		case audit.Low:
			summary.Low++
		case audit.Info:
			summary.Info++
		}
		summary.Total++
	}
	return summary
}

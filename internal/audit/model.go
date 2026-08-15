package audit

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Severity is ordered from least to most severe.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	if s < Info || s > Critical {
		return "unknown"
	}
	return [...]string{"info", "low", "medium", "high", "critical"}[s]
}

// ParseSeverity accepts case-insensitive public severity names.
func ParseSeverity(value string) (Severity, bool) {
	for i, name := range []string{"info", "low", "medium", "high", "critical"} {
		if strings.EqualFold(value, name) {
			return Severity(i), true
		}
	}
	return 0, false
}

// SeverityJSON emits a stable string representation in JSON.
type SeverityJSON Severity

func (s SeverityJSON) String() string { return Severity(s).String() }

func (s SeverityJSON) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// Finding is the stable rule result shared by human and JSON output.
type Finding struct {
	RuleID      string       `json:"rule_id"`
	Severity    SeverityJSON `json:"severity"`
	Container   string       `json:"container"`
	Image       string       `json:"image"`
	Summary     string       `json:"summary"`
	Risk        string       `json:"risk"`
	Remediation string       `json:"remediation"`
}

// Rule defines stable public metadata for an audit rule.
type Rule struct {
	ID          string
	Severity    Severity
	Summary     string
	Risk        string
	Remediation string
}

// Explain returns metadata for a rule ID.
func Explain(id string) (Rule, error) {
	id = strings.ToUpper(strings.TrimSpace(id))
	for _, item := range Rules {
		if item.ID == id {
			return item, nil
		}
	}
	return Rule{}, fmt.Errorf("unknown rule")
}

// SortFindings applies the schema's deterministic ordering.
func SortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		left, right := findings[i], findings[j]
		if left.Severity != right.Severity {
			return left.Severity > right.Severity
		}
		leftName, rightName := strings.ToLower(left.Container), strings.ToLower(right.Container)
		if leftName != rightName {
			return leftName < rightName
		}
		if left.Container != right.Container {
			return left.Container < right.Container
		}
		return left.RuleID < right.RuleID
	})
}

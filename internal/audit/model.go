package audit

import (
	"encoding/json"
	"regexp"
	"strings"
)

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

func ParseSeverity(v string) (Severity, bool) {
	for i, name := range []string{"info", "low", "medium", "high", "critical"} {
		if strings.EqualFold(v, name) {
			return Severity(i), true
		}
	}
	return 0, false
}

type Finding struct {
	ID          string       `json:"id"`
	Severity    SeverityJSON `json:"severity"`
	Container   string       `json:"container,omitempty"`
	Image       string       `json:"image,omitempty"`
	Summary     string       `json:"summary"`
	Risk        string       `json:"risk"`
	Remediation string       `json:"remediation"`
}

type SeverityJSON Severity

func (s SeverityJSON) String() string { return Severity(s).String() }

func (s SeverityJSON) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

var ansi = regexp.MustCompile(`\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))`)
var controls = regexp.MustCompile(`[\x00-\x1f\x7f-\x9f]`)
var bidiControls = regexp.MustCompile(`[\x{061c}\x{200e}\x{200f}\x{202a}-\x{202e}\x{2066}-\x{2069}]`)

func Sanitize(s string) string {
	s = ansi.ReplaceAllString(s, "")
	s = controls.ReplaceAllString(s, "")
	return bidiControls.ReplaceAllString(s, "")
}

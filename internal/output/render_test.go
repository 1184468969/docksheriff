package output

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/1184468969/docksheriff/internal/audit"
)

func TestTableIncludesWhyFixAndCollapsesBelowMinimum(t *testing.T) {
	report := Report{
		SchemaVersion:     SchemaVersion,
		Docker:            DockerMetadata{Endpoint: "unix:///var/run/docker.sock", ServerVersion: "28.0.0", APIVersion: "1.48"},
		ScannedContainers: 1,
		Findings: []audit.Finding{
			{RuleID: "DS001", Severity: audit.SeverityJSON(audit.Critical), Container: "web", Image: "demo:1", Summary: "critical summary", Risk: "critical risk", Remediation: "critical fix"},
			{RuleID: "DS014", Severity: audit.SeverityJSON(audit.Low), Container: "web", Image: "demo:latest", Summary: "low summary", Risk: "low risk", Remediation: "low fix"},
		},
	}
	report.Summary = Summarize(report.Findings)
	var output bytes.Buffer
	if err := Table(&output, report, audit.Medium); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, text := range []string{"CRITICAL DS001", "Why:      critical risk", "Fix:      critical fix", "low=1", "total=2"} {
		if !strings.Contains(got, text) {
			t.Fatalf("table missing %q:\n%s", text, got)
		}
	}
	if strings.Contains(got, "low summary") {
		t.Fatalf("low finding was expanded:\n%s", got)
	}
}

func TestJSONNeverContainsANSIOrNullFindings(t *testing.T) {
	report := Report{
		SchemaVersion: SchemaVersion,
		Docker: DockerMetadata{
			Endpoint: "unix:///safe\x1b[31m",
		},
		Findings: []audit.Finding{{
			RuleID:    "DS001\x1b[31m",
			Container: "bad\x1b]8;;https://evil.invalid\x07name",
			Image:     "demo\nimage",
		}},
	}
	var output bytes.Buffer
	if err := JSON(&output, report); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "\x1b") || strings.Contains(output.String(), "evil.invalid") || strings.Contains(output.String(), `demo\nimage`) {
		t.Fatalf("unsafe or unstable JSON: %s", output.String())
	}
}

func TestRenderWriterErrors(t *testing.T) {
	report := Report{SchemaVersion: SchemaVersion}
	for name, render := range map[string]func() error{
		"json":    func() error { return JSON(failingWriter{}, report) },
		"table":   func() error { return Table(failingWriter{}, report, audit.Medium) },
		"rules":   func() error { return Rules(failingWriter{}) },
		"explain": func() error { return Explain(failingWriter{}, audit.Rules[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := render(); !errors.Is(err, errWrite) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

var errWrite = errors.New("write failed")

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errWrite }

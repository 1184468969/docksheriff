package cli

import (
	"reflect"
	"testing"
)

func TestCommandForms(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		command Command
		format  string
		target  string
	}{
		{"bare", nil, Scan, "table", ""},
		{"scan", []string{"scan"}, Scan, "table", ""},
		{"global only", []string{"--format", "json"}, Scan, "json", ""},
		{"scan after flag", []string{"--format", "json", "scan"}, Scan, "json", ""},
		{"scan before flag", []string{"scan", "--format", "json"}, Scan, "json", ""},
		{"inspect", []string{"inspect", "portainer"}, Inspect, "table", "portainer"},
		{"inspect trailing flag", []string{"inspect", "portainer", "--format", "json"}, Inspect, "json", "portainer"},
		{"inspect leading flag", []string{"--format", "json", "inspect", "portainer"}, Inspect, "json", "portainer"},
		{"inspect interleaved", []string{"inspect", "--format", "json", "portainer"}, Inspect, "json", "portainer"},
		{"rules", []string{"rules"}, Rules, "", ""},
		{"explain", []string{"explain", "ds002"}, Explain, "", ""},
		{"help", []string{"--help"}, Help, "", ""},
		{"scan help", []string{"scan", "--help"}, Help, "", ""},
		{"inspect help", []string{"inspect", "--help"}, Help, "", ""},
		{"version", []string{"--version"}, Version, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options, err := Parse(tt.args)
			if err != nil {
				t.Fatal(err)
			}
			if options.Command != tt.command || options.Format != tt.format || options.InspectTarget != tt.target {
				t.Fatalf("options=%#v", options)
			}
		})
	}
}

func TestFlagValueIsNeverACommand(t *testing.T) {
	options, err := Parse([]string{"--host", "inspect"})
	if err != nil {
		t.Fatal(err)
	}
	if options.Command != Scan || options.Host != "inspect" {
		t.Fatalf("options=%#v", options)
	}
	options, err = Parse([]string{"--host=inspect", "scan"})
	if err != nil || options.Command != Scan || options.Host != "inspect" {
		t.Fatalf("options=%#v err=%v", options, err)
	}
}

func TestPolicyFlagsAndErrors(t *testing.T) {
	options, err := Parse([]string{"scan", "--all", "--ignore", "ds012", "--ignore=DS014", "--fail-on", "high", "--min-severity", "low"})
	if err != nil {
		t.Fatal(err)
	}
	if !options.All || !options.FailOnSet || options.FailOn.String() != "high" || options.Minimum.String() != "low" {
		t.Fatalf("options=%#v", options)
	}
	if got, want := options.IgnoredRules, map[string]struct{}{"DS012": {}, "DS014": {}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ignored=%v want=%v", got, want)
	}
	for _, args := range [][]string{
		{"unknown"},
		{"--unknown"},
		{"--format", "xml"},
		{"--min-severity", "urgent"},
		{"--fail-on", "urgent"},
		{"--ignore", "NOPE"},
		{"inspect"},
		{"inspect", "one", "two"},
		{"explain"},
		{"explain", "NOPE"},
		{"rules", "extra"},
		{"scan", "extra"},
		{"--host"},
	} {
		if _, err := Parse(args); err == nil {
			t.Errorf("Parse(%q) succeeded", args)
		}
	}
}

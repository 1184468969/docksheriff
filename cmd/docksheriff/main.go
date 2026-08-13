package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/1184468969/docksheriff/internal/audit"
	"github.com/1184468969/docksheriff/internal/dockerapi"
	"github.com/1184468969/docksheriff/internal/engine"
)

type stringsFlag []string

func (s *stringsFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringsFlag) Set(v string) error { *s = append(*s, strings.ToUpper(v)); return nil }

func main() { os.Exit(run(os.Args[1:])) }
func run(args []string) int {
	command := "scan"
	for i, arg := range args {
		if arg == "scan" || arg == "inspect" || arg == "rules" || arg == "explain" {
			command = arg
			args = append(args[:i:i], args[i+1:]...)
			break
		}
	}
	if command == "rules" {
		for _, r := range audit.Rules {
			fmt.Printf("%s %-8s %s\n", r.ID, r.Severity.String(), r.Summary)
		}
		return 0
	}
	if command == "explain" {
		if len(args) != 1 {
			fmt.Fprintln(os.Stderr, "usage: docksheriff explain RULE")
			return 2
		}
		r, e := audit.Explain(args[0])
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 2
		}
		fmt.Printf("%s [%s] %s\nRisk: %s\nFix: %s\n", r.ID, r.Severity.String(), r.Summary, r.Risk, r.Remediation)
		return 0
	}
	if command != "scan" && command != "inspect" {
		fmt.Fprintln(os.Stderr, "unknown command:", command)
		return 2
	}
	fs := flag.NewFlagSet("docksheriff", flag.ContinueOnError)
	format := fs.String("format", "table", "table or json")
	minText := fs.String("min-severity", "medium", "minimum expanded severity")
	failText := fs.String("fail-on", "", "failure threshold")
	all := fs.Bool("all", false, "include stopped containers")
	host := fs.String("host", "", "Docker endpoint")
	var ignores stringsFlag
	fs.Var(&ignores, "ignore", "rule ID to ignore")
	if fs.Parse(args) != nil {
		return 2
	}
	min, ok := audit.ParseSeverity(*minText)
	if !ok {
		fmt.Fprintln(os.Stderr, "invalid minimum severity")
		return 2
	}
	fail := audit.Critical + 1
	if *failText != "" {
		var ok bool
		fail, ok = audit.ParseSeverity(*failText)
		if !ok {
			fmt.Fprintln(os.Stderr, "invalid fail-on severity")
			return 2
		}
	}
	c, e := engine.New(*host)
	if e != nil {
		fmt.Fprintln(os.Stderr, "Docker client error:", e)
		return 2
	}
	defer c.Close()
	ctx := context.Background()
	if e = c.Ping(ctx); e != nil {
		fmt.Fprintln(os.Stderr, "Docker connection error:", e)
		return 2
	}
	var targets []string
	if command == "inspect" {
		if fs.NArg() != 1 {
			fmt.Fprintln(os.Stderr, "inspect requires one container")
			return 2
		}
		targets = []string{fs.Arg(0)}
	} else {
		cs, e := c.List(ctx, *all)
		if e != nil {
			fmt.Fprintln(os.Stderr, "Docker list error:", e)
			return 2
		}
		for _, x := range cs {
			targets = append(targets, x.ID)
		}
	}
	ignored := map[string]bool{}
	for _, x := range ignores {
		if _, err := audit.Explain(x); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		ignored[x] = true
	}
	var findings []audit.Finding
	for _, id := range targets {
		x, e := c.Inspect(ctx, id)
		if e != nil {
			fmt.Fprintln(os.Stderr, "Docker inspect error:", e)
			return 2
		}
		if x.Config == nil || x.HostConfig == nil {
			fmt.Fprintln(os.Stderr, "Docker inspect returned an incomplete response")
			return 2
		}
		name := strings.TrimPrefix(x.Name, "/")
		image := x.Config.Image
		hostConfig := *x.HostConfig
		hostConfig.Mounts = append(append([]dockerapi.Mount(nil), hostConfig.Mounts...), x.Mounts...)
		for _, f := range audit.Evaluate(name, image, x.Config, &hostConfig) {
			if !ignored[f.ID] {
				findings = append(findings, f)
			}
		}
	}
	if c.InsecureTCP() && !ignored["DS015"] {
		f, _ := audit.Explain("DS015")
		findings = append(findings, audit.Finding{ID: f.ID, Severity: audit.SeverityJSON(f.Severity), Summary: f.Summary, Risk: f.Risk, Remediation: f.Remediation})
	}
	sort.Slice(findings, func(i, j int) bool {
		return audit.Severity(findings[i].Severity) > audit.Severity(findings[j].Severity)
	})
	if *format == "json" {
		if findings == nil {
			findings = []audit.Finding{}
		}
		if err := json.NewEncoder(os.Stdout).Encode(struct {
			Findings []audit.Finding `json:"findings"`
			Count    int             `json:"count"`
		}{findings, len(findings)}); err != nil {
			fmt.Fprintln(os.Stderr, "write JSON:", err)
			return 2
		}
	} else if *format == "table" {
		counts := map[audit.Severity]int{}
		for _, f := range findings {
			sev := audit.Severity(f.Severity)
			counts[sev]++
			if sev >= min {
				fmt.Printf("%s %-8s %-20s %s\n", f.ID, sev.String(), f.Container, f.Summary)
			}
		}
		fmt.Printf("Summary: critical=%d high=%d medium=%d low=%d info=%d\n", counts[audit.Critical], counts[audit.High], counts[audit.Medium], counts[audit.Low], counts[audit.Info])
	} else {
		fmt.Fprintln(os.Stderr, "format must be table or json")
		return 2
	}
	for _, f := range findings {
		if audit.Severity(f.Severity) >= fail {
			return 1
		}
	}
	return 0
}

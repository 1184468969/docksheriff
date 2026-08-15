// Package cli parses DockSheriff's stable command-line interface.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/1184468969/docksheriff/internal/audit"
)

const rootUsage = `DockSheriff audits running Docker container configuration.

Usage:
  docksheriff [global flags] [scan] [scan flags]
  docksheriff [global flags] inspect CONTAINER [inspect flags]
  docksheriff rules
  docksheriff explain RULE
  docksheriff --version

Global/scan/inspect flags:
  --format table|json       output format (default table)
  --min-severity SEVERITY   minimum expanded table severity (default medium)
  --fail-on SEVERITY        exit 1 when a finding meets the threshold
  --ignore RULE             ignore a rule; repeatable
  --all                     include stopped containers in scans
  --host ENDPOINT           override DOCKER_HOST
`

type Command string

const (
	Scan    Command = "scan"
	Inspect Command = "inspect"
	Rules   Command = "rules"
	Explain Command = "explain"
	Version Command = "version"
	Help    Command = "help"
)

type Options struct {
	Command       Command
	Format        string
	Minimum       audit.Severity
	FailOn        audit.Severity
	FailOnSet     bool
	All           bool
	Host          string
	IgnoredRules  map[string]struct{}
	InspectTarget string
	ExplainRule   string
	HelpFor       Command
}

// Parse accepts shared flags before or after scan/inspect while treating flag
// values as values, never as command tokens.
func Parse(args []string) (Options, error) {
	if len(args) == 0 {
		args = []string{"scan"}
	}
	if special, helpFor, found := specialCommand(args); found {
		return Options{Command: special, HelpFor: helpFor}, nil
	}
	command, commandIndex, err := locateCommand(args)
	if err != nil {
		return Options{}, err
	}
	if command == Help || command == Version {
		return Options{Command: command}, nil
	}
	if command == Rules || command == Explain {
		return parseMetadataCommand(command, removeIndex(args, commandIndex))
	}

	remaining := args
	if commandIndex >= 0 {
		remaining = removeIndex(args, commandIndex)
	}
	return parseScanCommand(command, remaining)
}

func specialCommand(args []string) (Command, Command, bool) {
	var command Command
	expectsValue := false
	for _, arg := range args {
		if expectsValue {
			expectsValue = false
			continue
		}
		if arg == "--" {
			break
		}
		if strings.HasPrefix(arg, "-") {
			name, hasValue := splitFlag(arg)
			if name == "--version" {
				return Version, command, true
			}
			if name == "--help" || name == "-h" {
				return Help, command, true
			}
			switch name {
			case "--format", "--min-severity", "--fail-on", "--ignore", "--host":
				expectsValue = !hasValue
			}
			continue
		}
		if command == "" {
			switch arg {
			case "scan":
				command = Scan
			case "inspect":
				command = Inspect
			case "rules":
				command = Rules
			case "explain":
				command = Explain
			}
		}
	}
	return "", "", false
}

func locateCommand(args []string) (Command, int, error) {
	expectsValue := false
	for index, arg := range args {
		if expectsValue {
			expectsValue = false
			continue
		}
		if arg == "--" {
			break
		}
		if arg == "-h" || arg == "--help" {
			return Help, index, nil
		}
		if arg == "--version" {
			return Version, index, nil
		}
		if strings.HasPrefix(arg, "-") {
			name, hasValue := splitFlag(arg)
			switch name {
			case "--format", "--min-severity", "--fail-on", "--ignore", "--host":
				expectsValue = !hasValue
			case "--all":
			default:
				return "", -1, fmt.Errorf("unknown flag")
			}
			continue
		}
		switch arg {
		case "scan":
			return Scan, index, nil
		case "inspect":
			return Inspect, index, nil
		case "rules":
			return Rules, index, nil
		case "explain":
			return Explain, index, nil
		default:
			return "", -1, fmt.Errorf("unknown command")
		}
	}
	if expectsValue {
		return "", -1, fmt.Errorf("flag requires a value")
	}
	return Scan, -1, nil
}

func parseMetadataCommand(command Command, args []string) (Options, error) {
	if command == Rules {
		if len(args) != 0 {
			return Options{}, errors.New("rules accepts no arguments")
		}
		return Options{Command: Rules}, nil
	}
	if len(args) != 1 {
		return Options{}, errors.New("explain requires one rule ID")
	}
	rule, err := audit.Explain(args[0])
	if err != nil {
		return Options{}, err
	}
	return Options{Command: Explain, ExplainRule: rule.ID}, nil
}

func parseScanCommand(command Command, args []string) (Options, error) {
	options := Options{
		Command:      command,
		Format:       "table",
		Minimum:      audit.Medium,
		IgnoredRules: map[string]struct{}{},
	}
	set := flag.NewFlagSet(string(command), flag.ContinueOnError)
	set.SetOutput(io.Discard)
	format := set.String("format", "table", "")
	minimum := set.String("min-severity", "medium", "")
	failOn := set.String("fail-on", "", "")
	all := set.Bool("all", false, "")
	host := set.String("host", "", "")
	ignored := &ruleFlags{}
	set.Var(ignored, "ignore", "")
	ordered, positionals, err := reorderFlags(args)
	if err != nil {
		return Options{}, err
	}
	if err = set.Parse(ordered); err != nil {
		return Options{}, errors.New("invalid command-line arguments")
	}
	options.Format = strings.ToLower(*format)
	if options.Format != "table" && options.Format != "json" {
		return Options{}, errors.New("format must be table or json")
	}
	options.Minimum, _ = audit.ParseSeverity(*minimum)
	if _, valid := audit.ParseSeverity(*minimum); !valid {
		return Options{}, errors.New("invalid minimum severity")
	}
	if *failOn != "" {
		var valid bool
		options.FailOn, valid = audit.ParseSeverity(*failOn)
		if !valid {
			return Options{}, errors.New("invalid fail-on severity")
		}
		options.FailOnSet = true
	}
	options.All = *all
	options.Host = *host
	for _, id := range *ignored {
		rule, explainErr := audit.Explain(id)
		if explainErr != nil {
			return Options{}, explainErr
		}
		options.IgnoredRules[rule.ID] = struct{}{}
	}
	if command == Inspect {
		if len(positionals) != 1 {
			return Options{}, errors.New("inspect requires one container")
		}
		options.InspectTarget = positionals[0]
	} else if len(positionals) != 0 {
		return Options{}, errors.New("scan accepts no positional arguments")
	}
	return options, nil
}

func reorderFlags(args []string) ([]string, []string, error) {
	flags := make([]string, 0, len(args))
	positionals := make([]string, 0, 1)
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--" {
			positionals = append(positionals, args[index+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positionals = append(positionals, arg)
			continue
		}
		name, hasValue := splitFlag(arg)
		switch name {
		case "--format", "--min-severity", "--fail-on", "--ignore", "--host":
			flags = append(flags, arg)
			if !hasValue {
				index++
				if index >= len(args) {
					return nil, nil, errors.New("flag requires a value")
				}
				flags = append(flags, args[index])
			}
		case "--all":
			flags = append(flags, arg)
		default:
			return nil, nil, errors.New("unknown flag")
		}
	}
	return flags, positionals, nil
}

func splitFlag(arg string) (name string, hasValue bool) {
	name, _, hasValue = strings.Cut(arg, "=")
	return name, hasValue
}

func removeIndex(args []string, index int) []string {
	if index < 0 {
		return append([]string(nil), args...)
	}
	result := make([]string, 0, len(args)-1)
	result = append(result, args[:index]...)
	result = append(result, args[index+1:]...)
	return result
}

type ruleFlags []string

func (r *ruleFlags) String() string { return strings.Join(*r, ",") }
func (r *ruleFlags) Set(value string) error {
	*r = append(*r, value)
	return nil
}

// Usage returns stable help without embedding untrusted arguments.
func Usage(command Command) string {
	if command == Inspect {
		return rootUsage + "\nInspect requires exactly one container name or ID.\n"
	}
	if command == Scan {
		return rootUsage + "\nScan is the default command.\n"
	}
	return rootUsage
}

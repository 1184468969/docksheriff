package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/1184468969/docksheriff/internal/app"
	"github.com/1184468969/docksheriff/internal/audit"
	"github.com/1184468969/docksheriff/internal/cli"
	"github.com/1184468969/docksheriff/internal/docker"
	"github.com/1184468969/docksheriff/internal/output"
	"github.com/1184468969/docksheriff/internal/safe"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type connection interface {
	docker.Engine
	Metadata() docker.Metadata
	Close() error
}

type connectionFactory func(string) (connection, error)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	return execute(args, os.Stdout, os.Stderr, func(host string) (connection, error) {
		return docker.New(host)
	}, time.Now)
}

func execute(
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	connect connectionFactory,
	now func() time.Time,
) int {
	options, err := cli.Parse(args)
	if err != nil {
		writeError(stderr, err)
		return 2
	}
	switch options.Command {
	case cli.Help:
		if _, err = io.WriteString(stdout, cli.Usage(options.HelpFor)); err != nil {
			writeOutputError(stderr)
			return 2
		}
		return 0
	case cli.Version:
		if _, err = fmt.Fprintf(stdout, "docksheriff %s (commit %s, built %s)\n",
			safe.Text(version), safe.Text(commit), safe.Text(date)); err != nil {
			writeOutputError(stderr)
			return 2
		}
		return 0
	case cli.Rules:
		if err = output.Rules(stdout); err != nil {
			writeOutputError(stderr)
			return 2
		}
		return 0
	case cli.Explain:
		rule, explainErr := audit.Explain(options.ExplainRule)
		if explainErr != nil {
			writeError(stderr, explainErr)
			return 2
		}
		if err = output.Explain(stdout, rule); err != nil {
			writeOutputError(stderr)
			return 2
		}
		return 0
	}

	engine, err := connect(options.Host)
	if err != nil {
		writeError(stderr, err)
		return 2
	}
	defer func() { _ = engine.Close() }()
	report, err := app.Scan(context.Background(), engine, engine.Metadata(), app.Options{
		InspectTarget: options.InspectTarget,
		All:           options.All,
		IgnoredRules:  options.IgnoredRules,
	}, now)
	if err != nil {
		writeError(stderr, err)
		return 2
	}
	if options.Format == "json" {
		err = output.JSON(stdout, report)
	} else {
		err = output.Table(stdout, report, options.Minimum)
	}
	if err != nil {
		writeOutputError(stderr)
		return 2
	}
	if app.ThresholdReached(report, options.FailOn, options.FailOnSet) {
		return 1
	}
	return 0
}

func writeError(writer io.Writer, err error) {
	_, _ = fmt.Fprintf(writer, "Error: %s\n", safe.Text(err.Error()))
}

func writeOutputError(writer io.Writer) {
	_, _ = io.WriteString(writer, "Error: output write failed\n")
}

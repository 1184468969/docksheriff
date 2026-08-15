// Package app orchestrates read-only Engine access and rule evaluation.
package app

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/1184468969/docksheriff/internal/audit"
	"github.com/1184468969/docksheriff/internal/docker"
	"github.com/1184468969/docksheriff/internal/output"
	"github.com/1184468969/docksheriff/internal/safe"
)

type Options struct {
	InspectTarget string
	All           bool
	IgnoredRules  map[string]struct{}
}

// Scan performs the complete read-only application workflow.
func Scan(
	ctx context.Context,
	engine docker.Engine,
	metadata docker.Metadata,
	options Options,
	now func() time.Time,
) (output.Report, error) {
	if _, err := engine.Ping(ctx); err != nil {
		return output.Report{}, operationError("Docker ping failed", err)
	}
	version, err := engine.ServerVersion(ctx)
	if err != nil {
		return output.Report{}, operationError("Docker server version failed", err)
	}

	targets := []string{options.InspectTarget}
	if options.InspectTarget == "" {
		items, listErr := engine.ContainerList(ctx, docker.ListOptions{All: options.All})
		if listErr != nil {
			return output.Report{}, operationError("Docker container list failed", listErr)
		}
		targets = make([]string, 0, len(items))
		for _, item := range items {
			targets = append(targets, item.ID)
		}
	}

	findings := make([]audit.Finding, 0)
	for _, target := range targets {
		inspect, inspectErr := engine.ContainerInspect(ctx, target)
		if inspectErr != nil {
			return output.Report{}, operationError("Docker container inspect failed", inspectErr)
		}
		if inspect.Config == nil || inspect.HostConfig == nil {
			return output.Report{}, errors.New("docker container inspect returned incomplete data")
		}
		if !strings.EqualFold(inspect.Platform, "linux") {
			return output.Report{}, errors.New("docker container platform is unsupported")
		}
		for _, finding := range audit.Evaluate(inspect) {
			if _, ignored := options.IgnoredRules[finding.RuleID]; !ignored {
				findings = append(findings, finding)
			}
		}
	}
	for _, finding := range audit.EvaluateEndpoint(metadata.InsecureTCP) {
		if _, ignored := options.IgnoredRules[finding.RuleID]; !ignored {
			findings = append(findings, finding)
		}
	}
	audit.SortFindings(findings)
	if findings == nil {
		findings = []audit.Finding{}
	}
	generatedAt := now().UTC().Truncate(time.Second).Format(time.RFC3339)
	return output.Report{
		SchemaVersion: output.SchemaVersion,
		GeneratedAt:   generatedAt,
		Docker: output.DockerMetadata{
			Endpoint:      fallback(docker.RedactEndpoint(metadata.Endpoint), "unknown"),
			ServerVersion: fallback(safe.Text(version.Version), "unknown"),
			APIVersion:    fallback(safe.Text(version.APIVersion), "unknown"),
		},
		ScannedContainers: len(targets),
		Summary:           output.Summarize(findings),
		Findings:          findings,
	}, nil
}

// ThresholdReached reports whether any non-ignored finding meets the policy.
func ThresholdReached(report output.Report, threshold audit.Severity, enabled bool) bool {
	if !enabled {
		return false
	}
	for _, finding := range report.Findings {
		if audit.Severity(finding.Severity) >= threshold {
			return true
		}
	}
	return false
}

type appError struct {
	message string
	cause   error
}

func (e *appError) Error() string { return e.message }
func (e *appError) Unwrap() error { return e.cause }

func operationError(message string, cause error) error {
	return &appError{message: message, cause: cause}
}

func fallback(value, replacement string) string {
	if strings.TrimSpace(value) == "" {
		return replacement
	}
	return value
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/kyverno/kyverno-json/pkg/apis/policy/v1alpha1"
	jsonengine "github.com/kyverno/kyverno-json/pkg/json-engine"
	"github.com/kyverno/kyverno-json/pkg/policy"

	"kyverno-show/part3-json-gitops/internal/jsondiff"
)

type ruleReport struct {
	Policy     string   `json:"policy"`
	Rule       string   `json:"rule"`
	Identifier string   `json:"identifier,omitempty"`
	Status     string   `json:"status"` // "pass" | "fail"
	Messages   []string `json:"messages,omitempty"`
}

type evalReport struct {
	Operation jsondiff.Operation     `json:"operation"`
	Kind      string                 `json:"kind"`
	Env       string                 `json:"environment"`
	Changes   []jsondiff.FieldChange `json:"changes"`
	Failures  int                    `json:"failures"`
	Rules     []ruleReport           `json:"rules"`
}

func main() {
	beforePath := flag.String("before", "", "Path to previous JSON state (omit for create)")
	afterPath := flag.String("after", "", "Path to new JSON state (omit for delete)")
	eventPath := flag.String("event", "", "Path to a pre-built ChangeEvent JSON file (skips diffing)")
	gitBase := flag.String("git-base", "", "Base git ref (e.g. origin/main or HEAD) to compare against working-tree -file")
	gitFile := flag.String("file", "", "Repo-relative JSON file path used with -git-base")
	resourcePath := flag.String("path", "", "Logical repository path (used to infer environment if omitted in metadata)")
	policyPath := flag.String("policy", "./policies", "Path to ValidatingPolicy YAML file or directory")
	ticket := flag.String("ticket", "", "Optional change ticket ID")
	outputFormat := flag.String("output", "text", "Output format: 'text' or 'json'")
	dumpEvent := flag.Bool("dump-event", false, "Print full ChangeEvent JSON payload")
	emitJSON := flag.String("emit-json", "", "Write the ChangeEvent JSON payload to a file")
	flag.Parse()

	ev, payload, err := resolveChangeEvent(*eventPath, *gitBase, *gitFile, *beforePath, *afterPath, *resourcePath, *ticket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error preparing change event: %v\n", err)
		os.Exit(2)
	}

	if *dumpEvent || *emitJSON != "" {
		pretty, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error formatting ChangeEvent JSON: %v\n", err)
			os.Exit(2)
		}
		if *emitJSON != "" {
			if err := os.WriteFile(*emitJSON, append(pretty, '\n'), 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "error writing -emit-json: %v\n", err)
				os.Exit(2)
			}
		}
		if *dumpEvent {
			fmt.Printf("=== ChangeEvent Payload ===\n%s\n\n", string(pretty))
		}
	}

	policies, err := policy.Load(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading policies: %v\n", err)
		os.Exit(2)
	}

	report, err := evaluateEvent(context.Background(), policies, ev, payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "evaluation error: %v\n", err)
		os.Exit(2)
	}

	switch *outputFormat {
	case "json":
		out, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error formatting output: %v\n", err)
			os.Exit(2)
		}
		fmt.Println(string(out))
	case "text":
		printTextReport(report)
	default:
		fmt.Fprintf(os.Stderr, "unknown -output %q (must be 'text' or 'json')\n", *outputFormat)
		os.Exit(2)
	}

	if report.Failures > 0 {
		os.Exit(1)
	}
}

func resolveChangeEvent(
	eventPath, gitBase, gitFile, beforePath, afterPath, resourcePath, ticket string,
) (jsondiff.ChangeEvent, map[string]any, error) {
	if eventPath != "" {
		raw, err := os.ReadFile(eventPath)
		if err != nil {
			return jsondiff.ChangeEvent{}, nil, fmt.Errorf("read -event: %w", err)
		}
		var ev jsondiff.ChangeEvent
		if err := json.Unmarshal(raw, &ev); err != nil {
			return jsondiff.ChangeEvent{}, nil, fmt.Errorf("parse -event JSON: %w", err)
		}
		var payload map[string]any
		if err := json.Unmarshal(raw, &payload); err != nil {
			return jsondiff.ChangeEvent{}, nil, fmt.Errorf("parse -event payload: %w", err)
		}
		return ev, payload, nil
	}

	var beforeRaw, afterRaw []byte
	var err error
	logicalPath := resourcePath

	if gitBase != "" || gitFile != "" {
		if gitBase == "" || gitFile == "" {
			return jsondiff.ChangeEvent{}, nil, errors.New("both -git-base and -file must be provided together")
		}
		beforeRaw, afterRaw, err = loadFromGitAndDisk(".", gitBase, gitFile)
		if err != nil {
			return jsondiff.ChangeEvent{}, nil, err
		}
		if logicalPath == "" {
			logicalPath = gitFile
		}
	} else {
		if beforePath != "" {
			beforeRaw, err = os.ReadFile(beforePath)
			if err != nil {
				return jsondiff.ChangeEvent{}, nil, fmt.Errorf("read -before: %w", err)
			}
		}
		if afterPath != "" {
			afterRaw, err = os.ReadFile(afterPath)
			if err != nil {
				return jsondiff.ChangeEvent{}, nil, fmt.Errorf("read -after: %w", err)
			}
		}
		if logicalPath == "" {
			logicalPath = afterPath
			if logicalPath == "" {
				logicalPath = beforePath
			}
		}
	}

	ev, err := jsondiff.BuildChangeEvent(beforeRaw, afterRaw, logicalPath, ticket)
	if err != nil {
		return jsondiff.ChangeEvent{}, nil, err
	}
	payload, err := ev.ToMap()
	if err != nil {
		return jsondiff.ChangeEvent{}, nil, err
	}
	return ev, payload, nil
}

// loadFromGitAndDisk loads the base revision of filePath via `git show` and the working-tree version from disk.
func loadFromGitAndDisk(repoDir, gitBase, filePath string) ([]byte, []byte, error) {
	verifyCmd := exec.Command("git", "-C", repoDir, "rev-parse", "--verify", gitBase)
	if out, err := verifyCmd.CombinedOutput(); err != nil {
		return nil, nil, fmt.Errorf("invalid -git-base %q: %s (%w)", gitBase, strings.TrimSpace(string(out)), err)
	}

	gitPath := filepath.ToSlash(filepath.Clean(filePath))
	objSpec := fmt.Sprintf("%s:%s", gitBase, gitPath)

	var beforeRaw []byte
	existsCmd := exec.Command("git", "-C", repoDir, "cat-file", "-e", objSpec)
	if err := existsCmd.Run(); err == nil {
		showCmd := exec.Command("git", "-C", repoDir, "show", objSpec)
		var stdout, stderr bytes.Buffer
		showCmd.Stdout = &stdout
		showCmd.Stderr = &stderr
		if err := showCmd.Run(); err != nil {
			return nil, nil, fmt.Errorf("git show %s failed: %s (%w)", objSpec, strings.TrimSpace(stderr.String()), err)
		}
		beforeRaw = stdout.Bytes()
	}

	diskPath := filePath
	if !filepath.IsAbs(diskPath) {
		diskPath = filepath.Join(repoDir, filePath)
	}
	var afterRaw []byte
	data, err := os.ReadFile(diskPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("read working file %s: %w", diskPath, err)
		}
	} else {
		afterRaw = data
	}

	return beforeRaw, afterRaw, nil
}

func evaluateEvent(
	ctx context.Context,
	policies []*v1alpha1.ValidatingPolicy,
	ev jsondiff.ChangeEvent,
	payload map[string]any,
) (evalReport, error) {
	eng := jsonengine.New()
	resp := eng.Run(ctx, jsonengine.Request{
		Resource: payload,
		Policies: policies,
	})

	report := evalReport{
		Operation: ev.Operation,
		Kind:      ev.Kind,
		Env:       ev.Environment,
		Changes:   ev.Diff.Changes,
		Rules:     []ruleReport{},
	}

	for _, polResp := range resp.Policies {
		for _, ruleResp := range polResp.Rules {
			if ruleResp.Error != nil {
				return report, fmt.Errorf("policy %s rule %s error: %w",
					polResp.Policy.Name, ruleResp.Rule.Name, ruleResp.Error)
			}
			rr := ruleReport{
				Policy:     polResp.Policy.Name,
				Rule:       ruleResp.Rule.Name,
				Identifier: ruleResp.Identifier,
				Status:     "pass",
			}
			if len(ruleResp.Violations) > 0 {
				rr.Status = "fail"
				report.Failures++
				for _, v := range ruleResp.Violations {
					rr.Messages = append(rr.Messages, v.Error())
				}
			}
			report.Rules = append(report.Rules, rr)
		}
	}
	return report, nil
}

func printTextReport(report evalReport) {
	fmt.Printf("Operation=%s | Kind=%s | Env=%s | Changes=%d\n",
		report.Operation, report.Kind, report.Env, len(report.Changes))
	if report.Operation == jsondiff.OpUpdate {
		for _, ch := range report.Changes {
			fmt.Printf("  [%s] %s: %v -> %v\n", ch.Op, ch.Path, ch.Before, ch.After)
		}
	}
	for _, r := range report.Rules {
		if r.Status == "fail" {
			fmt.Printf("[FAIL] policy=%s rule=%s id=%s\n", r.Policy, r.Rule, r.Identifier)
			for _, msg := range r.Messages {
				fmt.Printf("       %s\n", strings.ReplaceAll(msg, "\n", "\n       "))
			}
		} else {
			fmt.Printf("[PASS] policy=%s rule=%s id=%s\n", r.Policy, r.Rule, r.Identifier)
		}
	}
	fmt.Printf("\nSummary: Failures=%d\n", report.Failures)
}

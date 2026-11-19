package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kyverno/kyverno-json/pkg/apis/policy/v1alpha1"
	jsonengine "github.com/kyverno/kyverno-json/pkg/json-engine"
	"github.com/kyverno/kyverno-json/pkg/policy"

	"kyverno-show/part2-gitops/internal/diffparse"
	"kyverno-show/part2-gitops/internal/firstprinciples"
)

func main() {
	diffPath := flag.String("diff", "./samples/bad-prod-change.diff", "Path to unified git diff file (or '-' for stdin)")
	policyPath := flag.String("policy", "./policies", "Path to ValidatingPolicy YAML file or directory")
	engineMode := flag.String("engine", "kyverno-json", "Policy engine to run: 'kyverno-json' (official library) or 'mini' (from-first-principles)")
	author := flag.String("author", "dev-alice", "Pipeline/PR author")
	branch := flag.String("branch", "feature/payments-update", "Source git branch")
	ticket := flag.String("ticket", "", "Change ticket ID (e.g. CHG-4821); auto-extracted from -message if omitted")
	commitMsg := flag.String("message", "", "Commit or PR title/message")
	dumpPayload := flag.Bool("dump-payload", false, "Print the structured JSON payload parsed from the diff")
	emitJSON := flag.String("emit-json", "", "Write the parsed DiffReport JSON payload to a file")
	trace := flag.Bool("trace", false, "Print step-by-step evaluation trace (mini engine)")
	flag.Parse()

	rawDiff, err := readInput(*diffPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading diff: %v\n", err)
		os.Exit(2)
	}

	report := diffparse.Parse(rawDiff, diffparse.Metadata{
		Author:        *author,
		Branch:        *branch,
		ChangeTicket:  *ticket,
		CommitMessage: *commitMsg,
	})

	payload, err := report.ToMap()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error converting diff report to map: %v\n", err)
		os.Exit(2)
	}

	if *dumpPayload || *emitJSON != "" {
		pretty, _ := json.MarshalIndent(payload, "", "  ")
		if *emitJSON != "" {
			if err := os.WriteFile(*emitJSON, append(pretty, '\n'), 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "error writing -emit-json: %v\n", err)
				os.Exit(2)
			}
		}
		if *dumpPayload {
			fmt.Printf("=== Structured Diff Payload ===\n%s\n\n", string(pretty))
		}
	}

	policies, err := policy.Load(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading policies: %v\n", err)
		os.Exit(2)
	}

	var failures int
	switch *engineMode {
	case "kyverno-json":
		failures, err = runKyvernoJSON(context.Background(), policies, payload)
	case "mini":
		failures, err = runMiniEngine(policies, payload, *trace)
	default:
		fmt.Fprintf(os.Stderr, "unknown -engine %q (must be 'kyverno-json' or 'mini')\n", *engineMode)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "evaluation error: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("\nEngine=%s | Files=%d | ProdChanges=%v | Failures=%d\n",
		*engineMode, report.Summary.TotalFiles, report.Summary.HasProdChanges, failures)
	if failures > 0 {
		os.Exit(1)
	}
}

func runKyvernoJSON(ctx context.Context, policies []*v1alpha1.ValidatingPolicy, payload map[string]any) (int, error) {
	eng := jsonengine.New()
	resp := eng.Run(ctx, jsonengine.Request{
		Resource: payload,
		Policies: policies,
	})

	failures := 0
	for _, polResp := range resp.Policies {
		for _, ruleResp := range polResp.Rules {
			if ruleResp.Error != nil {
				return failures, fmt.Errorf("policy %s rule %s error: %w",
					polResp.Policy.Name, ruleResp.Rule.Name, ruleResp.Error)
			}
			if len(ruleResp.Violations) > 0 {
				failures++
				fmt.Printf("[FAIL] policy=%s rule=%s id=%s\n",
					polResp.Policy.Name, ruleResp.Rule.Name, ruleResp.Identifier)
				for _, v := range ruleResp.Violations {
					fmt.Printf("       %s\n", strings.ReplaceAll(v.Error(), "\n", "\n       "))
				}
			} else {
				fmt.Printf("[PASS] policy=%s rule=%s id=%s\n",
					polResp.Policy.Name, ruleResp.Rule.Name, ruleResp.Identifier)
			}
		}
	}
	return failures, nil
}

func runMiniEngine(policies []*v1alpha1.ValidatingPolicy, payload map[string]any, showTrace bool) (int, error) {
	eng := firstprinciples.NewEngine()
	outcomes, err := eng.Evaluate(policies, payload)
	if err != nil {
		return 0, err
	}

	failures := 0
	for _, out := range outcomes {
		fmt.Printf("[%s] policy=%s rule=%s\n",
			strings.ToUpper(string(out.Status)), out.PolicyName, out.RuleName)
		for _, v := range out.Violations {
			fmt.Printf("       -> %s\n", v)
		}
		if out.Status == firstprinciples.StatusFail {
			failures++
		}
		if showTrace {
			for _, line := range out.Trace {
				fmt.Printf("       trace: %s\n", line)
			}
		}
	}
	return failures, nil
}

func readInput(path string) (string, error) {
	if path == "-" {
		b, err := io.ReadAll(os.Stdin)
		return string(b), err
	}
	b, err := os.ReadFile(path)
	return string(b), err
}

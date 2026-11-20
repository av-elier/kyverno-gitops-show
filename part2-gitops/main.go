package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	policiesv1beta1 "github.com/kyverno/api/api/policies.kyverno.io/v1beta1"
	celengine "github.com/kyverno/kyverno/pkg/cel/engine"
	vpolcompiler "github.com/kyverno/kyverno/pkg/cel/policies/vpol/compiler"
	vpolengine "github.com/kyverno/kyverno/pkg/cel/policies/vpol/engine"
	"github.com/kyverno/kyverno/pkg/cel/trace"
	engineapi "github.com/kyverno/kyverno/pkg/engine/api"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

	"kyverno-show/part2-gitops/internal/diffparse"
	"kyverno-show/part2-gitops/internal/firstprinciples"
)

func main() {
	diffPath := flag.String("diff", "./samples/bad-prod-change.diff", "Path to unified git diff file (or '-' for stdin)")
	policyPath := flag.String("policy", "./policies", "Path to ValidatingPolicy YAML file or directory")
	engineMode := flag.String("engine", "kyverno", "Policy engine to run: 'kyverno' (official CEL engine) or 'mini' (from-first-principles CEL)")
	author := flag.String("author", "dev-alice", "Pipeline/PR author")
	branch := flag.String("branch", "feature/payments-update", "Source git branch")
	ticket := flag.String("ticket", "", "Change ticket ID (e.g. CHG-4821); auto-extracted from -message if omitted")
	commitMsg := flag.String("message", "", "Commit or PR title/message")
	dumpPayload := flag.Bool("dump-payload", false, "Print the structured JSON payload parsed from the diff")
	emitJSON := flag.String("emit-json", "", "Write the parsed DiffReport JSON payload to a file")
	traceFlag := flag.Bool("trace", false, "Print step-by-step evaluation trace")
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

	policies, err := loadValidatingPolicies(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading policies: %v\n", err)
		os.Exit(2)
	}

	var failures int
	switch *engineMode {
	case "kyverno":
		failures, err = runKyvernoCEL(context.Background(), policies, payload, *traceFlag)
	case "mini":
		failures, err = runMiniEngine(policies, payload, *traceFlag)
	default:
		fmt.Fprintf(os.Stderr, "unknown -engine %q (must be 'kyverno' or 'mini')\n", *engineMode)
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

func runKyvernoCEL(ctx context.Context, policies []*policiesv1beta1.ValidatingPolicy, payload map[string]any, showTrace bool) (int, error) {
	likes := make([]policiesv1beta1.ValidatingPolicyLike, len(policies))
	for i, p := range policies {
		likes[i] = p
	}

	comp := vpolcompiler.NewCompilerWithTrace(showTrace)
	provider, err := vpolengine.NewProvider(comp, likes, nil)
	if err != nil {
		return 0, fmt.Errorf("compile validating policies: %w", err)
	}

	eng := vpolengine.NewEngine(provider, nil, nil)
	resp, err := eng.Handle(ctx, celengine.RequestFromJSON(nil, &unstructured.Unstructured{Object: payload}), nil)
	if err != nil {
		return 0, err
	}

	failures := 0
	for _, polResp := range resp.Policies {
		for _, ruleResp := range polResp.Rules {
			status := ruleResp.Status()
			ruleName := ruleResp.Name()
			if ruleName == "" {
				ruleName = "validation"
			}
			if status == engineapi.RuleStatusError {
				return failures, fmt.Errorf("policy %s rule %s error: %s",
					polResp.Policy.GetName(), ruleName, ruleResp.Message())
			}
			fmt.Printf("[%s] policy=%s rule=%s\n",
				strings.ToUpper(string(status)), polResp.Policy.GetName(), ruleName)
			if status == engineapi.RuleStatusFail {
				failures++
				if msg := ruleResp.Message(); msg != "" {
					fmt.Printf("       -> %s\n", msg)
				}
			}
		}
		if showTrace && polResp.Trace != nil {
			trace.Render(os.Stdout, polResp.Trace)
		}
	}
	return failures, nil
}

func runMiniEngine(policies []*policiesv1beta1.ValidatingPolicy, payload map[string]any, showTrace bool) (int, error) {
	eng, err := firstprinciples.NewEngine()
	if err != nil {
		return 0, err
	}
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

func loadValidatingPolicies(root string) ([]*policiesv1beta1.ValidatingPolicy, error) {
	files, err := collectYAMLFiles(root)
	if err != nil {
		return nil, err
	}
	var policies []*policiesv1beta1.ValidatingPolicy
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		for _, doc := range splitYAMLDocuments(string(raw)) {
			var pol policiesv1beta1.ValidatingPolicy
			if err := yaml.Unmarshal([]byte(doc), &pol); err != nil {
				return nil, fmt.Errorf("parsing policy %s: %w", f, err)
			}
			if pol.Kind != "ValidatingPolicy" {
				continue
			}
			policies = append(policies, &pol)
		}
	}
	return policies, nil
}

func collectYAMLFiles(root string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{root}, nil
	}
	var files []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func splitYAMLDocuments(content string) []string {
	normalized := strings.ReplaceAll(content, "\r\n", "\n")
	parts := strings.Split("\n"+normalized, "\n---")
	var docs []string
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			docs = append(docs, trimmed)
		}
	}
	return docs
}

func readInput(path string) (string, error) {
	if path == "-" {
		b, err := io.ReadAll(os.Stdin)
		return string(b), err
	}
	b, err := os.ReadFile(path)
	return string(b), err
}

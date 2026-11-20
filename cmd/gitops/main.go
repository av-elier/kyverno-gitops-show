package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"kyverno-show/internal/firstprinciples"
	"kyverno-show/internal/jsondiff"
	"kyverno-show/internal/kit"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type fileReport struct {
	Event              jsondiff.ChangeEvent
	Results            []kit.Result
	Enforced, Warnings int
}

type rawPair struct {
	path          string
	before, after []byte
}

type cliConfig struct {
	RepoDir, GitBase, GitFile             string
	BeforePath, AfterPath, Ticket, Engine string
	Mutate, Explain                       bool
	Bundle                                kit.PolicyBundle
}

func main() {
	cfg := cliConfig{RepoDir: "."}
	flag.StringVar(&cfg.BeforePath, "before", "", "Previous JSON/YAML state (omit for create)")
	flag.StringVar(&cfg.AfterPath, "after", "", "New JSON/YAML state (omit for delete)")
	flag.StringVar(&cfg.GitBase, "git-base", "", "Base git ref (e.g. origin/main or HEAD) to compare against working tree")
	flag.StringVar(&cfg.GitFile, "file", "", "Optional repo-relative path with -git-base (omit to scan all changed files)")
	policyPath := flag.String("policy", "./gitops/policies", "Path to policy YAML/JSON file or directory")
	exceptionPath := flag.String("exception", "", "Optional PolicyException YAML/JSON file or directory")
	flag.BoolVar(&cfg.Mutate, "mutate", false, "Apply JSON-mode MutatingPolicies before validating (kyverno engine only)")
	flag.StringVar(&cfg.Engine, "engine", "kyverno", "Validation engine: 'kyverno' or 'mini'")
	flag.StringVar(&cfg.Ticket, "ticket", "", "Optional change ticket ID (e.g. CHG-4821 or INC-9001)")
	flag.BoolVar(&cfg.Explain, "explain", false, "Print step-by-step evaluation traces")
	flag.Parse()

	if cfg.Engine != "kyverno" && cfg.Engine != "mini" {
		must("unknown -engine: %v", fmt.Errorf("%q (must be 'kyverno' or 'mini')", cfg.Engine))
	}
	if cfg.Engine == "mini" && (*exceptionPath != "" || cfg.Mutate) {
		must("%v", errors.New("-exception and -mutate require -engine kyverno"))
	}
	var err error
	if cfg.Bundle, err = kit.LoadPolicies(*policyPath, *exceptionPath); err != nil {
		must("error loading policies: %v", err)
	}
	reports, err := runCLI(context.Background(), cfg)
	must("error: %v", err)
	if len(reports) == 0 {
		fmt.Printf("No changed JSON/YAML files vs %s.\n", cfg.GitBase)
		return
	}

	totalEnforced := 0
	for i, rep := range reports {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("Operation=%s | Kind=%s | Env=%s | Changes=%d\n", rep.Event.Operation, rep.Event.Kind, rep.Event.Environment, len(rep.Event.Diff.Changes))
		if rep.Event.Operation == jsondiff.OpUpdate {
			for _, ch := range rep.Event.Diff.Changes {
				fmt.Printf("  [%s] %s: %v -> %v\n", ch.Op, ch.Path, ch.Before, ch.After)
			}
		}
		kit.PrintResults(os.Stdout, identifier(rep.Event), rep.Results, cfg.Explain)
		fmt.Printf("\nSummary: EnforcedFailures=%d | Warnings=%d\n", rep.Enforced, rep.Warnings)
		totalEnforced += rep.Enforced
	}
	if totalEnforced > 0 {
		os.Exit(1)
	}
}

func runCLI(ctx context.Context, cfg cliConfig) ([]fileReport, error) {
	var miniEng *firstprinciples.Engine
	var miniPols []firstprinciples.CompiledPolicy
	if cfg.Engine == "mini" {
		var err error
		if miniEng, err = firstprinciples.NewEngine(); err != nil {
			return nil, err
		}
		if miniPols, err = miniEng.Compile(cfg.Bundle.Validating); err != nil {
			return nil, err
		}
	}

	pairs, err := loadPairs(cfg)
	if err != nil || len(pairs) == 0 {
		return nil, err
	}
	reps := make([]fileReport, 0, len(pairs))
	for _, p := range pairs {
		rep, err := evalPair(ctx, p.before, p.after, p.path, cfg, miniEng, miniPols)
		if err != nil {
			return nil, err
		}
		reps = append(reps, rep)
	}
	return reps, nil
}

func loadPairs(cfg cliConfig) ([]rawPair, error) {
	if cfg.GitBase == "" {
		b, err := readOptional(cfg.BeforePath)
		if err != nil {
			return nil, fmt.Errorf("read -before: %w", err)
		}
		a, err := readOptional(cfg.AfterPath)
		if err != nil {
			return nil, fmt.Errorf("read -after: %w", err)
		}
		p := cfg.AfterPath
		if p == "" {
			p = cfg.BeforePath
		}
		return []rawPair{{p, b, a}}, nil
	}

	if _, err := gitCmd(cfg.RepoDir, "rev-parse", "--verify", cfg.GitBase); err != nil {
		return nil, fmt.Errorf("invalid -git-base %q: %w", cfg.GitBase, err)
	}
	files := []string{cfg.GitFile}
	if cfg.GitFile == "" {
		seen := map[string]struct{}{}
		for _, args := range [][]string{{"diff", "--name-only", cfg.GitBase}, {"ls-files", "--others", "--exclude-standard"}} {
			out, err := gitCmd(cfg.RepoDir, args...)
			if err != nil {
				return nil, err
			}
			for _, line := range strings.Split(string(out), "\n") {
				p := strings.TrimSpace(line)
				if ext := strings.ToLower(filepath.Ext(p)); ext == ".json" || ext == ".yaml" || ext == ".yml" {
					seen[p] = struct{}{}
				}
			}
		}
		files = slices.Sorted(maps.Keys(seen))
	}

	pairs := make([]rawPair, 0, len(files))
	for _, f := range files {
		spec := fmt.Sprintf("%s:%s", cfg.GitBase, filepath.ToSlash(filepath.Clean(f)))
		var before []byte
		if _, err := gitCmd(cfg.RepoDir, "cat-file", "-e", spec); err == nil {
			if before, err = gitCmd(cfg.RepoDir, "show", spec); err != nil {
				return nil, err
			}
		}
		disk := f
		if !filepath.IsAbs(disk) {
			disk = filepath.Join(cfg.RepoDir, f)
		}
		after, err := os.ReadFile(disk)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		pairs = append(pairs, rawPair{f, before, after})
	}
	return pairs, nil
}

func evalPair(ctx context.Context, beforeRaw, afterRaw []byte, path string, cfg cliConfig, miniEng *firstprinciples.Engine, miniPols []firstprinciples.CompiledPolicy) (fileReport, error) {
	before, err := jsondiff.Parse(beforeRaw)
	if err != nil {
		return fileReport{}, fmt.Errorf("parse before %s: %w", path, err)
	}
	after, err := jsondiff.Parse(afterRaw)
	if err != nil {
		return fileReport{}, fmt.Errorf("parse after %s: %w", path, err)
	}
	var pre []kit.Result
	if cfg.Mutate && after != nil {
		patched, mutRes, err := kit.Mutate(ctx, cfg.Bundle, kit.JSONRequest(after), &unstructured.Unstructured{Object: after}, cfg.Explain)
		if err != nil {
			return fileReport{}, fmt.Errorf("mutate: %w", err)
		}
		pre, after = mutRes, patched.Object
	}
	ev, err := jsondiff.Build(before, after, path, cfg.Ticket)
	if err != nil {
		return fileReport{}, err
	}
	payload, err := ev.ToMap()
	if err != nil {
		return fileReport{}, err
	}
	var results []kit.Result
	var enforced, warnings int
	if miniEng != nil {
		results, enforced, warnings, err = miniEng.Evaluate(miniPols, payload)
	} else {
		results, enforced, warnings, err = kit.Validate(ctx, cfg.Bundle, kit.JSONRequest(payload), cfg.Explain)
	}
	if err != nil {
		return fileReport{}, err
	}
	return fileReport{Event: ev, Results: append(pre, results...), Enforced: enforced, Warnings: warnings}, nil
}

func gitCmd(dir string, args ...string) ([]byte, error) {
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}

func readOptional(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	return os.ReadFile(path)
}

func identifier(ev jsondiff.ChangeEvent) string {
	for _, doc := range []map[string]any{ev.After, ev.Before} {
		if meta, ok := doc["metadata"].(map[string]any); ok {
			if name, _ := meta["name"].(string); name != "" {
				return name
			}
		}
	}
	return ev.ResourcePath
}

func must(format string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, format+"\n", err)
		os.Exit(2)
	}
}

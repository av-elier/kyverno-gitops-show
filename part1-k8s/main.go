package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	"github.com/kyverno/kyverno/pkg/config"
	"github.com/kyverno/kyverno/pkg/engine"
	"github.com/kyverno/kyverno/pkg/engine/adapters"
	engineapi "github.com/kyverno/kyverno/pkg/engine/api"
	"github.com/kyverno/kyverno/pkg/engine/factories"
	"github.com/kyverno/kyverno/pkg/engine/jmespath"
	"github.com/kyverno/kyverno/pkg/imageverifycache"
	"github.com/kyverno/kyverno/pkg/registryclient"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

type evalSummary struct {
	PolicyName string
	Action     string
	Resource   string
	RuleName   string
	Status     engineapi.RuleStatus
	Message    string
}

func main() {
	policyPath := flag.String("policy", "./policies", "Path to a ClusterPolicy YAML file or directory")
	manifestPath := flag.String("manifest", "./manifests/deployment-bad.yaml", "Path to a Kubernetes resource YAML file or directory")
	flag.Parse()

	policies, err := loadClusterPolicies(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading policies: %v\n", err)
		os.Exit(2)
	}
	resources, err := loadResources(*manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading manifests: %v\n", err)
		os.Exit(2)
	}

	summaries, enforcedFailures, err := evaluatePolicies(context.Background(), policies, resources)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error evaluating policies: %v\n", err)
		os.Exit(2)
	}

	for _, s := range summaries {
		fmt.Printf("[%s] policy=%s action=%s resource=%s rule=%s\n",
			strings.ToUpper(string(s.Status)), s.PolicyName, s.Action, s.Resource, s.RuleName)
		if s.Message != "" && s.Status != engineapi.RuleStatusPass {
			fmt.Printf("       message: %s\n", s.Message)
		}
	}

	fmt.Printf("\nSummary: %d rule evaluations, %d enforced failures\n", len(summaries), enforcedFailures)
	if enforcedFailures > 0 {
		os.Exit(1)
	}
}

func evaluatePolicies(
	ctx context.Context,
	policies []*kyvernov1.ClusterPolicy,
	resources []unstructured.Unstructured,
) ([]evalSummary, int, error) {
	cfg := config.NewDefaultConfiguration(false)
	jp := jmespath.New(cfg)

	eng := engine.NewEngine(
		cfg,
		config.NewDefaultMetricsConfiguration(),
		jp,
		nil,
		factories.DefaultRegistryClientFactory(adapters.RegistryClient(registryclient.NewOrDie()), nil),
		imageverifycache.DisabledImageVerifyCache(),
		factories.DefaultContextLoaderFactory(nil),
		nil,
	)

	var summaries []evalSummary
	enforcedFailures := 0

	for _, res := range resources {
		resLabel := fmt.Sprintf("%s/%s", res.GetKind(), res.GetName())
		if ns := res.GetNamespace(); ns != "" {
			resLabel = fmt.Sprintf("%s/%s/%s", res.GetKind(), ns, res.GetName())
		}

		for _, pol := range policies {
			pCtx, err := engine.NewPolicyContext(jp, res, kyvernov1.Create, nil, cfg)
			if err != nil {
				return nil, 0, fmt.Errorf("creating policy context for %s: %w", resLabel, err)
			}
			pCtx = pCtx.WithPolicy(pol)

			resp := eng.Validate(ctx, pCtx)
			action := string(pol.Spec.ValidationFailureAction)
			if action == "" {
				action = string(kyvernov1.Audit)
			}

			for _, ruleResp := range resp.PolicyResponse.Rules {
				status := ruleResp.Status()
				if status == engineapi.RuleStatusFail && pol.Spec.ValidationFailureAction.Enforce() {
					enforcedFailures++
				}
				summaries = append(summaries, evalSummary{
					PolicyName: pol.GetName(),
					Action:     action,
					Resource:   resLabel,
					RuleName:   ruleResp.Name(),
					Status:     status,
					Message:    ruleResp.Message(),
				})
			}
		}
	}

	return summaries, enforcedFailures, nil
}

func loadClusterPolicies(root string) ([]*kyvernov1.ClusterPolicy, error) {
	files, err := collectYAMLFiles(root)
	if err != nil {
		return nil, err
	}
	var policies []*kyvernov1.ClusterPolicy
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		for _, doc := range splitYAMLDocuments(string(raw)) {
			var pol kyvernov1.ClusterPolicy
			if err := yaml.Unmarshal([]byte(doc), &pol); err != nil {
				return nil, fmt.Errorf("parsing policy %s: %w", f, err)
			}
			if pol.Kind != "ClusterPolicy" {
				continue
			}
			policies = append(policies, &pol)
		}
	}
	return policies, nil
}

func loadResources(root string) ([]unstructured.Unstructured, error) {
	files, err := collectYAMLFiles(root)
	if err != nil {
		return nil, err
	}
	var resources []unstructured.Unstructured
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		for _, doc := range splitYAMLDocuments(string(raw)) {
			var obj map[string]any
			if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
				return nil, fmt.Errorf("parsing manifest %s: %w", f, err)
			}
			if len(obj) == 0 {
				continue
			}
			resources = append(resources, unstructured.Unstructured{Object: obj})
		}
	}
	return resources, nil
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
	parts := strings.Split(content, "\n---")
	var docs []string
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" && trimmed != "---" {
			docs = append(docs, trimmed)
		}
	}
	return docs
}

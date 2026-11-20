package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	policiesv1beta1 "github.com/kyverno/api/api/policies.kyverno.io/v1beta1"
	celengine "github.com/kyverno/kyverno/pkg/cel/engine"
	"github.com/kyverno/kyverno/pkg/cel/matching"
	vpolcompiler "github.com/kyverno/kyverno/pkg/cel/policies/vpol/compiler"
	vpolengine "github.com/kyverno/kyverno/pkg/cel/policies/vpol/engine"
	engineapi "github.com/kyverno/kyverno/pkg/engine/api"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/sets"
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
	policyPath := flag.String("policy", "./policies", "Path to a ValidatingPolicy YAML file or directory")
	manifestPath := flag.String("manifest", "./manifests/deployment-bad.yaml", "Path to a Kubernetes resource YAML file or directory")
	flag.Parse()

	policies, err := loadValidatingPolicies(*policyPath)
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

	fmt.Printf("\nSummary: %d policy evaluations, %d enforced failures\n", len(summaries), enforcedFailures)
	if enforcedFailures > 0 {
		os.Exit(1)
	}
}

func evaluatePolicies(
	ctx context.Context,
	policies []policiesv1beta1.ValidatingPolicyLike,
	resources []unstructured.Unstructured,
) ([]evalSummary, int, error) {
	provider, err := vpolengine.NewProvider(vpolcompiler.NewCompiler(), policies, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("compiling validating policies: %w", err)
	}

	noopNsResolver := func(string) *corev1.Namespace { return nil }
	eng := vpolengine.NewEngine(provider, noopNsResolver, matching.NewMatcher())

	var summaries []evalSummary
	enforcedFailures := 0

	for i := range resources {
		res := resources[i]
		resLabel := formatResourceLabel(res)
		gvk := res.GroupVersionKind()
		gvr, _ := apimeta.UnsafeGuessKindToResource(gvk)

		req := celengine.Request(
			nil,
			gvk,
			gvr,
			"",
			res.GetName(),
			res.GetNamespace(),
			admissionv1.Create,
			authenticationv1.UserInfo{},
			&res,
			nil,
			false,
			nil,
		)

		resp, err := eng.Handle(ctx, req, nil)
		if err != nil {
			return nil, 0, fmt.Errorf("evaluating policies for %s: %w", resLabel, err)
		}

		for _, polResp := range resp.Policies {
			action := formatValidationActions(polResp.Actions)
			for _, ruleResp := range polResp.Rules {
				status := ruleResp.Status()
				if status == engineapi.RuleStatusError {
					return nil, 0, fmt.Errorf("policy %s rule %s error: %s",
						polResp.Policy.GetName(), ruleResp.Name(), ruleResp.Message())
				}
				if status == engineapi.RuleStatusFail && polResp.Actions.Has(admissionregistrationv1.Deny) {
					enforcedFailures++
				}
				summaries = append(summaries, evalSummary{
					PolicyName: polResp.Policy.GetName(),
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

func formatResourceLabel(res unstructured.Unstructured) string {
	if ns := res.GetNamespace(); ns != "" {
		return fmt.Sprintf("%s/%s/%s", res.GetKind(), ns, res.GetName())
	}
	return fmt.Sprintf("%s/%s", res.GetKind(), res.GetName())
}

func formatValidationActions(actions sets.Set[admissionregistrationv1.ValidationAction]) string {
	switch {
	case actions.Has(admissionregistrationv1.Deny):
		return string(admissionregistrationv1.Deny)
	case actions.Has(admissionregistrationv1.Audit):
		return string(admissionregistrationv1.Audit)
	case actions.Has(admissionregistrationv1.Warn):
		return string(admissionregistrationv1.Warn)
	default:
		return string(admissionregistrationv1.Audit)
	}
}

func loadValidatingPolicies(root string) ([]policiesv1beta1.ValidatingPolicyLike, error) {
	files, err := collectYAMLFiles(root)
	if err != nil {
		return nil, err
	}
	var policies []policiesv1beta1.ValidatingPolicyLike
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

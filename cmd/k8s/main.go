package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"kyverno-show/internal/kit"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type resourceReport struct {
	Target  string
	Results []kit.Result
}

func main() {
	policyPath := flag.String("policy", "./k8s/policies", "Policy YAML/JSON file or directory")
	manifestPath := flag.String("manifest", "./k8s/manifests/deployment-bad.yaml", "Target Kubernetes manifest YAML/JSON")
	oldPath := flag.String("old-manifest", "", "Optional previous manifest for simulating UPDATE (oldObject)")
	exceptionPath := flag.String("exception", "", "Optional PolicyException YAML/JSON file or directory")
	mutate := flag.Bool("mutate", false, "Apply MutatingPolicies before ValidatingPolicies")
	explain := flag.Bool("explain", false, "Print Kyverno CEL decision traces")
	flag.Parse()

	bundle, err := kit.LoadPolicies(*policyPath, *exceptionPath)
	must("error loading policies: %v", err)
	resources, err := kit.LoadUnstructured(*manifestPath)
	must("error loading manifests: %v", err)
	var oldResources []unstructured.Unstructured
	if *oldPath != "" {
		oldResources, err = kit.LoadUnstructured(*oldPath)
		must("error loading old manifests: %v", err)
	}

	reports, enforced, err := evaluateAll(context.Background(), bundle, resources, oldResources, *mutate, *explain)
	must("evaluation error: %v", err)

	total := 0
	for _, rep := range reports {
		kit.PrintResults(os.Stdout, rep.Target, rep.Results, *explain)
		total += len(rep.Results)
	}
	fmt.Printf("\nSummary: %d evaluations, %d enforced failures\n", total, enforced)
	if enforced > 0 {
		os.Exit(1)
	}
}

func evaluateAll(ctx context.Context, bundle kit.PolicyBundle, resources, oldResources []unstructured.Unstructured, mutate, explain bool) ([]resourceReport, int, error) {
	reports := make([]resourceReport, 0, len(resources))
	enforced := 0
	for i := range resources {
		res := resources[i]
		target := fmt.Sprintf("%s/%s", res.GetKind(), res.GetName())
		if ns := res.GetNamespace(); ns != "" {
			target = fmt.Sprintf("%s/%s/%s", res.GetKind(), ns, res.GetName())
		}
		op := admissionv1.Create
		var oldRes *unstructured.Unstructured
		if len(oldResources) > 0 {
			op = admissionv1.Update
			oldRes = &oldResources[min(i, len(oldResources)-1)]
		}
		var results []kit.Result
		if mutate {
			patched, mutRes, err := kit.Mutate(ctx, bundle, kit.K8sRequest(&res, oldRes, op), &res, explain)
			if err != nil {
				return nil, 0, fmt.Errorf("mutate %s: %w", target, err)
			}
			results, res = mutRes, *patched
		}
		valRes, enf, _, err := kit.Validate(ctx, bundle, kit.K8sRequest(&res, oldRes, op), explain)
		if err != nil {
			return nil, 0, fmt.Errorf("validate %s: %w", target, err)
		}
		enforced += enf
		reports = append(reports, resourceReport{Target: target, Results: append(results, valRes...)})
	}
	return reports, enforced, nil
}

func must(format string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, format+"\n", err)
		os.Exit(2)
	}
}

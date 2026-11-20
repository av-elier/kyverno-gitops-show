package main

import (
	"context"
	"testing"

	engineapi "github.com/kyverno/kyverno/pkg/engine/api"
)

func TestKubernetesPolicies(t *testing.T) {
	policies, err := loadValidatingPolicies("./policies")
	if err != nil {
		t.Fatalf("failed to load policies: %v", err)
	}
	if len(policies) != 3 {
		t.Fatalf("expected 3 validating policies, got %d", len(policies))
	}

	t.Run("bad deployment fails deny and audit policies", func(t *testing.T) {
		res, err := loadResources("./manifests/deployment-bad.yaml")
		if err != nil {
			t.Fatalf("failed to load bad deployment: %v", err)
		}
		summaries, enforcedFailures, err := evaluatePolicies(context.Background(), policies, res)
		if err != nil {
			t.Fatalf("evaluation failed: %v", err)
		}
		if enforcedFailures != 2 {
			t.Fatalf("expected 2 enforced (Deny) failures, got %d (summaries=%+v)", enforcedFailures, summaries)
		}

		failCount := 0
		for _, s := range summaries {
			if s.Status == engineapi.RuleStatusFail {
				failCount++
			}
		}
		if failCount != 3 {
			t.Fatalf("expected 3 total failed policies (2 Deny + 1 Audit), got %d", failCount)
		}
	})

	t.Run("good deployment passes all policies", func(t *testing.T) {
		res, err := loadResources("./manifests/deployment-good.yaml")
		if err != nil {
			t.Fatalf("failed to load good deployment: %v", err)
		}
		summaries, enforcedFailures, err := evaluatePolicies(context.Background(), policies, res)
		if err != nil {
			t.Fatalf("evaluation failed: %v", err)
		}
		if enforcedFailures != 0 {
			t.Fatalf("expected 0 enforced failures, got %d", enforcedFailures)
		}
		if len(summaries) != 3 {
			t.Fatalf("expected 3 policy evaluations, got %d", len(summaries))
		}
		for _, s := range summaries {
			if s.Status != engineapi.RuleStatusPass {
				t.Fatalf("expected policy %s/%s to pass, got %s (%s)", s.PolicyName, s.RuleName, s.Status, s.Message)
			}
		}
	})
}

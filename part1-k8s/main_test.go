package main

import (
	"context"
	"testing"

	engineapi "github.com/kyverno/kyverno/pkg/engine/api"
)

func TestKubernetesPolicies(t *testing.T) {
	policies, err := loadClusterPolicies("./policies")
	if err != nil {
		t.Fatalf("failed to load policies: %v", err)
	}
	if len(policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(policies))
	}

	t.Run("bad deployment fails enforced and audit rules", func(t *testing.T) {
		res, err := loadResources("./manifests/deployment-bad.yaml")
		if err != nil {
			t.Fatalf("failed to load bad deployment: %v", err)
		}
		summaries, enforcedFailures, err := evaluatePolicies(context.Background(), policies, res)
		if err != nil {
			t.Fatalf("evaluation failed: %v", err)
		}
		if enforcedFailures != 2 {
			t.Fatalf("expected 2 enforced failures, got %d (summaries=%+v)", enforcedFailures, summaries)
		}

		failCount := 0
		for _, s := range summaries {
			if s.Status == engineapi.RuleStatusFail {
				failCount++
			}
		}
		if failCount != 3 {
			t.Fatalf("expected 3 total failed rules (2 Enforce + 1 Audit), got %d", failCount)
		}
	})

	t.Run("good deployment passes all rules", func(t *testing.T) {
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
		for _, s := range summaries {
			if s.Status != engineapi.RuleStatusPass {
				t.Fatalf("expected rule %s/%s to pass, got %s (%s)", s.PolicyName, s.RuleName, s.Status, s.Message)
			}
		}
	})
}

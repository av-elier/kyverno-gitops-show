package main

import (
	"context"
	"os"
	"testing"

	policiesv1beta1 "github.com/kyverno/api/api/policies.kyverno.io/v1beta1"
	celengine "github.com/kyverno/kyverno/pkg/cel/engine"
	vpolcompiler "github.com/kyverno/kyverno/pkg/cel/policies/vpol/compiler"
	vpolengine "github.com/kyverno/kyverno/pkg/cel/policies/vpol/engine"
	engineapi "github.com/kyverno/kyverno/pkg/engine/api"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"kyverno-show/part2-gitops/internal/diffparse"
	"kyverno-show/part2-gitops/internal/firstprinciples"
)

func evalBothEngines(t *testing.T, diffFile string, meta diffparse.Metadata) (kyvernoFails int, miniFails int) {
	t.Helper()
	raw, err := os.ReadFile(diffFile)
	if err != nil {
		t.Fatalf("read diff %s: %v", diffFile, err)
	}
	report := diffparse.Parse(string(raw), meta)
	payload, err := report.ToMap()
	if err != nil {
		t.Fatalf("toMap: %v", err)
	}
	policies, err := loadValidatingPolicies("./policies")
	if err != nil {
		t.Fatalf("load policies: %v", err)
	}

	kyvernoFails = countKyvernoCELFailures(t, policies, payload)

	mini, err := firstprinciples.NewEngine()
	if err != nil {
		t.Fatalf("mini NewEngine error: %v", err)
	}
	outcomes, err := mini.Evaluate(policies, payload)
	if err != nil {
		t.Fatalf("mini engine error: %v", err)
	}
	for _, o := range outcomes {
		if o.Status == firstprinciples.StatusFail {
			miniFails++
		}
	}
	return kyvernoFails, miniFails
}

func countKyvernoCELFailures(t *testing.T, policies []*policiesv1beta1.ValidatingPolicy, payload map[string]any) int {
	t.Helper()
	likes := make([]policiesv1beta1.ValidatingPolicyLike, len(policies))
	for i, p := range policies {
		likes[i] = p
	}
	provider, err := vpolengine.NewProvider(vpolcompiler.NewCompiler(), likes, nil)
	if err != nil {
		t.Fatalf("compile policies: %v", err)
	}
	eng := vpolengine.NewEngine(provider, nil, nil)
	resp, err := eng.Handle(context.Background(), celengine.RequestFromJSON(nil, &unstructured.Unstructured{Object: payload}), nil)
	if err != nil {
		t.Fatalf("kyverno engine error: %v", err)
	}

	fails := 0
	for _, polResp := range resp.Policies {
		for _, ruleResp := range polResp.Rules {
			if ruleResp.Status() == engineapi.RuleStatusError {
				t.Fatalf("policy %s rule %s error: %s", polResp.Policy.GetName(), ruleResp.Name(), ruleResp.Message())
			}
			if ruleResp.Status() == engineapi.RuleStatusFail {
				fails++
			}
		}
	}
	return fails
}

func TestGitOpsDiffValidationParity(t *testing.T) {
	t.Run("bad prod change fails all 4 rules in both engines", func(t *testing.T) {
		kFails, mFails := evalBothEngines(t, "./samples/bad-prod-change.diff", diffparse.Metadata{
			Author: "dev-alice",
			Branch: "hotfix/break-prod",
		})
		if kFails != 4 || mFails != 4 {
			t.Fatalf("expected 4 failed policies in both engines, got kyverno=%d mini=%d", kFails, mFails)
		}
	})

	t.Run("good prod change with ticket in commit message passes both engines", func(t *testing.T) {
		kFails, mFails := evalBothEngines(t, "./samples/good-prod-change.diff", diffparse.Metadata{
			Author:        "dev-bob",
			Branch:        "release/v2.1.1",
			CommitMessage: "chore(prod): bump payments image (CHG-4821)",
		})
		if kFails != 0 || mFails != 0 {
			t.Fatalf("expected 0 failures in both engines, got kyverno=%d mini=%d", kFails, mFails)
		}
	})

	t.Run("staging change with replicas 0 and no ticket passes prod-scoped rules", func(t *testing.T) {
		kFails, mFails := evalBothEngines(t, "./samples/staging-only.diff", diffparse.Metadata{
			Author: "dev-charlie",
			Branch: "feat/staging-scale-down",
		})
		if kFails != 0 || mFails != 0 {
			t.Fatalf("expected 0 failures in both engines, got kyverno=%d mini=%d", kFails, mFails)
		}
	})
}

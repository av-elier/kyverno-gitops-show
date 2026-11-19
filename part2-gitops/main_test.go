package main

import (
	"context"
	"os"
	"testing"

	"github.com/kyverno/kyverno-json/pkg/apis/policy/v1alpha1"
	jsonengine "github.com/kyverno/kyverno-json/pkg/json-engine"
	"github.com/kyverno/kyverno-json/pkg/policy"

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
	policies, err := policy.Load("./policies")
	if err != nil {
		t.Fatalf("load policies: %v", err)
	}

	kyvernoFails = countKyvernoJSONFailures(t, policies, payload)

	mini := firstprinciples.NewEngine()
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

func countKyvernoJSONFailures(t *testing.T, policies []*v1alpha1.ValidatingPolicy, payload map[string]any) int {
	t.Helper()
	eng := jsonengine.New()
	resp := eng.Run(context.Background(), jsonengine.Request{
		Resource: payload,
		Policies: policies,
	})
	fails := 0
	for _, polResp := range resp.Policies {
		for _, ruleResp := range polResp.Rules {
			if ruleResp.Error != nil {
				t.Fatalf("rule %s error: %v", ruleResp.Rule.Name, ruleResp.Error)
			}
			if len(ruleResp.Violations) > 0 {
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
			t.Fatalf("expected 4 failed rules in both engines, got kyverno-json=%d mini=%d", kFails, mFails)
		}
	})

	t.Run("good prod change with ticket in commit message passes both engines", func(t *testing.T) {
		kFails, mFails := evalBothEngines(t, "./samples/good-prod-change.diff", diffparse.Metadata{
			Author:        "dev-bob",
			Branch:        "release/v2.1.1",
			CommitMessage: "chore(prod): bump payments image (CHG-4821)",
		})
		if kFails != 0 || mFails != 0 {
			t.Fatalf("expected 0 failures in both engines, got kyverno-json=%d mini=%d", kFails, mFails)
		}
	})

	t.Run("staging change with replicas 0 and no ticket passes prod-scoped rules", func(t *testing.T) {
		kFails, mFails := evalBothEngines(t, "./samples/staging-only.diff", diffparse.Metadata{
			Author: "dev-charlie",
			Branch: "feat/staging-scale-down",
		})
		if kFails != 0 || mFails != 0 {
			t.Fatalf("expected 0 failures in both engines, got kyverno-json=%d mini=%d", kFails, mFails)
		}
	})
}

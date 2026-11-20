package firstprinciples

import (
	"strings"
	"testing"

	policiesv1beta1 "github.com/kyverno/api/api/policies.kyverno.io/v1beta1"
	engineapi "github.com/kyverno/kyverno/pkg/engine/api"
	"sigs.k8s.io/yaml"
)

func TestMiniCELEngineCompileVariablesAndActions(t *testing.T) {
	policyYAML := `
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: unit-test-deny
spec:
  validationActions: [Deny]
  evaluation: {mode: JSON}
  matchConditions:
    - name: only-prod
      expression: "object.env == 'prod'"
    - name: exclude-release-bot
      expression: "object.author != 'release-bot'"
  variables:
    - name: count
      expression: "object.?count.orValue(null)"
    - name: hasTicket
      expression: "has(object.ticket) && object.ticket.matches('^CHG-[0-9]+$')"
  validations:
    - messageExpression: "'missing ticket/hotfix for count=' + (variables.count != null ? string(variables.count) : 'missing')"
      expression: "((has(object.hotfix) && object.hotfix == true) || variables.hasTicket) && (variables.count == null || variables.count >= 5)"
---
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: unit-test-warn
spec:
  validationActions: [Warn]
  evaluation: {mode: JSON}
  validations:
    - message: "non-blocking warning"
      expression: "object.?warn.orValue(false) == false"
`
	var denyPol, warnPol policiesv1beta1.ValidatingPolicy
	docs := strings.Split(policyYAML, "---")
	if err := yaml.Unmarshal([]byte(docs[0]), &denyPol); err != nil {
		t.Fatalf("unmarshal deny policy: %v", err)
	}
	if err := yaml.Unmarshal([]byte(docs[1]), &warnPol); err != nil {
		t.Fatalf("unmarshal warn policy: %v", err)
	}

	eng, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	compiled, err := eng.Compile([]policiesv1beta1.ValidatingPolicyLike{&denyPol, &warnPol})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	cases := []struct {
		name               string
		payload            map[string]any
		wantDeny, wantWarn engineapi.RuleStatus
		wantMsg            string
		wantEnf, wantWrn   int
	}{
		{"non-prod skipped", map[string]any{"env": "staging", "author": "alice", "hotfix": false}, engineapi.RuleStatusSkip, engineapi.RuleStatusPass, "", 0, 0},
		{"release-bot skipped", map[string]any{"env": "prod", "author": "release-bot", "hotfix": false}, engineapi.RuleStatusSkip, engineapi.RuleStatusPass, "", 0, 0},
		{"prod CHG ticket and omitted count passes", map[string]any{"env": "prod", "author": "alice", "ticket": "CHG-101"}, engineapi.RuleStatusPass, engineapi.RuleStatusPass, "", 0, 0},
		{"prod missing ticket + warn", map[string]any{"env": "prod", "author": "alice", "ticket": "NONE", "warn": true}, engineapi.RuleStatusFail, engineapi.RuleStatusFail, "missing ticket/hotfix for count=missing", 1, 1},
		{"prod low numeric count", map[string]any{"env": "prod", "author": "alice", "hotfix": true, "count": float64(2)}, engineapi.RuleStatusFail, engineapi.RuleStatusPass, "missing ticket/hotfix for count=2", 1, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, enf, wrn, err := eng.Evaluate(compiled, tc.payload)
			if err != nil {
				t.Fatalf("evaluate error: %v", err)
			}
			if enf != tc.wantEnf || wrn != tc.wantWrn {
				t.Fatalf("counts mismatch: got (%d,%d), want (%d,%d)", enf, wrn, tc.wantEnf, tc.wantWrn)
			}
			if res[0].Status != tc.wantDeny || res[1].Status != tc.wantWarn {
				t.Fatalf("status mismatch: got (%s,%s), want (%s,%s)", res[0].Status, res[1].Status, tc.wantDeny, tc.wantWarn)
			}
			if tc.wantMsg != "" && res[0].Message != tc.wantMsg {
				t.Fatalf("expected message %q, got %q", tc.wantMsg, res[0].Message)
			}
		})
	}
}

package firstprinciples

import (
	"testing"

	policiesv1beta1 "github.com/kyverno/api/api/policies.kyverno.io/v1beta1"
	"sigs.k8s.io/yaml"
)

func TestMiniCELEngineMatchVariablesAndValidations(t *testing.T) {
	policyYAML := `
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: unit-test-policy
spec:
  validationActions:
    - Deny
  evaluation:
    mode: JSON
  matchConditions:
    - name: only-prod
      expression: "object.env == 'prod'"
    - name: exclude-release-bot
      expression: "object.author != 'release-bot'"
  variables:
    - name: hasTicket
      expression: "has(object.ticket) && object.ticket.matches('^CHG-[0-9]+$')"
  validations:
    - message: "must have hotfix flag or CHG ticket"
      expression: "(has(object.hotfix) && object.hotfix == true) || variables.hasTicket"
`
	var pol policiesv1beta1.ValidatingPolicy
	if err := yaml.Unmarshal([]byte(policyYAML), &pol); err != nil {
		t.Fatalf("unmarshal policy: %v", err)
	}

	eng, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	cases := []struct {
		name       string
		payload    map[string]any
		wantStatus RuleStatus
	}{
		{
			name:       "non-prod skipped by matchCondition",
			payload:    map[string]any{"env": "staging", "author": "alice", "hotfix": false, "ticket": ""},
			wantStatus: StatusSkip,
		},
		{
			name:       "release-bot skipped by matchCondition",
			payload:    map[string]any{"env": "prod", "author": "release-bot", "hotfix": false, "ticket": ""},
			wantStatus: StatusSkip,
		},
		{
			name:       "prod with CHG ticket passes via variable",
			payload:    map[string]any{"env": "prod", "author": "alice", "hotfix": false, "ticket": "CHG-101", "count": float64(5)},
			wantStatus: StatusPass,
		},
		{
			name:       "prod without hotfix or CHG fails",
			payload:    map[string]any{"env": "prod", "author": "alice", "hotfix": false, "ticket": "NONE"},
			wantStatus: StatusFail,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outcomes, err := eng.Evaluate([]*policiesv1beta1.ValidatingPolicy{&pol}, tc.payload)
			if err != nil {
				t.Fatalf("evaluate error: %v", err)
			}
			if len(outcomes) != 1 || outcomes[0].Status != tc.wantStatus {
				t.Fatalf("expected status %s, got %+v", tc.wantStatus, outcomes)
			}
		})
	}
}

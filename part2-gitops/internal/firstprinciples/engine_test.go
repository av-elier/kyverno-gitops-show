package firstprinciples

import (
	"testing"

	"github.com/kyverno/kyverno-json/pkg/apis/policy/v1alpha1"
	"sigs.k8s.io/yaml"
)

func TestMiniEngineMatchExcludeAndAny(t *testing.T) {
	policyYAML := `
apiVersion: json.kyverno.io/v1alpha1
kind: ValidatingPolicy
metadata:
  name: unit-test-policy
spec:
  rules:
    - name: check-env-or-ticket
      match:
        all:
          - env: "prod"
      exclude:
        all:
          - author: "release-bot"
      assert:
        any:
          - message: "must have hotfix flag or CHG ticket"
            check:
              hotfix: true
          - message: "must have hotfix flag or CHG ticket"
            check:
              (wildcard('CHG-*', ticket)): true
`
	var pol v1alpha1.ValidatingPolicy
	if err := yaml.Unmarshal([]byte(policyYAML), &pol); err != nil {
		t.Fatalf("unmarshal policy: %v", err)
	}

	eng := NewEngine()

	cases := []struct {
		name       string
		payload    map[string]any
		wantStatus RuleStatus
	}{
		{
			name:       "non-prod skipped by match",
			payload:    map[string]any{"env": "staging", "author": "alice", "hotfix": false, "ticket": ""},
			wantStatus: StatusSkip,
		},
		{
			name:       "release-bot skipped by exclude",
			payload:    map[string]any{"env": "prod", "author": "release-bot", "hotfix": false, "ticket": ""},
			wantStatus: StatusSkip,
		},
		{
			name:       "prod with CHG ticket passes via assert.any",
			payload:    map[string]any{"env": "prod", "author": "alice", "hotfix": false, "ticket": "CHG-101"},
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
			outcomes, err := eng.Evaluate([]*v1alpha1.ValidatingPolicy{&pol}, tc.payload)
			if err != nil {
				t.Fatalf("evaluate error: %v", err)
			}
			if len(outcomes) != 1 || outcomes[0].Status != tc.wantStatus {
				t.Fatalf("expected status %s, got %+v", tc.wantStatus, outcomes)
			}
		})
	}
}

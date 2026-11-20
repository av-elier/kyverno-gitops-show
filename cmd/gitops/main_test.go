package main

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"kyverno-show/internal/jsondiff"
	"kyverno-show/internal/kit"

	engineapi "github.com/kyverno/kyverno/pkg/engine/api"
)

func repoPath(parts ...string) string {
	return filepath.Join(append([]string{"..", ".."}, parts...)...)
}

func failingPolicies(r fileReport) map[string]string {
	out := map[string]string{}
	for _, res := range r.Results {
		if res.Status == engineapi.RuleStatusFail {
			out[res.Policy] = res.Message
		}
	}
	return out
}

func TestStructuredGitOpsKyvernoAndMiniParity(t *testing.T) {
	bundle, err := kit.LoadPolicies(repoPath("gitops", "policies"))
	if err != nil {
		t.Fatalf("load policies: %v", err)
	}

	cases := []struct {
		name         string
		before       string
		after        string
		wantEnforced int
		wantWarnings int
		wantFailed   []string
	}{
		{"postgres create valid JSON", "", repoPath("gitops", "samples", "postgres-create-valid.json"), 0, 0, nil},
		{"postgres create bad YAML violates prod requirements", "", repoPath("gitops", "samples", "postgres-create-bad.yaml"), 1, 0, []string{"postgres-prod-create-requirements"}},
		{"postgres update bad fails allowlist, disk shrink, and backup floor", repoPath("gitops", "samples", "postgres-update-before.json"), repoPath("gitops", "samples", "postgres-update-bad.json"), 3, 0, []string{"postgres-no-disk-shrink", "postgres-prod-backup-floor", "postgres-update-allowed-attributes"}},
		{"postgres update good passes all rules", repoPath("gitops", "samples", "postgres-update-before.json"), repoPath("gitops", "samples", "postgres-update-good.json"), 0, 0, nil},
		{"postgres large disk jump triggers non-blocking Warn only", repoPath("gitops", "samples", "postgres-update-before.json"), repoPath("gitops", "samples", "postgres-update-warn.json"), 0, 1, []string{"postgres-large-disk-jump"}},
		{"kafka update bad fails allowlist, partition shrink, and replication floor", repoPath("gitops", "samples", "kafka-before.json"), repoPath("gitops", "samples", "kafka-bad.json"), 3, 0, []string{"kafka-no-partition-shrink", "kafka-prod-replication-floor", "kafka-update-allowed-attributes"}},
		{"kafka update good passes all rules", repoPath("gitops", "samples", "kafka-before.json"), repoPath("gitops", "samples", "kafka-good.json"), 0, 0, nil},
		{"kafka acls bad fails array-of-objects guardrail", repoPath("gitops", "samples", "kafka-before.json"), repoPath("gitops", "samples", "kafka-acls-bad.json"), 1, 0, []string{"kafka-prod-acl-guardrails"}},
		{"aws secret bad fails plaintext, rotation/kms, and allowlist", repoPath("gitops", "samples", "aws-secret-before.json"), repoPath("gitops", "samples", "aws-secret-bad.json"), 3, 0, []string{"aws-secret-no-plaintext-value", "aws-secret-prod-rotation-and-kms", "aws-secret-update-allowed-attributes"}},
		{"aws secret good passes all rules", repoPath("gitops", "samples", "aws-secret-before.json"), repoPath("gitops", "samples", "aws-secret-good.json"), 0, 0, nil},
		{"delete skips create and update rules cleanly", repoPath("gitops", "samples", "postgres-update-before.json"), "", 0, 0, nil},
		{"no-op update passes cleanly without null errors", repoPath("gitops", "samples", "postgres-update-before.json"), repoPath("gitops", "samples", "postgres-update-before.json"), 0, 0, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kCfg := cliConfig{RepoDir: ".", BeforePath: tc.before, AfterPath: tc.after, Ticket: "CHG-9001", Bundle: bundle, Engine: "kyverno", Explain: true}
			mCfg := kCfg
			mCfg.Engine = "mini"

			kReps, err := runCLI(context.Background(), kCfg)
			if err != nil {
				t.Fatalf("kyverno engine error: %v", err)
			}
			mReps, err := runCLI(context.Background(), mCfg)
			if err != nil {
				t.Fatalf("mini engine error: %v", err)
			}
			kRep, mRep := kReps[0], mReps[0]

			if kRep.Enforced != tc.wantEnforced || mRep.Enforced != tc.wantEnforced {
				t.Fatalf("enforced mismatch: want=%d kyverno=%d mini=%d", tc.wantEnforced, kRep.Enforced, mRep.Enforced)
			}
			if kRep.Warnings != tc.wantWarnings || mRep.Warnings != tc.wantWarnings {
				t.Fatalf("warnings mismatch: want=%d kyverno=%d mini=%d", tc.wantWarnings, kRep.Warnings, mRep.Warnings)
			}

			kFailed, mFailed := failingPolicies(kRep), failingPolicies(mRep)
			if !reflect.DeepEqual(kFailed, mFailed) {
				t.Fatalf("parity mismatch between kyverno and mini:\nkyverno=%v\nmini=%v", kFailed, mFailed)
			}

			gotNames := make([]string, 0, len(kFailed))
			for name := range kFailed {
				gotNames = append(gotNames, name)
			}
			slices.Sort(gotNames)
			wantNames := slices.Clone(tc.wantFailed)
			slices.Sort(wantNames)
			if !slices.Equal(gotNames, wantNames) {
				t.Fatalf("failing policies mismatch: want=%v got=%v", wantNames, gotNames)
			}
		})
	}
}

func TestRemovedNumericFieldProducesCleanFailureInBothEngines(t *testing.T) {
	bundle, err := kit.LoadPolicies(repoPath("gitops", "policies"))
	if err != nil {
		t.Fatalf("load policies: %v", err)
	}
	before := []byte(`{"kind":"PostgresDatabase","metadata":{"name":"orders-db","environment":"prod"},"spec":{"storageGB":200,"backupRetentionDays":14}}`)
	after := []byte(`{"kind":"PostgresDatabase","metadata":{"name":"orders-db","environment":"prod"},"spec":{"backupRetentionDays":14}}`)

	for _, engine := range []string{"kyverno", "mini"} {
		rep, err := evalPair(context.Background(), before, after, "infra/prod/orders-db.json", cliConfig{Ticket: "CHG-1", Bundle: bundle, Engine: engine}, nil, nil)
		if err != nil {
			t.Fatalf("%s error: %v", engine, err)
		}
		if rep.Enforced != 1 {
			t.Fatalf("%s expected 1 enforced failure, got %d (%+v)", engine, rep.Enforced, rep.Results)
		}
		msg, ok := failingPolicies(rep)["postgres-no-disk-shrink"]
		if !ok || !strings.Contains(msg, "200 -> missing") {
			t.Fatalf("%s expected '200 -> missing' message, got %q", engine, msg)
		}
	}
}

func TestJSONMutatingPolicyAndPolicyException(t *testing.T) {
	bundle, err := kit.LoadPolicies(repoPath("gitops", "policies"), repoPath("gitops", "exceptions", "incident-waiver.yaml"))
	if err != nil {
		t.Fatalf("load policies: %v", err)
	}

	t.Run("JSON MutatingPolicy populates encryptionEnabled and maintenanceWindow", func(t *testing.T) {
		reps, err := runCLI(context.Background(), cliConfig{
			RepoDir: ".", AfterPath: repoPath("gitops", "samples", "postgres-create-bad.yaml"),
			Bundle: bundle, Engine: "kyverno", Mutate: true,
		})
		if err != nil {
			t.Fatalf("runCLI mutate: %v", err)
		}
		if msg := failingPolicies(reps[0])["postgres-prod-create-requirements"]; !strings.Contains(msg, "encrypted=true") {
			t.Fatalf("expected mutated encrypted=true in validation message, got %q", msg)
		}
		var sawMutate bool
		for _, r := range reps[0].Results {
			if r.Policy == "mutate-postgres-defaults" && r.Status == engineapi.RuleStatusPass {
				sawMutate = true
			}
		}
		if !sawMutate {
			t.Fatalf("expected mutate-postgres-defaults pass entry in results: %+v", reps[0].Results)
		}
	})

	t.Run("PolicyException grants waiver for INC ticket and refuses CHG ticket", func(t *testing.T) {
		before := repoPath("gitops", "samples", "postgres-update-before.json")
		after := repoPath("gitops", "samples", "postgres-update-bad.json")

		incReps, err := runCLI(context.Background(), cliConfig{
			RepoDir: ".", BeforePath: before, AfterPath: after, Ticket: "INC-9911", Bundle: bundle, Engine: "kyverno",
		})
		if err != nil {
			t.Fatalf("runCLI INC waiver: %v", err)
		}
		if incReps[0].Enforced != 2 {
			t.Fatalf("expected 2 remaining failures after INC waiver, got %d (%+v)", incReps[0].Enforced, incReps[0].Results)
		}
		if _, stillFailed := failingPolicies(incReps[0])["postgres-update-allowed-attributes"]; stillFailed {
			t.Fatalf("expected postgres-update-allowed-attributes to be exempted")
		}

		chgReps, err := runCLI(context.Background(), cliConfig{
			RepoDir: ".", BeforePath: before, AfterPath: after, Ticket: "CHG-123", Bundle: bundle, Engine: "kyverno",
		})
		if err != nil {
			t.Fatalf("runCLI CHG refused: %v", err)
		}
		if chgReps[0].Enforced != 3 {
			t.Fatalf("expected 3 failures when compensating control fails, got %d", chgReps[0].Enforced)
		}
		if msg := failingPolicies(chgReps[0])["postgres-update-allowed-attributes"]; !strings.Contains(msg, "INC-####") {
			t.Fatalf("expected INC-#### compensating control refusal message, got %q", msg)
		}
	})
}

func TestMultiFileGitBaseScan(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not available")
	}
	repo := t.TempDir()
	t.Cleanup(func() {
		_ = filepath.WalkDir(repo, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			mode := os.FileMode(0o600)
			if d.IsDir() {
				mode = 0o700
			}
			_ = os.Chmod(path, mode)
			return nil
		})
	})

	runGit := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %s (%v)", args, string(out), err)
		}
	}
	runGit("init")
	runGit("config", "user.email", "ci@example.com")
	runGit("config", "user.name", "CI Bot")

	dbRel := filepath.Join("infra", "prod", "orders-db.json")
	if err := os.MkdirAll(filepath.Dir(filepath.Join(repo, dbRel)), 0o755); err != nil {
		t.Fatal(err)
	}
	beforeDB, err := os.ReadFile(repoPath("gitops", "samples", "postgres-update-before.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, dbRel), beforeDB, 0o644); err != nil {
		t.Fatal(err)
	}
	runGit("add", ".")
	runGit("commit", "-m", "initial prod db")

	badDB, err := os.ReadFile(repoPath("gitops", "samples", "postgres-update-bad.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, dbRel), badDB, 0o644); err != nil {
		t.Fatal(err)
	}
	newYAML, err := os.ReadFile(repoPath("gitops", "samples", "postgres-create-bad.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "infra", "prod", "new-db.yaml"), newYAML, 0o644); err != nil {
		t.Fatal(err)
	}

	bundle, err := kit.LoadPolicies(repoPath("gitops", "policies"))
	if err != nil {
		t.Fatalf("load policies: %v", err)
	}
	reps, err := runCLI(context.Background(), cliConfig{RepoDir: repo, GitBase: "HEAD", Bundle: bundle, Engine: "kyverno"})
	if err != nil {
		t.Fatalf("multi-file git scan error: %v", err)
	}
	if len(reps) != 2 {
		t.Fatalf("expected 2 changed file reports, got %d", len(reps))
	}
	if reps[0].Event.Operation != jsondiff.OpCreate || reps[0].Enforced != 1 {
		t.Fatalf("expected new-db.yaml create failure=1, got %+v", reps[0])
	}
	if reps[1].Event.Operation != jsondiff.OpUpdate || reps[1].Enforced != 3 {
		t.Fatalf("expected orders-db.json update failures=3, got %+v", reps[1])
	}
}

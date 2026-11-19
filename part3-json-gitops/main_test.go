package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/kyverno/kyverno-json/pkg/policy"

	"kyverno-show/part3-json-gitops/internal/jsondiff"
)

func evalSample(t *testing.T, beforeFile, afterFile string) int {
	t.Helper()
	var beforeRaw, afterRaw []byte
	var err error
	if beforeFile != "" {
		beforeRaw, err = os.ReadFile(beforeFile)
		if err != nil {
			t.Fatalf("read before %s: %v", beforeFile, err)
		}
	}
	if afterFile != "" {
		afterRaw, err = os.ReadFile(afterFile)
		if err != nil {
			t.Fatalf("read after %s: %v", afterFile, err)
		}
	}

	logicalPath := afterFile
	if logicalPath == "" {
		logicalPath = beforeFile
	}

	ev, err := jsondiff.BuildChangeEvent(beforeRaw, afterRaw, logicalPath, "CHG-9001")
	if err != nil {
		t.Fatalf("BuildChangeEvent: %v", err)
	}
	payload, err := ev.ToMap()
	if err != nil {
		t.Fatalf("ToMap: %v", err)
	}
	policies, err := policy.Load("./policies")
	if err != nil {
		t.Fatalf("load policies: %v", err)
	}

	report, err := evaluateEvent(context.Background(), policies, ev, payload)
	if err != nil {
		t.Fatalf("evaluateEvent error: %v", err)
	}
	return report.Failures
}

func TestStructuredJSONGitOpsPolicies(t *testing.T) {
	cases := []struct {
		name      string
		before    string
		after     string
		wantFails int
	}{
		{
			name:      "postgres create valid",
			after:     "./samples/postgres-create-valid.json",
			wantFails: 0,
		},
		{
			name:      "postgres create bad violates prod requirements",
			after:     "./samples/postgres-create-bad.json",
			wantFails: 1,
		},
		{
			name:      "postgres update bad fails allowlist, disk shrink, and backup floor",
			before:    "./samples/postgres-update-before.json",
			after:     "./samples/postgres-update-bad.json",
			wantFails: 3,
		},
		{
			name:      "postgres update good passes all rules",
			before:    "./samples/postgres-update-before.json",
			after:     "./samples/postgres-update-good.json",
			wantFails: 0,
		},
		{
			name:      "kafka update bad fails allowlist, partition shrink, and replication floor",
			before:    "./samples/kafka-before.json",
			after:     "./samples/kafka-bad.json",
			wantFails: 3,
		},
		{
			name:      "kafka update good passes all rules",
			before:    "./samples/kafka-before.json",
			after:     "./samples/kafka-good.json",
			wantFails: 0,
		},
		{
			name:      "kafka acls bad fails array-of-objects rule on index 1",
			before:    "./samples/kafka-before.json",
			after:     "./samples/kafka-acls-bad.json",
			wantFails: 1,
		},
		{
			name:      "aws secret bad fails plaintext check, rotation/kms, and allowlist",
			before:    "./samples/aws-secret-before.json",
			after:     "./samples/aws-secret-bad.json",
			wantFails: 3,
		},
		{
			name:      "aws secret good passes all rules",
			before:    "./samples/aws-secret-before.json",
			after:     "./samples/aws-secret-good.json",
			wantFails: 0,
		},
		{
			name:      "delete operation skips create and update rules cleanly",
			before:    "./samples/postgres-update-before.json",
			wantFails: 0,
		},
		{
			name:      "no-op update passes cleanly without null errors",
			before:    "./samples/postgres-update-before.json",
			after:     "./samples/postgres-update-before.json",
			wantFails: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := evalSample(t, tc.before, tc.after)
			if got != tc.wantFails {
				t.Fatalf("expected %d failures, got %d", tc.wantFails, got)
			}
		})
	}
}

func TestRemovedRequiredNumericFieldProducesCleanFailure(t *testing.T) {
	before := []byte(`{
		"kind": "PostgresDatabase",
		"metadata": {"name": "orders-db", "environment": "prod"},
		"spec": {"storageGB": 200, "backupRetentionDays": 14}
	}`)
	after := []byte(`{
		"kind": "PostgresDatabase",
		"metadata": {"name": "orders-db", "environment": "prod"},
		"spec": {"backupRetentionDays": 14}
	}`)

	ev, err := jsondiff.BuildChangeEvent(before, after, "infra/prod/orders-db.json", "CHG-1")
	if err != nil {
		t.Fatalf("BuildChangeEvent: %v", err)
	}
	payload, err := ev.ToMap()
	if err != nil {
		t.Fatalf("ToMap: %v", err)
	}
	policies, err := policy.Load("./policies")
	if err != nil {
		t.Fatalf("load policies: %v", err)
	}

	report, err := evaluateEvent(context.Background(), policies, ev, payload)
	if err != nil {
		t.Fatalf("expected clean failure rather than evaluation error, got: %v", err)
	}
	if report.Failures != 1 {
		t.Fatalf("expected 1 failure (postgres-no-disk-shrink), got %d (%+v)", report.Failures, report.Rules)
	}
}

func TestLoadFromGitAndDisk(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not available")
	}

	repo := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %s (%v)", args, string(out), err)
		}
	}

	runGit("init")
	runGit("config", "user.email", "ci@example.com")
	runGit("config", "user.name", "CI Bot")

	relPath := filepath.Join("infra", "prod", "orders-db.json")
	absPath := filepath.Join(repo, relPath)
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		t.Fatal(err)
	}
	beforeData, err := os.ReadFile("./samples/postgres-update-before.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(absPath, beforeData, 0o644); err != nil {
		t.Fatal(err)
	}
	runGit("add", ".")
	runGit("commit", "-m", "initial prod db")

	// Overwrite working tree file with invalid shrink/region change.
	badData, err := os.ReadFile("./samples/postgres-update-bad.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(absPath, badData, 0o644); err != nil {
		t.Fatal(err)
	}

	gotBefore, gotAfter, err := loadFromGitAndDisk(repo, "HEAD", relPath)
	if err != nil {
		t.Fatalf("loadFromGitAndDisk: %v", err)
	}
	ev, err := jsondiff.BuildChangeEvent(gotBefore, gotAfter, relPath, "")
	if err != nil {
		t.Fatalf("BuildChangeEvent: %v", err)
	}
	payload, err := ev.ToMap()
	if err != nil {
		t.Fatalf("ToMap: %v", err)
	}
	policies, err := policy.Load("./policies")
	if err != nil {
		t.Fatalf("load policies: %v", err)
	}
	report, err := evaluateEvent(context.Background(), policies, ev, payload)
	if err != nil {
		t.Fatalf("evaluateEvent: %v", err)
	}
	if report.Failures != 3 {
		t.Fatalf("expected 3 failures from git diff validation, got %d", report.Failures)
	}
}

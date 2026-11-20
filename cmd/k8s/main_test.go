package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kyverno-show/internal/kit"

	engineapi "github.com/kyverno/kyverno/pkg/engine/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func repoPath(parts ...string) string {
	return filepath.Join(append([]string{"..", ".."}, parts...)...)
}

func findResult(reports []resourceReport, policy string) (kit.Result, bool) {
	for _, rep := range reports {
		for _, r := range rep.Results {
			if r.Policy == policy {
				return r, true
			}
		}
	}
	return kit.Result{}, false
}

func TestKubernetesPolicies(t *testing.T) {
	bundle, err := kit.LoadPolicies(repoPath("k8s", "policies"))
	if err != nil {
		t.Fatalf("load policies: %v", err)
	}
	if len(bundle.Validating) != 4 || len(bundle.Mutating) != 1 {
		t.Fatalf("expected 4 validating + 1 mutating policies, got %d + %d", len(bundle.Validating), len(bundle.Mutating))
	}

	t.Run("bad deployment fails image, non-root, and audit labels with dynamic messages", func(t *testing.T) {
		res, err := kit.LoadUnstructured(repoPath("k8s", "manifests", "deployment-bad.yaml"))
		if err != nil {
			t.Fatalf("load bad deployment: %v", err)
		}
		reps, enforced, err := evaluateAll(context.Background(), bundle, res, nil, false, true)
		if err != nil {
			t.Fatalf("evaluateAll: %v", err)
		}
		if enforced != 2 {
			t.Fatalf("expected 2 enforced (Deny) failures, got %d (%+v)", enforced, reps)
		}

		imgRes, ok := findResult(reps, "disallow-mutable-image")
		if !ok || imgRes.Status != engineapi.RuleStatusFail {
			t.Fatalf("expected disallow-mutable-image failure, got %+v", imgRes)
		}
		if !strings.Contains(imgRes.Message, "web=nginx:latest") || !strings.Contains(imgRes.Message, "migrator=localhost:5000/migrator") {
			t.Fatalf("expected image message to name both offenders, got %q", imgRes.Message)
		}
		if imgRes.Trace == nil {
			t.Fatalf("expected non-nil decision trace when explain=true")
		}

		lblRes, ok := findResult(reps, "require-standard-labels")
		if !ok || lblRes.Status != engineapi.RuleStatusFail || lblRes.Enforced {
			t.Fatalf("expected non-enforced Audit failure for labels, got %+v", lblRes)
		}
	})

	t.Run("good deployment passes all CREATE policies", func(t *testing.T) {
		res, err := kit.LoadUnstructured(repoPath("k8s", "manifests", "deployment-good.yaml"))
		if err != nil {
			t.Fatalf("load good deployment: %v", err)
		}
		reps, enforced, err := evaluateAll(context.Background(), bundle, res, nil, false, false)
		if err != nil {
			t.Fatalf("evaluateAll: %v", err)
		}
		if enforced != 0 {
			t.Fatalf("expected 0 enforced failures, got %d", enforced)
		}
		for _, r := range reps[0].Results {
			if r.Status != engineapi.RuleStatusPass {
				t.Fatalf("expected PASS, got %+v", r)
			}
		}
	})

	t.Run("bad cronjob caught automatically via Pod-controller Autogen", func(t *testing.T) {
		res, err := kit.LoadUnstructured(repoPath("k8s", "manifests", "cronjob-bad.yaml"))
		if err != nil {
			t.Fatalf("load cronjob: %v", err)
		}
		reps, enforced, err := evaluateAll(context.Background(), bundle, res, nil, false, false)
		if err != nil {
			t.Fatalf("evaluateAll: %v", err)
		}
		if enforced != 2 {
			t.Fatalf("expected 2 autogen Deny failures on CronJob, got %d (%+v)", enforced, reps)
		}
	})

	t.Run("mutate-pod-defaults remediates require-non-root before validation", func(t *testing.T) {
		res, err := kit.LoadUnstructured(repoPath("k8s", "manifests", "deployment-bad.yaml"))
		if err != nil {
			t.Fatalf("load bad deployment: %v", err)
		}
		reps, enforced, err := evaluateAll(context.Background(), bundle, res, nil, true, false)
		if err != nil {
			t.Fatalf("evaluateAll with mutate: %v", err)
		}
		if enforced != 1 {
			t.Fatalf("expected 1 remaining Deny failure (disallow-mutable-image), got %d (%+v)", enforced, reps)
		}
		nonRoot, ok := findResult(reps, "require-non-root")
		if !ok || nonRoot.Status != engineapi.RuleStatusPass {
			t.Fatalf("expected require-non-root to PASS after mutation, got %+v", nonRoot)
		}
	})

	t.Run("policy exception granted, refused, and expired behavior", func(t *testing.T) {
		exBundle, err := kit.LoadPolicies(repoPath("k8s", "policies"), repoPath("k8s", "exceptions", "legacy-waiver.yaml"))
		if err != nil {
			t.Fatalf("load policies + exceptions: %v", err)
		}

		validManifest, err := kit.LoadUnstructured(repoPath("k8s", "manifests", "deployment-waiver-valid.yaml"))
		if err != nil {
			t.Fatalf("load waiver-valid: %v", err)
		}
		reps, enforced, err := evaluateAll(context.Background(), exBundle, validManifest, nil, false, false)
		if err != nil {
			t.Fatalf("evaluateAll waiver-valid: %v", err)
		}
		if enforced != 0 {
			t.Fatalf("expected 0 enforced failures with valid waiver, got %d (%+v)", enforced, reps)
		}
		nonRoot, _ := findResult(reps, "require-non-root")
		if nonRoot.Status != engineapi.RuleStatusSkip || nonRoot.Rule != "exception" {
			t.Fatalf("expected require-non-root to skip via exception, got %+v", nonRoot)
		}

		refusedManifest, err := kit.LoadUnstructured(repoPath("k8s", "manifests", "deployment-waiver-refused.yaml"))
		if err != nil {
			t.Fatalf("load waiver-refused: %v", err)
		}
		reps, enforced, err = evaluateAll(context.Background(), exBundle, refusedManifest, nil, false, false)
		if err != nil {
			t.Fatalf("evaluateAll waiver-refused: %v", err)
		}
		if enforced != 1 {
			t.Fatalf("expected 1 enforced failure on refused waiver, got %d", enforced)
		}
		nonRoot, _ = findResult(reps, "require-non-root")
		if nonRoot.Status != engineapi.RuleStatusFail || !strings.Contains(nonRoot.Message, "security.acme.io/waiver=SEC-####") {
			t.Fatalf("expected compensating control refusal message, got %+v", nonRoot)
		}

		expiredCopy := exBundle
		expiredEx := exBundle.Exceptions[0].DeepCopy()
		expiredEx.Spec.ExpiresAt = &metav1.Time{Time: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)}
		expiredCopy.Exceptions = append(expiredCopy.Exceptions[:0:0], expiredEx)
		reps, enforced, err = evaluateAll(context.Background(), expiredCopy, validManifest, nil, false, false)
		if err != nil {
			t.Fatalf("evaluateAll expired waiver: %v", err)
		}
		if enforced != 1 {
			t.Fatalf("expected 1 enforced failure when exception is expired, got %d", enforced)
		}
		nonRoot, _ = findResult(reps, "require-non-root")
		if !strings.Contains(nonRoot.Message, "runAsNonRoot=true") {
			t.Fatalf("expected standard require-non-root message when exception expired, got %q", nonRoot.Message)
		}
	})

	t.Run("UPDATE forbids scaling production deployment to zero replicas", func(t *testing.T) {
		oldRes, err := kit.LoadUnstructured(repoPath("k8s", "manifests", "deployment-good.yaml"))
		if err != nil {
			t.Fatalf("load old manifest: %v", err)
		}
		newRes, err := kit.LoadUnstructured(repoPath("k8s", "manifests", "deployment-scale-zero.yaml"))
		if err != nil {
			t.Fatalf("load scale-zero manifest: %v", err)
		}
		reps, enforced, err := evaluateAll(context.Background(), bundle, newRes, []unstructured.Unstructured{oldRes[0]}, false, false)
		if err != nil {
			t.Fatalf("evaluateAll UPDATE: %v", err)
		}
		if enforced != 1 {
			t.Fatalf("expected 1 enforced failure on scale-to-zero UPDATE, got %d (%+v)", enforced, reps)
		}
		scaleRes, ok := findResult(reps, "forbid-prod-scale-to-zero")
		if !ok || scaleRes.Status != engineapi.RuleStatusFail || !strings.Contains(scaleRes.Message, "from 2 to 0") {
			t.Fatalf("expected scale-to-zero message 'from 2 to 0', got %+v", scaleRes)
		}
	})
}

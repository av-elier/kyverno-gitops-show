package diffparse

import (
	"testing"
)

func TestParseUnifiedDiff(t *testing.T) {
	raw := `diff --git a/environments/prod/app/deploy.yaml b/environments/prod/app/deploy.yaml
--- a/environments/prod/app/deploy.yaml
+++ b/environments/prod/app/deploy.yaml
@@ -1,3 +1,3 @@
 spec:
-  replicas: 2
+  replicas: 0
diff --git a/environments/staging/app/config.yaml b/environments/staging/app/config.yaml
--- a/environments/staging/app/config.yaml
+++ b/environments/staging/app/config.yaml
@@ -1,2 +1,3 @@
 featureFlags:
+  beta: true
`
	report := Parse(raw, Metadata{
		Author:        "alice",
		Branch:        "feat/test",
		CommitMessage: "deploy fix JIRA-901",
	})

	if report.Metadata.ChangeTicket != "JIRA-901" {
		t.Fatalf("expected auto-extracted ticket JIRA-901, got %q", report.Metadata.ChangeTicket)
	}
	if report.Summary.TotalFiles != 2 {
		t.Fatalf("expected 2 files, got %d", report.Summary.TotalFiles)
	}
	if !report.Summary.HasProdChanges {
		t.Fatalf("expected HasProdChanges=true")
	}
	if report.Summary.TotalAdded != 2 || report.Summary.TotalRemoved != 1 {
		t.Fatalf("unexpected counts: added=%d removed=%d", report.Summary.TotalAdded, report.Summary.TotalRemoved)
	}
	if report.Files[0].Environment != "prod" || report.Files[1].Environment != "staging" {
		t.Fatalf("unexpected environments: %q, %q", report.Files[0].Environment, report.Files[1].Environment)
	}
}

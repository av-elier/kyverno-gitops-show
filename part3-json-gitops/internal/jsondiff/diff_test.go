package jsondiff

import (
	"reflect"
	"testing"
)

func TestComputeDiffAndBuildEvent(t *testing.T) {
	before := []byte(`{
		"kind": "PostgresDatabase",
		"metadata": {"name": "orders-db", "environment": "prod", "labels": {"team": "checkout"}},
		"spec": {"storageGB": 200, "region": "eu-central-1", "allowedCidrs": ["10.0.0.0/16"]}
	}`)
	after := []byte(`{
		"kind": "PostgresDatabase",
		"metadata": {"name": "orders-db", "environment": "prod", "labels": {"team": "checkout", "tier": "critical"}},
		"spec": {"storageGB": 100, "region": "eu-central-1", "allowedCidrs": ["10.0.0.0/16", "10.1.0.0/16"]}
	}`)

	ev, err := BuildChangeEvent(before, after, `infra\prod\orders-db.json`, "CHG-100")
	if err != nil {
		t.Fatalf("BuildChangeEvent error: %v", err)
	}
	if ev.Operation != OpUpdate {
		t.Fatalf("expected operation update, got %s", ev.Operation)
	}
	if ev.ResourcePath != "infra/prod/orders-db.json" {
		t.Fatalf("expected normalized slash path, got %q", ev.ResourcePath)
	}
	if ev.Kind != "PostgresDatabase" || ev.Environment != "prod" {
		t.Fatalf("unexpected metadata: kind=%s env=%s", ev.Kind, ev.Environment)
	}

	wantPaths := []string{"/metadata/labels/tier", "/spec/allowedCidrs/1", "/spec/storageGB"}
	if !reflect.DeepEqual(ev.Diff.ChangedPaths, wantPaths) {
		t.Fatalf("expected changedPaths=%v, got %v", wantPaths, ev.Diff.ChangedPaths)
	}

	// Verify nested object fields inside arrays emit deep JSON Pointer paths.
	aclBefore := []byte(`{"spec":{"acls":[{"principal":"User:a","operation":"READ"}]}}`)
	aclAfter := []byte(`{"spec":{"acls":[{"principal":"User:a","operation":"WRITE"}]}}`)
	aclEv, err := BuildChangeEvent(aclBefore, aclAfter, "infra/prod/topic.json", "")
	if err != nil {
		t.Fatalf("BuildChangeEvent acl error: %v", err)
	}
	if !reflect.DeepEqual(aclEv.Diff.ChangedPaths, []string{"/spec/acls/0/operation"}) {
		t.Fatalf("expected /spec/acls/0/operation, got %v", aclEv.Diff.ChangedPaths)
	}

	createEv, err := BuildChangeEvent(nil, after, "infra/prod/orders-db.json", "")
	if err != nil {
		t.Fatalf("BuildChangeEvent create error: %v", err)
	}
	if createEv.Operation != OpCreate {
		t.Fatalf("expected operation create, got %s", createEv.Operation)
	}

	deleteEv, err := BuildChangeEvent(before, nil, "infra/prod/orders-db.json", "")
	if err != nil {
		t.Fatalf("BuildChangeEvent delete error: %v", err)
	}
	if deleteEv.Operation != OpDelete {
		t.Fatalf("expected operation delete, got %s", deleteEv.Operation)
	}
}

func TestNoOpDiffProducesEmptySliceNotNull(t *testing.T) {
	doc := []byte(`{"kind":"KafkaTopic","spec":{"partitions":12}}`)
	ev, err := BuildChangeEvent(doc, doc, "infra/prod/topic.json", "")
	if err != nil {
		t.Fatalf("BuildChangeEvent error: %v", err)
	}
	if ev.Diff.TotalChanges != 0 || ev.Diff.Changes == nil {
		t.Fatalf("expected non-nil empty changes slice, got %+v", ev.Diff)
	}
	m, err := ev.ToMap()
	if err != nil {
		t.Fatalf("ToMap: %v", err)
	}
	diffMap := m["diff"].(map[string]any)
	if _, ok := diffMap["changes"].([]any); !ok {
		t.Fatalf("expected JSON array for diff.changes, got %T", diffMap["changes"])
	}
}

package jsondiff

import (
	"reflect"
	"testing"
)

func buildBytes(t *testing.T, beforeRaw, afterRaw []byte, path, ticket string) (ChangeEvent, error) {
	t.Helper()
	b, err := Parse(beforeRaw)
	if err != nil {
		return ChangeEvent{}, err
	}
	a, err := Parse(afterRaw)
	if err != nil {
		return ChangeEvent{}, err
	}
	return Build(b, a, path, ticket)
}

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

	ev, err := buildBytes(t, before, after, `infra\prod\orders-db.json`, "CHG-100")
	if err != nil {
		t.Fatalf("buildBytes error: %v", err)
	}
	if ev.Operation != OpUpdate || ev.ResourcePath != "infra/prod/orders-db.json" || ev.Kind != "PostgresDatabase" || ev.Environment != "prod" {
		t.Fatalf("unexpected event metadata: %+v", ev)
	}

	wantPaths := []string{"/metadata/labels/tier", "/spec/allowedCidrs/1", "/spec/storageGB"}
	if !reflect.DeepEqual(ev.Diff.ChangedPaths, wantPaths) {
		t.Fatalf("expected changedPaths=%v, got %v", wantPaths, ev.Diff.ChangedPaths)
	}

	aclEv, err := buildBytes(t, []byte(`{"spec":{"acls":[{"principal":"User:a","operation":"READ"}]}}`), []byte(`{"spec":{"acls":[{"principal":"User:a","operation":"WRITE"}]}}`), "infra/prod/topic.json", "")
	if err != nil || !reflect.DeepEqual(aclEv.Diff.ChangedPaths, []string{"/spec/acls/0/operation"}) {
		t.Fatalf("expected /spec/acls/0/operation, got %v (err=%v)", aclEv.Diff.ChangedPaths, err)
	}

	if createEv, err := buildBytes(t, nil, after, "infra/prod/orders-db.json", ""); err != nil || createEv.Operation != OpCreate {
		t.Fatalf("expected create, got %s (err=%v)", createEv.Operation, err)
	}
	if deleteEv, err := buildBytes(t, before, nil, "infra/prod/orders-db.json", ""); err != nil || deleteEv.Operation != OpDelete {
		t.Fatalf("expected delete, got %s (err=%v)", deleteEv.Operation, err)
	}
}

func TestYAMLDocumentsProduceIdenticalChangeEvent(t *testing.T) {
	beforeYAML := []byte("kind: PostgresDatabase\nmetadata:\n  name: orders-db\nspec:\n  storageGB: 200\n  region: eu-central-1\n")
	afterYAML := []byte("kind: PostgresDatabase\nmetadata:\n  name: orders-db\nspec:\n  storageGB: 500\n  region: eu-central-1\n")

	ev, err := buildBytes(t, beforeYAML, afterYAML, "infra/prod/orders-db.yaml", "CHG-202")
	if err != nil {
		t.Fatalf("buildBytes YAML error: %v", err)
	}
	if ev.Operation != OpUpdate || ev.Environment != "prod" || ev.Kind != "PostgresDatabase" || !reflect.DeepEqual(ev.Diff.ChangedPaths, []string{"/spec/storageGB"}) {
		t.Fatalf("unexpected YAML event: %+v", ev)
	}
}

func TestNoOpDiffProducesEmptySliceNotNull(t *testing.T) {
	doc := []byte(`{"kind":"KafkaTopic","spec":{"partitions":12}}`)
	ev, err := buildBytes(t, doc, doc, "infra/prod/topic.json", "")
	if err != nil {
		t.Fatalf("buildBytes error: %v", err)
	}
	if ev.Diff.TotalChanges != 0 || ev.Diff.Changes == nil {
		t.Fatalf("expected non-nil empty changes slice, got %+v", ev.Diff)
	}
	m, err := ev.ToMap()
	if err != nil {
		t.Fatalf("ToMap: %v", err)
	}
	if _, ok := m["diff"].(map[string]any)["changes"].([]any); !ok {
		t.Fatalf("expected JSON array for diff.changes")
	}
}

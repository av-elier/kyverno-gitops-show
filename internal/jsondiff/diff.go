package jsondiff

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

	"sigs.k8s.io/yaml"
)

// Operation describes the lifecycle transition of a resource file.
type Operation string

const (
	OpCreate Operation = "create"
	OpUpdate Operation = "update"
	OpDelete Operation = "delete"
)

// FieldChange represents one leaf-level RFC 6902 JSON Pointer change.
type FieldChange struct {
	Op     string `json:"op"`
	Path   string `json:"path"`
	Before any    `json:"before,omitempty"`
	After  any    `json:"after,omitempty"`
}

// DiffSummary holds all structured changes between before and after states.
type DiffSummary struct {
	ChangedPaths []string      `json:"changedPaths"`
	Changes      []FieldChange `json:"changes"`
	TotalChanges int           `json:"totalChanges"`
}

// ChangeEvent is the structured payload evaluated by CEL ValidatingPolicy rules (evaluation.mode: JSON).
type ChangeEvent struct {
	Operation    Operation      `json:"operation"`
	ResourcePath string         `json:"resourcePath"`
	Environment  string         `json:"environment"`
	Kind         string         `json:"kind"`
	ChangeTicket string         `json:"changeTicket"`
	Before       map[string]any `json:"before,omitempty"`
	After        map[string]any `json:"after,omitempty"`
	Diff         DiffSummary    `json:"diff"`
}

// Parse unmarshals JSON or YAML bytes into a generic map (nil for empty input).
func Parse(raw []byte) (map[string]any, error) {
	if strings.TrimSpace(string(raw)) == "" {
		return nil, nil
	}
	var m map[string]any
	return m, yaml.Unmarshal(raw, &m)
}

// Build constructs a ChangeEvent from parsed before/after maps.
func Build(before, after map[string]any, path, ticket string) (ChangeEvent, error) {
	if before == nil && after == nil {
		return ChangeEvent{}, fmt.Errorf("at least one of before or after document must be provided")
	}
	op := OpUpdate
	if before == nil {
		op = OpCreate
	} else if after == nil {
		op = OpDelete
	}
	changes := Compute(before, after)
	paths := make([]string, len(changes))
	for i, c := range changes {
		paths[i] = c.Path
	}
	return ChangeEvent{
		Operation: op, ResourcePath: strings.ReplaceAll(path, "\\", "/"),
		Environment:  first(strAt(after, "metadata", "environment"), strAt(before, "metadata", "environment"), detectEnv(path)),
		Kind:         first(strAt(after, "kind"), strAt(before, "kind")),
		ChangeTicket: ticket, Before: before, After: after,
		Diff: DiffSummary{ChangedPaths: paths, Changes: changes, TotalChanges: len(changes)},
	}, nil
}

// Compute walks two JSON/YAML values recursively and emits leaf-level FieldChanges.
func Compute(before, after any) []FieldChange {
	out := []FieldChange{}
	diff("", before, after, &out)
	return out
}

func diff(path string, before, after any, out *[]FieldChange) {
	if before == nil && after == nil {
		return
	}
	if before == nil {
		*out = append(*out, FieldChange{Op: "add", Path: ptrOrRoot(path), After: after})
		return
	}
	if after == nil {
		*out = append(*out, FieldChange{Op: "remove", Path: ptrOrRoot(path), Before: before})
		return
	}
	if bMap, ok := before.(map[string]any); ok {
		if aMap, ok := after.(map[string]any); ok {
			for _, k := range sortedKeys(bMap, aMap) {
				cp := path + "/" + strings.NewReplacer("~", "~0", "/", "~1").Replace(k)
				bVal, bOk := bMap[k]
				aVal, aOk := aMap[k]
				if !bOk {
					*out = append(*out, FieldChange{Op: "add", Path: cp, After: aVal})
				} else if !aOk {
					*out = append(*out, FieldChange{Op: "remove", Path: cp, Before: bVal})
				} else {
					diff(cp, bVal, aVal, out)
				}
			}
			return
		}
	}
	if bSlice, ok := before.([]any); ok {
		if aSlice, ok := after.([]any); ok {
			n := min(len(bSlice), len(aSlice))
			for i := range n {
				diff(fmt.Sprintf("%s/%d", path, i), bSlice[i], aSlice[i], out)
			}
			for i := n; i < len(aSlice); i++ {
				*out = append(*out, FieldChange{Op: "add", Path: fmt.Sprintf("%s/%d", path, i), After: aSlice[i]})
			}
			for i := n; i < len(bSlice); i++ {
				*out = append(*out, FieldChange{Op: "remove", Path: fmt.Sprintf("%s/%d", path, i), Before: bSlice[i]})
			}
			return
		}
	}
	if !equalVal(before, after) {
		*out = append(*out, FieldChange{Op: "replace", Path: ptrOrRoot(path), Before: before, After: after})
	}
}

// ToMap converts ChangeEvent to generic JSON structures (map[string]any / []any).
func (e ChangeEvent) ToMap() (map[string]any, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	return m, json.Unmarshal(b, &m)
}

func equalVal(a, b any) bool {
	if fa, okA := asFloat(a); okA {
		if fb, okB := asFloat(b); okB {
			return fa == fb
		}
	}
	return reflect.DeepEqual(a, b)
}

func asFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

func sortedKeys(a, b map[string]any) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		seen[k] = struct{}{}
	}
	for k := range b {
		seen[k] = struct{}{}
	}
	return slices.Sorted(maps.Keys(seen))
}

func ptrOrRoot(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

func strAt(m map[string]any, keys ...string) string {
	cur := any(m)
	for _, k := range keys {
		obj, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = obj[k]
	}
	s, _ := cur.(string)
	return s
}

func first(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func detectEnv(path string) string {
	lower := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	for _, env := range []string{"prod", "staging", "dev"} {
		if strings.Contains(lower, "/"+env+"/") || strings.HasPrefix(lower, env+"/") {
			return env
		}
	}
	return "unknown"
}

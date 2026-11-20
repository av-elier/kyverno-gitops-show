package jsondiff

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Operation describes the lifecycle transition of a resource file.
type Operation string

const (
	OpCreate Operation = "create"
	OpUpdate Operation = "update"
	OpDelete Operation = "delete"
)

// FieldChange represents a single structured JSON change in RFC 6902 JSON Pointer style.
type FieldChange struct {
	Op     string `json:"op"` // "add", "remove", "replace"
	Path   string `json:"path"`
	Before any    `json:"before,omitempty"`
	After  any    `json:"after,omitempty"`
}

// DiffSummary holds all structured changes computed between before and after JSON states.
type DiffSummary struct {
	ChangedPaths []string      `json:"changedPaths"`
	Changes      []FieldChange `json:"changes"`
	TotalChanges int           `json:"totalChanges"`
}

// ChangeEvent is the structured payload evaluated by CEL ValidatingPolicy rules (evaluation.mode: JSON).
// Instead of running regexes on raw diff lines, policies inspect typed before/after state
// and RFC 6902-style JSON Pointer paths.
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

// BuildChangeEvent parses optional before/after JSON documents and computes a structured ChangeEvent.
func BuildChangeEvent(beforeRaw, afterRaw []byte, resourcePath, changeTicket string) (ChangeEvent, error) {
	before, err := unmarshalJSONMap(beforeRaw)
	if err != nil {
		return ChangeEvent{}, fmt.Errorf("parse before JSON: %w", err)
	}
	after, err := unmarshalJSONMap(afterRaw)
	if err != nil {
		return ChangeEvent{}, fmt.Errorf("parse after JSON: %w", err)
	}
	if before == nil && after == nil {
		return ChangeEvent{}, fmt.Errorf("at least one of before or after JSON must be provided")
	}

	op := OpUpdate
	if before == nil {
		op = OpCreate
	} else if after == nil {
		op = OpDelete
	}

	changes := ComputeDiff(before, after)
	paths := make([]string, 0, len(changes))
	for _, c := range changes {
		paths = append(paths, c.Path)
	}

	kind := extractString(after, "kind")
	if kind == "" {
		kind = extractString(before, "kind")
	}

	env := extractNestedString(after, "metadata", "environment")
	if env == "" {
		env = extractNestedString(before, "metadata", "environment")
	}
	if env == "" {
		env = detectEnvironment(resourcePath)
	}

	return ChangeEvent{
		Operation:    op,
		ResourcePath: normalizeRepoPath(resourcePath),
		Environment:  env,
		Kind:         kind,
		ChangeTicket: changeTicket,
		Before:       before,
		After:        after,
		Diff: DiffSummary{
			ChangedPaths: paths,
			Changes:      changes,
			TotalChanges: len(changes),
		},
	}, nil
}

// ComputeDiff walks two JSON values recursively and emits leaf-level FieldChange records
// using RFC 6901/6902 JSON Pointer paths (e.g. "/spec/storageGB").
//
// Maps are compared recursively by sorted keys. Arrays are compared positionally
// ("/field/0", "/field/1", ...), which keeps path semantics simple and deterministic
// without requiring schema-specific identity keys.
func ComputeDiff(before, after any) []FieldChange {
	out := []FieldChange{}
	diffRecursive("", before, after, &out)
	return out
}

func diffRecursive(path string, before, after any, out *[]FieldChange) {
	if before == nil && after == nil {
		return
	}
	if before == nil {
		*out = append(*out, FieldChange{Op: "add", Path: pointerOrRoot(path), After: after})
		return
	}
	if after == nil {
		*out = append(*out, FieldChange{Op: "remove", Path: pointerOrRoot(path), Before: before})
		return
	}

	if bMap, ok := before.(map[string]any); ok {
		if aMap, ok := after.(map[string]any); ok {
			for _, k := range mergedSortedKeys(bMap, aMap) {
				childPath := path + "/" + escapePointerToken(k)
				bVal, bOk := bMap[k]
				aVal, aOk := aMap[k]
				switch {
				case !bOk:
					*out = append(*out, FieldChange{Op: "add", Path: childPath, After: aVal})
				case !aOk:
					*out = append(*out, FieldChange{Op: "remove", Path: childPath, Before: bVal})
				default:
					diffRecursive(childPath, bVal, aVal, out)
				}
			}
			return
		}
	}

	if bSlice, ok := before.([]any); ok {
		if aSlice, ok := after.([]any); ok {
			minLen := len(bSlice)
			if len(aSlice) < minLen {
				minLen = len(aSlice)
			}
			for i := 0; i < minLen; i++ {
				diffRecursive(fmt.Sprintf("%s/%d", path, i), bSlice[i], aSlice[i], out)
			}
			for i := minLen; i < len(aSlice); i++ {
				*out = append(*out, FieldChange{Op: "add", Path: fmt.Sprintf("%s/%d", path, i), After: aSlice[i]})
			}
			for i := minLen; i < len(bSlice); i++ {
				*out = append(*out, FieldChange{Op: "remove", Path: fmt.Sprintf("%s/%d", path, i), Before: bSlice[i]})
			}
			return
		}
	}

	if !reflect.DeepEqual(before, after) {
		*out = append(*out, FieldChange{
			Op:     "replace",
			Path:   pointerOrRoot(path),
			Before: before,
			After:  after,
		})
	}
}

// ToMap converts ChangeEvent to generic JSON structures (map[string]any / []any).
func (e ChangeEvent) ToMap() (map[string]any, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func unmarshalJSONMap(raw []byte) (map[string]any, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(trimmed), &m); err != nil {
		return nil, err
	}
	return m, nil
}

func mergedSortedKeys(a, b map[string]any) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		seen[k] = struct{}{}
	}
	for k := range b {
		seen[k] = struct{}{}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func escapePointerToken(token string) string {
	token = strings.ReplaceAll(token, "~", "~0")
	return strings.ReplaceAll(token, "/", "~1")
}

func pointerOrRoot(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func normalizeRepoPath(path string) string {
	return strings.ReplaceAll(path, "\\", "/")
}

func extractString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, _ := m[key].(string)
	return v
}

func extractNestedString(m map[string]any, k1, k2 string) string {
	if m == nil {
		return ""
	}
	sub, ok := m[k1].(map[string]any)
	if !ok {
		return ""
	}
	v, _ := sub[k2].(string)
	return v
}

func detectEnvironment(path string) string {
	lower := strings.ToLower(normalizeRepoPath(path))
	switch {
	case strings.Contains(lower, "/prod/") || strings.HasPrefix(lower, "prod/"):
		return "prod"
	case strings.Contains(lower, "/staging/") || strings.HasPrefix(lower, "staging/"):
		return "staging"
	case strings.Contains(lower, "/dev/") || strings.HasPrefix(lower, "dev/"):
		return "dev"
	default:
		return "unknown"
	}
}

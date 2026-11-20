package kit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	policiesv1beta1 "github.com/kyverno/api/api/policies.kyverno.io/v1beta1"
	celengine "github.com/kyverno/kyverno/pkg/cel/engine"
	"github.com/kyverno/kyverno/pkg/cel/matching"
	mpolcompiler "github.com/kyverno/kyverno/pkg/cel/policies/mpol/compiler"
	mpolengine "github.com/kyverno/kyverno/pkg/cel/policies/mpol/engine"
	vpolcompiler "github.com/kyverno/kyverno/pkg/cel/policies/vpol/compiler"
	vpolengine "github.com/kyverno/kyverno/pkg/cel/policies/vpol/engine"
	"github.com/kyverno/kyverno/pkg/cel/trace"
	engineapi "github.com/kyverno/kyverno/pkg/engine/api"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/managedfields"
	"k8s.io/apimachinery/pkg/util/sets"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"
)

// PolicyBundle holds Kyverno v1.20 CEL policies and exceptions loaded from YAML/JSON files.
type PolicyBundle struct {
	Validating []policiesv1beta1.ValidatingPolicyLike
	Mutating   []policiesv1beta1.MutatingPolicyLike
	Exceptions []*policiesv1beta1.PolicyException
}

// Result captures one rule outcome across Kyverno vpol, mpol, or the mini CEL engine.
type Result struct {
	Policy, Rule, Actions, Message string
	Enforced                       bool
	Status                         engineapi.RuleStatus
	Trace                          *trace.Decision
	MiniTrace                      []string
}

type deducedTCM struct{}

func (deducedTCM) GetTypeConverter(schema.GroupVersionKind) managedfields.TypeConverter {
	return managedfields.NewDeducedTypeConverter()
}

func noopNs(string) *corev1.Namespace { return nil }

// LoadPolicies loads ValidatingPolicy, MutatingPolicy, and PolicyException documents from files or dirs.
func LoadPolicies(paths ...string) (PolicyBundle, error) {
	var b PolicyBundle
	return b, walkDocs(paths, func(p string, raw []byte) error {
		var meta metav1.TypeMeta
		if err := yaml.Unmarshal(raw, &meta); err != nil {
			return fmt.Errorf("parse %s: %w", p, err)
		}
		switch meta.Kind {
		case "ValidatingPolicy":
			return appendDoc[policiesv1beta1.ValidatingPolicy](&b.Validating, p, raw)
		case "MutatingPolicy":
			return appendDoc[policiesv1beta1.MutatingPolicy](&b.Mutating, p, raw)
		case "PolicyException":
			return appendDoc[policiesv1beta1.PolicyException](&b.Exceptions, p, raw)
		}
		return nil
	})
}

// LoadUnstructured reads Kubernetes YAML/JSON manifests from a file or directory.
func LoadUnstructured(root string) ([]unstructured.Unstructured, error) {
	var out []unstructured.Unstructured
	return out, walkDocs([]string{root}, func(p string, raw []byte) error {
		var obj map[string]any
		if err := yaml.Unmarshal(raw, &obj); err != nil {
			return fmt.Errorf("parse %s: %w", p, err)
		}
		if len(obj) > 0 {
			out = append(out, unstructured.Unstructured{Object: obj})
		}
		return nil
	})
}

// K8sRequest builds a Kubernetes admission request for Kyverno CEL engines.
func K8sRequest(res, oldRes *unstructured.Unstructured, op admissionv1.Operation) celengine.EngineRequest {
	gvk := res.GroupVersionKind()
	gvr, _ := apimeta.UnsafeGuessKindToResource(gvk)
	var oldObj runtime.Object
	if oldRes != nil {
		oldObj = oldRes.DeepCopy()
	}
	return celengine.Request(nil, gvk, gvr, "", res.GetName(), res.GetNamespace(), op, authenticationv1.UserInfo{}, res.DeepCopy(), oldObj, false, nil)
}

// JSONRequest builds a JSON-mode evaluation request for Kyverno CEL engines.
func JSONRequest(payload map[string]any) celengine.EngineRequest {
	return celengine.RequestFromJSON(nil, &unstructured.Unstructured{Object: payload})
}

// Mutate runs MutatingPolicies (Kubernetes or JSON mode) and returns the patched object and results.
func Mutate(ctx context.Context, b PolicyBundle, req celengine.EngineRequest, fallback *unstructured.Unstructured, explain bool) (*unstructured.Unstructured, []Result, error) {
	if len(b.Mutating) == 0 {
		return fallback, nil, nil
	}
	provider, err := mpolengine.NewProvider(mpolcompiler.NewCompilerWithTrace(explain), b.Mutating, activeExceptions(b.Exceptions), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("compile mutating policies: %w", err)
	}
	resp, err := mpolengine.NewEngine(provider, noopNs, matcherFor(req), deducedTCM{}, nil).Handle(ctx, req, nil)
	if err != nil {
		return nil, nil, err
	}
	var results []Result
	for _, pol := range resp.Policies {
		if results, _, _, err = collectRules(results, 0, 0, pol.Policy.GetName(), "Mutate", false, "mutation", pol.Rules, pol.Trace); err != nil {
			return nil, results, err
		}
	}
	if resp.PatchedResource != nil {
		return resp.PatchedResource, results, nil
	}
	return fallback, results, nil
}

// Validate runs ValidatingPolicies (Kubernetes with Autogen or JSON mode) with active PolicyExceptions.
func Validate(ctx context.Context, b PolicyBundle, req celengine.EngineRequest, explain bool) ([]Result, int, int, error) {
	provider, err := vpolengine.NewProvider(vpolcompiler.NewCompilerWithTrace(explain), b.Validating, activeExceptions(b.Exceptions))
	if err != nil {
		return nil, 0, 0, fmt.Errorf("compile validating policies: %w", err)
	}
	resp, err := vpolengine.NewEngine(provider, noopNs, matcherFor(req)).Handle(ctx, req, nil)
	if err != nil {
		return nil, 0, 0, err
	}
	var results []Result
	var enforced, warnings int
	for _, pol := range resp.Policies {
		results, enforced, warnings, err = collectRules(
			results, enforced, warnings, pol.Policy.GetName(), formatActions(pol.Actions),
			pol.Actions.Has(admissionregistrationv1.Deny), "validation", pol.Rules, pol.Trace,
		)
		if err != nil {
			return nil, enforced, warnings, err
		}
	}
	return results, enforced, warnings, nil
}

// PrintResults writes rule results, messages, and optional traces to w.
func PrintResults(w io.Writer, target string, results []Result, explain bool) {
	var traces []*trace.Decision
	for _, r := range results {
		if r.Status == engineapi.RuleStatusSkip && r.Rule != "exception" {
			continue
		}
		fmt.Fprintf(w, "[%s] policy=%s action=%s target=%s rule=%s\n", strings.ToUpper(string(r.Status)), r.Policy, r.Actions, target, r.Rule)
		if r.Message != "" && (r.Status != engineapi.RuleStatusPass || r.Rule == "exception") {
			fmt.Fprintf(w, "       message: %s\n", r.Message)
		}
		if explain {
			for _, line := range r.MiniTrace {
				fmt.Fprintf(w, "       trace: %s\n", line)
			}
			if r.Trace != nil {
				traces = append(traces, r.Trace)
			}
		}
	}
	for i, tr := range traces {
		fmt.Fprintln(w, map[bool]string{true: "\n=== Decision Traces ===", false: "---"}[i == 0])
		trace.Render(w, tr)
	}
}

func collectRules(dst []Result, enf, wrn int, policy, actions string, isDeny bool, defRule string, rules []engineapi.RuleResponse, tr *trace.Decision) ([]Result, int, int, error) {
	for i, rr := range rules {
		rule := rr.Name()
		if rule == "" {
			rule = defRule
		}
		if rr.Status() == engineapi.RuleStatusError {
			return dst, enf, wrn, fmt.Errorf("policy %s rule %s error: %s", policy, rule, rr.Message())
		}
		if rr.Status() == engineapi.RuleStatusFail {
			if isDeny {
				enf++
			} else {
				wrn++
			}
		}
		var ruleTrace *trace.Decision
		if i == 0 {
			ruleTrace = tr
		}
		dst = append(dst, Result{Policy: policy, Rule: rule, Actions: actions, Enforced: isDeny, Status: rr.Status(), Message: rr.Message(), Trace: ruleTrace})
	}
	return dst, enf, wrn, nil
}

func activeExceptions(all []*policiesv1beta1.PolicyException) (active []*policiesv1beta1.PolicyException) {
	for _, ex := range all {
		if !ex.IsExpired() {
			active = append(active, ex)
		}
	}
	return active
}

func matcherFor(req celengine.EngineRequest) matching.Matcher {
	if req.JsonPayload != nil {
		return nil
	}
	return matching.NewMatcher()
}

func formatActions(actions sets.Set[admissionregistrationv1.ValidationAction]) string {
	if actions.Len() == 0 {
		return string(admissionregistrationv1.Audit)
	}
	out := make([]string, 0, actions.Len())
	for _, a := range sets.List(actions) {
		out = append(out, string(a))
	}
	return strings.Join(out, ",")
}

func appendDoc[T any, L any](dst *[]L, path string, raw []byte) error {
	var v T
	if err := yaml.Unmarshal(raw, &v); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	*dst = append(*dst, any(&v).(L))
	return nil
}

func walkDocs(roots []string, fn func(path string, raw []byte) error) error {
	for _, root := range roots {
		if root == "" {
			continue
		}
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil || d.IsDir() {
				return walkErr
			}
			ext := strings.ToLower(filepath.Ext(p))
			if p != root && ext != ".yaml" && ext != ".yml" && ext != ".json" {
				return nil
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			dec := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
			for {
				var raw json.RawMessage
				if err := dec.Decode(&raw); errors.Is(err, io.EOF) {
					return nil
				} else if err != nil {
					return fmt.Errorf("decode %s: %w", p, err)
				}
				if t := bytes.TrimSpace(raw); len(t) > 0 && !bytes.Equal(t, []byte("null")) {
					if err := fn(p, t); err != nil {
						return err
					}
				}
			}
		})
		if err != nil {
			return err
		}
	}
	return nil
}

package firstprinciples

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	policiesv1beta1 "github.com/kyverno/api/api/policies.kyverno.io/v1beta1"
)

// RuleStatus represents the outcome of evaluating a single ValidatingPolicy.
type RuleStatus string

const (
	StatusPass RuleStatus = "pass"
	StatusFail RuleStatus = "fail"
	StatusSkip RuleStatus = "skip"
)

// RuleOutcome captures the evaluation result and optional trace for one policy.
type RuleOutcome struct {
	PolicyName string
	RuleName   string
	Status     RuleStatus
	Violations []string
	Trace      []string
}

// Engine is a from-first-principles CEL evaluator for Kyverno's ValidatingPolicy model
// (policies.kyverno.io/v1, evaluation.mode: JSON). It implements the core policy loop
// in ~170 lines directly over google/cel-go:
//  1. Build a CEL environment with `object`, `variables`, optional types, and standard extensions
//  2. Filter applicability via MatchConditions (short-circuiting to SKIP on false)
//  3. Evaluate lazy/ordered Variables
//  4. Evaluate Validations sequentially (short-circuiting to FAIL on first false)
type Engine struct {
	env *cel.Env
}

// NewEngine constructs a first-principles CEL policy engine compatible with Kyverno JSON mode.
func NewEngine() (*Engine, error) {
	env, err := cel.NewEnv(
		cel.Variable("object", cel.DynType),
		cel.Variable("variables", cel.MapType(cel.StringType, cel.DynType)),
		cel.CrossTypeNumericComparisons(true),
		cel.OptionalTypes(),
		ext.Bindings(),
		ext.Strings(ext.StringsVersion(2)),
		ext.Lists(ext.ListsVersion(3)),
		ext.Sets(),
		ext.Regex(ext.RegexVersion(1)),
	)
	if err != nil {
		return nil, fmt.Errorf("create CEL environment: %w", err)
	}
	return &Engine{env: env}, nil
}

// Evaluate runs all ValidatingPolicies against an arbitrary JSON-compatible payload.
func (e *Engine) Evaluate(policies []*policiesv1beta1.ValidatingPolicy, payload map[string]any) ([]RuleOutcome, error) {
	outcomes := make([]RuleOutcome, 0, len(policies))
	for _, pol := range policies {
		outcome, err := e.evalPolicy(pol, payload)
		if err != nil {
			return nil, fmt.Errorf("policy %s: %w", pol.Name, err)
		}
		outcomes = append(outcomes, outcome)
	}
	return outcomes, nil
}

func (e *Engine) evalPolicy(pol *policiesv1beta1.ValidatingPolicy, payload map[string]any) (RuleOutcome, error) {
	out := RuleOutcome{
		PolicyName: pol.Name,
		RuleName:   "validation",
		Status:     StatusPass,
	}

	vars := map[string]any{}
	activation := map[string]any{
		"object":    payload,
		"variables": vars,
	}

	for _, mc := range pol.Spec.MatchConditions {
		ok, err := e.evalBool(mc.Expression, activation)
		if err != nil {
			return out, fmt.Errorf("matchCondition %q: %w", mc.Name, err)
		}
		out.Trace = append(out.Trace, fmt.Sprintf("[MATCH] %s (%s) -> %v", mc.Name, mc.Expression, ok))
		if !ok {
			out.Status = StatusSkip
			out.Trace = append(out.Trace, fmt.Sprintf("[SKIP] matchCondition %q returned false", mc.Name))
			return out, nil
		}
	}

	for _, v := range pol.Spec.Variables {
		val, err := e.evalAny(v.Expression, activation)
		if err != nil {
			return out, fmt.Errorf("variable %q: %w", v.Name, err)
		}
		vars[v.Name] = val
		out.Trace = append(out.Trace, fmt.Sprintf("[VAR] %s = %v", v.Name, val))
	}

	for i, valRule := range pol.Spec.Validations {
		ok, err := e.evalBool(valRule.Expression, activation)
		if err != nil {
			return out, fmt.Errorf("validation[%d]: %w", i, err)
		}
		out.Trace = append(out.Trace, fmt.Sprintf("[CEL] validation[%d] (%s) -> %v", i, strings.TrimSpace(valRule.Expression), ok))
		if !ok {
			msg := valRule.Message
			if msg == "" {
				msg = fmt.Sprintf("CEL validation[%d] failed", i)
			}
			out.Status = StatusFail
			out.Violations = append(out.Violations, msg)
			out.Trace = append(out.Trace, fmt.Sprintf("[FAIL] %s", msg))
			return out, nil
		}
		out.Trace = append(out.Trace, fmt.Sprintf("[PASS] validation[%d]", i))
	}

	return out, nil
}

func (e *Engine) evalBool(expr string, activation map[string]any) (bool, error) {
	val, err := e.evalAny(expr, activation)
	if err != nil {
		return false, err
	}
	b, ok := val.(bool)
	if !ok {
		return false, fmt.Errorf("expected bool result, got %T (%v)", val, val)
	}
	return b, nil
}

func (e *Engine) evalAny(expr string, activation map[string]any) (any, error) {
	ast, iss := e.env.Compile(expr)
	if iss.Err() != nil {
		return nil, fmt.Errorf("compile CEL %q: %w", expr, iss.Err())
	}
	prg, err := e.env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("build CEL program %q: %w", expr, err)
	}
	out, _, err := prg.Eval(activation)
	if err != nil {
		return nil, fmt.Errorf("eval CEL %q: %w", expr, err)
	}
	return out.Value(), nil
}

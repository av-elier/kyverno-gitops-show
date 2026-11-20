package firstprinciples

import (
	"fmt"
	"slices"
	"strings"

	"kyverno-show/internal/kit"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
	policiesv1beta1 "github.com/kyverno/api/api/policies.kyverno.io/v1beta1"
	engineapi "github.com/kyverno/kyverno/pkg/engine/api"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
)

type compiledExpr struct {
	name, expr string
	prg        cel.Program
}

type compiledVal struct {
	expr, msg   string
	prg, msgPrg cel.Program
}

// CompiledPolicy holds pre-compiled CEL programs for one ValidatingPolicy.
type CompiledPolicy struct {
	name, actions string
	enforced      bool
	matches, vars []compiledExpr
	validations   []compiledVal
}

// Engine is a compile-once, from-first-principles CEL evaluator for Kyverno JSON policies.
type Engine struct{ env *cel.Env }

// NewEngine builds a CEL environment compatible with Kyverno evaluation.mode: JSON.
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

// Compile compiles all policies once at load time so Evaluate runs without re-parsing CEL.
func (e *Engine) Compile(policies []policiesv1beta1.ValidatingPolicyLike) ([]CompiledPolicy, error) {
	out := make([]CompiledPolicy, 0, len(policies))
	for _, pol := range policies {
		cp, err := e.compilePolicy(pol)
		if err != nil {
			return nil, fmt.Errorf("compile policy %s: %w", pol.GetName(), err)
		}
		out = append(out, cp)
	}
	return out, nil
}

func (e *Engine) compilePolicy(pol policiesv1beta1.ValidatingPolicyLike) (CompiledPolicy, error) {
	spec := pol.GetValidatingPolicySpec()
	var actions []string
	enforced := false
	for _, a := range spec.ValidationActions() {
		actions = append(actions, string(a))
		enforced = enforced || a == admissionregistrationv1.Deny
	}
	slices.Sort(actions)
	cp := CompiledPolicy{name: pol.GetName(), actions: strings.Join(actions, ","), enforced: enforced}

	var err error
	for _, mc := range spec.MatchConditions {
		if cp.matches, err = e.appendExpr(cp.matches, "matchCondition", mc.Name, mc.Expression); err != nil {
			return cp, err
		}
	}
	for _, v := range spec.Variables {
		if cp.vars, err = e.appendExpr(cp.vars, "variable", v.Name, v.Expression); err != nil {
			return cp, err
		}
	}
	for i, val := range spec.Validations {
		prg, err := e.compile(val.Expression)
		if err != nil {
			return cp, fmt.Errorf("validation[%d]: %w", i, err)
		}
		var msgPrg cel.Program
		if val.MessageExpression != "" {
			if msgPrg, err = e.compile(val.MessageExpression); err != nil {
				return cp, fmt.Errorf("validation[%d].messageExpression: %w", i, err)
			}
		}
		cp.validations = append(cp.validations, compiledVal{val.Expression, val.Message, prg, msgPrg})
	}
	return cp, nil
}

func (e *Engine) appendExpr(dst []compiledExpr, kind, name, expr string) ([]compiledExpr, error) {
	prg, err := e.compile(expr)
	if err != nil {
		return dst, fmt.Errorf("%s %q: %w", kind, name, err)
	}
	return append(dst, compiledExpr{name, expr, prg}), nil
}

func (e *Engine) compile(expr string) (cel.Program, error) {
	ast, iss := e.env.Compile(expr)
	if iss.Err() != nil {
		return nil, fmt.Errorf("compile CEL %q: %w", expr, iss.Err())
	}
	return e.env.Program(ast)
}

// Evaluate runs pre-compiled policies against payload and returns (results, enforcedFailures, warnings).
func (e *Engine) Evaluate(policies []CompiledPolicy, payload map[string]any) ([]kit.Result, int, int, error) {
	results := make([]kit.Result, 0, len(policies))
	var enforced, warnings int
	for _, pol := range policies {
		res, err := evalPolicy(pol, payload)
		if err != nil {
			return nil, enforced, warnings, fmt.Errorf("policy %s: %w", pol.name, err)
		}
		if res.Status == engineapi.RuleStatusFail {
			if res.Enforced {
				enforced++
			} else {
				warnings++
			}
		}
		results = append(results, res)
	}
	return results, enforced, warnings, nil
}

func evalPolicy(pol CompiledPolicy, payload map[string]any) (kit.Result, error) {
	res := kit.Result{Policy: pol.name, Rule: "validation", Actions: pol.actions, Enforced: pol.enforced, Status: engineapi.RuleStatusPass}
	vars := map[string]any{}
	act := map[string]any{"object": payload, "variables": vars}

	for _, mc := range pol.matches {
		ok, err := evalAs[bool](mc.prg, act)
		if err != nil {
			return res, fmt.Errorf("matchCondition %q: %w", mc.name, err)
		}
		res.MiniTrace = append(res.MiniTrace, fmt.Sprintf("[MATCH] %s (%s) -> %v", mc.name, mc.expr, ok))
		if !ok {
			res.Status = engineapi.RuleStatusSkip
			res.MiniTrace = append(res.MiniTrace, fmt.Sprintf("[SKIP] matchCondition %q returned false", mc.name))
			return res, nil
		}
	}
	for _, v := range pol.vars {
		val, _, err := v.prg.Eval(act)
		if err != nil {
			return res, fmt.Errorf("variable %q: %w", v.name, err)
		}
		vars[v.name] = val // Preserve ref.Val so types.NullValue stays CEL null.
		res.MiniTrace = append(res.MiniTrace, fmt.Sprintf("[VAR] %s = %s", v.name, formatVal(val)))
	}
	for i, v := range pol.validations {
		ok, err := evalAs[bool](v.prg, act)
		if err != nil {
			return res, fmt.Errorf("validation[%d]: %w", i, err)
		}
		res.MiniTrace = append(res.MiniTrace, fmt.Sprintf("[CEL] validation[%d] (%s) -> %v", i, strings.TrimSpace(v.expr), ok))
		if !ok {
			msg := v.msg
			if v.msgPrg != nil {
				if msg, err = evalAs[string](v.msgPrg, act); err != nil {
					return res, fmt.Errorf("validation[%d].messageExpression: %w", i, err)
				}
			}
			if msg == "" {
				msg = fmt.Sprintf("CEL validation[%d] failed", i)
			}
			res.Status, res.Message = engineapi.RuleStatusFail, msg
			res.MiniTrace = append(res.MiniTrace, fmt.Sprintf("[FAIL] %s", msg))
			return res, nil
		}
		res.MiniTrace = append(res.MiniTrace, fmt.Sprintf("[PASS] validation[%d]", i))
	}
	return res, nil
}

func evalAs[T any](prg cel.Program, act map[string]any) (T, error) {
	var zero T
	val, _, err := prg.Eval(act)
	if err != nil {
		return zero, err
	}
	typed, ok := val.Value().(T)
	if !ok {
		return zero, fmt.Errorf("expected %T, got %T (%v)", zero, val.Value(), val.Value())
	}
	return typed, nil
}

func formatVal(val ref.Val) string {
	if val == types.NullValue {
		return "null"
	}
	return fmt.Sprintf("%v", val.Value())
}

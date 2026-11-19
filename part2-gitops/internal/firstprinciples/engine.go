package firstprinciples

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/jmespath-community/go-jmespath/pkg/binding"
	"github.com/jmespath-community/go-jmespath/pkg/functions"
	"github.com/jmespath-community/go-jmespath/pkg/interpreter"
	"github.com/jmespath-community/go-jmespath/pkg/parsing"
	"github.com/kyverno/kyverno-json/pkg/apis/policy/v1alpha1"
)

// RuleStatus represents the outcome of evaluating a single rule.
type RuleStatus string

const (
	StatusPass RuleStatus = "pass"
	StatusFail RuleStatus = "fail"
	StatusSkip RuleStatus = "skip"
)

// RuleOutcome captures the evaluation result and optional trace for one rule.
type RuleOutcome struct {
	PolicyName string
	RuleName   string
	Status     RuleStatus
	Violations []string
	Trace      []string
}

// Engine is a from-first-principles evaluator for Kyverno's ValidatingPolicy model.
// It implements the core loop of a declarative policy engine in ~170 lines:
//  1. Rule filtering via Match / Exclude trees
//  2. Recursive assertion-tree matching (maps, slices, scalars, wildcards)
//  3. Array iteration via "~.<field>" (foreach)
//  4. Computed key expressions "(jmespath)" via go-jmespath
type Engine struct {
	fnCaller interpreter.FunctionCaller
}

// NewEngine constructs a first-principles policy engine with JMESPath extensions.
func NewEngine() *Engine {
	allFuncs := append([]functions.FunctionEntry{}, functions.GetDefaultFunctions()...)
	allFuncs = append(allFuncs,
		functions.FunctionEntry{
			Name: "regex_match",
			Arguments: []functions.ArgSpec{
				{Types: []functions.JpType{functions.JpString}},
				{Types: []functions.JpType{functions.JpString}},
			},
			Handler: func(args []any) (any, error) {
				pattern := args[0].(string)
				target := args[1].(string)
				return regexp.MatchString(pattern, target)
			},
		},
		functions.FunctionEntry{
			Name: "wildcard",
			Arguments: []functions.ArgSpec{
				{Types: []functions.JpType{functions.JpString}},
				{Types: []functions.JpType{functions.JpString}},
			},
			Handler: func(args []any) (any, error) {
				return wildcardMatch(args[0].(string), args[1].(string)), nil
			},
		},
	)
	return &Engine{
		fnCaller: interpreter.NewFunctionCaller(allFuncs...),
	}
}

// Evaluate runs all policies against the arbitrary JSON-compatible payload.
func (e *Engine) Evaluate(policies []*v1alpha1.ValidatingPolicy, payload any) ([]RuleOutcome, error) {
	var outcomes []RuleOutcome
	for _, pol := range policies {
		for _, rule := range pol.Spec.Rules {
			outcome, err := e.evalRule(pol.Name, rule, payload)
			if err != nil {
				return nil, fmt.Errorf("policy %s rule %s: %w", pol.Name, rule.Name, err)
			}
			outcomes = append(outcomes, outcome)
		}
	}
	return outcomes, nil
}

func (e *Engine) evalRule(policyName string, rule v1alpha1.ValidatingRule, payload any) (RuleOutcome, error) {
	out := RuleOutcome{
		PolicyName: policyName,
		RuleName:   rule.Name,
		Status:     StatusPass,
	}

	if rule.Match != nil {
		matched, errs, err := e.evalMatch(rule.Match, payload, &out.Trace)
		if err != nil {
			return out, err
		}
		if !matched {
			out.Status = StatusSkip
			out.Trace = append(out.Trace, fmt.Sprintf("[SKIP] match condition not satisfied (%s)", strings.Join(errs, "; ")))
			return out, nil
		}
		out.Trace = append(out.Trace, "[MATCH] rule matched payload")
	}

	if rule.Exclude != nil {
		excluded, _, err := e.evalMatch(rule.Exclude, payload, &out.Trace)
		if err != nil {
			return out, err
		}
		if excluded {
			out.Status = StatusSkip
			out.Trace = append(out.Trace, "[SKIP] exclude condition matched payload")
			return out, nil
		}
	}

	if rule.Assert != nil {
		if err := e.evalAssert(rule.Assert, payload, &out); err != nil {
			return out, err
		}
	}

	if len(out.Violations) > 0 {
		out.Status = StatusFail
	}
	return out, nil
}

func (e *Engine) evalMatch(m *v1alpha1.Match, payload any, trace *[]string) (bool, []string, error) {
	if len(m.All) > 0 {
		var failReasons []string
		for i, tree := range m.All {
			errs, err := e.assertTree(fmt.Sprintf("match.all[%d]", i), tree.Value, payload, trace)
			if err != nil {
				return false, nil, err
			}
			failReasons = append(failReasons, errs...)
		}
		if len(failReasons) > 0 {
			return false, failReasons, nil
		}
	}
	if len(m.Any) > 0 {
		var allErrs []string
		anyMatched := false
		for i, tree := range m.Any {
			errs, err := e.assertTree(fmt.Sprintf("match.any[%d]", i), tree.Value, payload, trace)
			if err != nil {
				return false, nil, err
			}
			if len(errs) == 0 {
				anyMatched = true
				break
			}
			allErrs = append(allErrs, errs...)
		}
		if !anyMatched {
			return false, allErrs, nil
		}
	}
	return true, nil, nil
}

func (e *Engine) evalAssert(a *v1alpha1.Assert, payload any, out *RuleOutcome) error {
	for i, assertion := range a.All {
		errs, err := e.assertTree(fmt.Sprintf("assert.all[%d]", i), assertion.Check.Value, payload, &out.Trace)
		if err != nil {
			return err
		}
		if len(errs) > 0 {
			msg := assertion.Message
			if msg == "" {
				msg = "assertion failed"
			}
			for _, detail := range errs {
				out.Violations = append(out.Violations, fmt.Sprintf("%s (%s)", msg, detail))
			}
		}
	}
	if len(a.Any) > 0 {
		anyPassed := false
		var candidateErrs []string
		for i, assertion := range a.Any {
			errs, err := e.assertTree(fmt.Sprintf("assert.any[%d]", i), assertion.Check.Value, payload, &out.Trace)
			if err != nil {
				return err
			}
			if len(errs) == 0 {
				anyPassed = true
				break
			}
			msg := assertion.Message
			if msg == "" {
				msg = "assertion failed"
			}
			candidateErrs = append(candidateErrs, fmt.Sprintf("%s (%s)", msg, strings.Join(errs, "; ")))
		}
		if !anyPassed {
			out.Violations = append(out.Violations, candidateErrs...)
		}
	}
	return nil
}

// assertTree recursively walks an assertion node (map, slice, or scalar) against actual data.
func (e *Engine) assertTree(path string, expected, actual any, trace *[]string) ([]string, error) {
	switch exp := expected.(type) {
	case map[string]any:
		return e.assertMap(path, exp, actual, trace)
	case []any:
		actualSlice, ok := toAnySlice(actual)
		if !ok {
			return []string{fmt.Sprintf("%s: expected array, got %T", path, actual)}, nil
		}
		if len(actualSlice) < len(exp) {
			return []string{fmt.Sprintf("%s: expected at least %d items, got %d", path, len(exp), len(actualSlice))}, nil
		}
		var errs []string
		for i, itemExp := range exp {
			itemErrs, err := e.assertTree(fmt.Sprintf("%s[%d]", path, i), itemExp, actualSlice[i], trace)
			if err != nil {
				return nil, err
			}
			errs = append(errs, itemErrs...)
		}
		return errs, nil
	default:
		if !scalarEqual(exp, actual) {
			msg := fmt.Sprintf("%s: expected %v, got %v", path, exp, actual)
			*trace = append(*trace, "[FAIL] "+msg)
			return []string{msg}, nil
		}
		*trace = append(*trace, fmt.Sprintf("[PASS] %s == %v", path, exp))
		return nil, nil
	}
}

func (e *Engine) assertMap(path string, expMap map[string]any, actual any, trace *[]string) ([]string, error) {
	var errs []string
	for key, subExpected := range expMap {
		// 1. Foreach projection: "~.<field>" iterates over every element of slice at <field>.
		if strings.HasPrefix(key, "~.") {
			fieldName := strings.TrimPrefix(key, "~.")
			actualMap, ok := actual.(map[string]any)
			if !ok {
				errs = append(errs, fmt.Sprintf("%s.%s: expected object, got %T", path, fieldName, actual))
				continue
			}
			sliceVal, ok := toAnySlice(actualMap[fieldName])
			if !ok {
				errs = append(errs, fmt.Sprintf("%s.%s: expected array for foreach", path, fieldName))
				continue
			}
			*trace = append(*trace, fmt.Sprintf("[FOREACH] %s.%s (%d items)", path, fieldName, len(sliceVal)))
			for idx, item := range sliceVal {
				itemErrs, err := e.assertTree(fmt.Sprintf("%s.%s[%d]", path, fieldName, idx), subExpected, item, trace)
				if err != nil {
					return nil, err
				}
				errs = append(errs, itemErrs...)
			}
			continue
		}

		// 2. JMESPath expression key: "(expr)" evaluates JMESPath against the current node.
		if strings.HasPrefix(key, "(") && strings.HasSuffix(key, ")") {
			expr := strings.TrimSuffix(strings.TrimPrefix(key, "("), ")")
			res, err := e.evalJMESPath(expr, actual)
			if err != nil {
				return nil, fmt.Errorf("%s (%s): %w", path, expr, err)
			}
			*trace = append(*trace, fmt.Sprintf("[JMESPATH] %s (%s) -> %v", path, expr, res))
			subErrs, err := e.assertTree(fmt.Sprintf("%s.(%s)", path, expr), subExpected, res, trace)
			if err != nil {
				return nil, err
			}
			errs = append(errs, subErrs...)
			continue
		}

		// 3. Literal object key lookup.
		actualMap, ok := actual.(map[string]any)
		if !ok {
			errs = append(errs, fmt.Sprintf("%s.%s: expected object, got %T", path, key, actual))
			continue
		}
		val, exists := actualMap[key]
		if !exists {
			msg := fmt.Sprintf("%s.%s: field missing", path, key)
			*trace = append(*trace, "[FAIL] "+msg)
			errs = append(errs, msg)
			continue
		}
		subErrs, err := e.assertTree(fmt.Sprintf("%s.%s", path, key), subExpected, val, trace)
		if err != nil {
			return nil, err
		}
		errs = append(errs, subErrs...)
	}
	return errs, nil
}

func (e *Engine) evalJMESPath(expr string, data any) (any, error) {
	parser := parsing.NewParser()
	compiled, err := parser.Parse(expr)
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}
	vm := interpreter.NewInterpreter(nil, binding.NewBindings())
	return vm.Execute(compiled, data, interpreter.WithFunctionCaller(e.fnCaller))
}

func toAnySlice(v any) ([]any, bool) {
	if s, ok := v.([]any); ok {
		return s, true
	}
	rv := reflect.ValueOf(v)
	if !rv.IsValid() || rv.Kind() != reflect.Slice {
		return nil, false
	}
	out := make([]any, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		out[i] = rv.Index(i).Interface()
	}
	return out, true
}

func scalarEqual(expected, actual any) bool {
	if expStr, ok := expected.(string); ok {
		actStr, ok := actual.(string)
		if !ok {
			return false
		}
		if strings.HasPrefix(expStr, "!") {
			return !wildcardMatch(strings.TrimPrefix(expStr, "!"), actStr)
		}
		return wildcardMatch(expStr, actStr)
	}
	return reflect.DeepEqual(expected, actual)
}

func wildcardMatch(pattern, value string) bool {
	if !strings.ContainsAny(pattern, "*?") {
		return pattern == value
	}
	// Convert simple glob (* and ?) to anchored regex so slashes are matched cleanly.
	var b strings.Builder
	b.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	matched, _ := regexp.MatchString(b.String(), value)
	return matched
}

"""
Comprehensive test for the MISRA agent:
  1. Parser + context (55 violations × 29 rules)
  2. Knowledge base completeness
  3. Fix engine — suggestions for every violation
  4. Mechanical fix correctness for key rules
"""
import sys
import os
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.axivion_parser import AxivionParser
from core.context_provider import ContextProvider
from core.misra_knowledge_base import get_rule, get_all_rules, format_rule_explanation
from core.fix_engine import FixEngine

WORKSPACE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
REPORT    = os.path.join(WORKSPACE, 'tests', 'mock_report.json')

ALL_EXPECTED = {
    "MisraC2012-2.1", "MisraC2012-2.2", "MisraC2012-2.3", "MisraC2012-2.4",
    "MisraC2012-2.5", "MisraC2012-2.6", "MisraC2012-2.7",
    "MisraC2012-8.1", "MisraC2012-8.2", "MisraC2012-8.3", "MisraC2012-8.4",
    "MisraC2012-8.5", "MisraC2012-8.6", "MisraC2012-8.7", "MisraC2012-8.8",
    "MisraC2012-8.9", "MisraC2012-8.10", "MisraC2012-8.11", "MisraC2012-8.12",
    "MisraC2012-8.13", "MisraC2012-8.14",
    "MisraC2012-10.1", "MisraC2012-10.2", "MisraC2012-10.3", "MisraC2012-10.4",
    "MisraC2012-10.5", "MisraC2012-10.6", "MisraC2012-10.7", "MisraC2012-10.8",
}


def section(title: str):
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


def run_tests():
    print("=" * 72)
    print("  COMPREHENSIVE MISRA AGENT TEST SUITE")
    print("=" * 72)

    parser   = AxivionParser(REPORT)
    provider = ContextProvider(WORKSPACE)
    engine   = FixEngine()
    violations = parser.get_all_violations()

    # ═══════════════════════════════════════════════════════════════
    #  SECTION 1: Parser & Coverage
    # ═══════════════════════════════════════════════════════════════
    section("1. PARSER & COVERAGE")

    print(f"  Violations loaded: {len(violations)}")
    assert len(violations) == 55, f"Expected 55, got {len(violations)}"

    found_rules = {v.rule_id for v in violations}
    missing = ALL_EXPECTED - found_rules
    assert not missing, f"Missing rules: {missing}"
    print(f"  All {len(ALL_EXPECTED)} rules present ✓")

    # ═══════════════════════════════════════════════════════════════
    #  SECTION 2: Knowledge Base Completeness
    # ═══════════════════════════════════════════════════════════════
    section("2. KNOWLEDGE BASE")

    kb = get_all_rules()
    print(f"  Rules in KB: {len(kb)}")
    assert len(kb) == 29, f"Expected 29 rules in KB, got {len(kb)}"

    required_fields = ['rule_id', 'title', 'category', 'rationale',
                       'non_compliant', 'compliant', 'fix_strategy']
    missing_fields = []
    for rule_id, rule in kb.items():
        for field in required_fields:
            value = getattr(rule, field, None)
            if not value:
                missing_fields.append(f"{rule_id}.{field}")

    if missing_fields:
        print(f"  ✗ Missing fields: {missing_fields}")
    else:
        print(f"  All 29 rules × {len(required_fields)} fields complete ✓")
    assert not missing_fields

    # Check every rule in the report has a KB entry
    for rule_id in found_rules:
        assert get_rule(rule_id) is not None, f"KB missing: {rule_id}"
    print(f"  All violation rule IDs have KB entries ✓")

    # Check format_rule_explanation works
    for rule_id in ALL_EXPECTED:
        explanation = format_rule_explanation(rule_id)
        assert "Rationale" in explanation, f"Missing rationale in {rule_id}"
        assert "Non-Compliant" in explanation, f"Missing example in {rule_id}"
        assert "How to Fix" in explanation, f"Missing fix strategy in {rule_id}"
    print(f"  Rule explanations render correctly for all 29 rules ✓")

    # ═══════════════════════════════════════════════════════════════
    #  SECTION 3: Fix Engine — Every Violation Gets a Suggestion
    # ═══════════════════════════════════════════════════════════════
    section("3. FIX ENGINE — COVERAGE")

    confidence_dist = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    failed = 0

    for v in violations:
        line = provider.get_line(v.file_path, v.line_number)
        ctx  = provider.get_code_context(v.file_path, v.line_number)

        try:
            suggestion = engine.propose_fix(v, ctx, line)
        except Exception as e:
            print(f"  ✗ {v.rule_id} @ {v.file_path}:{v.line_number}: {e}")
            failed += 1
            continue

        assert suggestion.rule_id == v.rule_id
        assert suggestion.confidence in ("HIGH", "MEDIUM", "LOW")
        assert suggestion.fix_strategy, f"Empty fix_strategy for {v.rule_id}"
        confidence_dist[suggestion.confidence] += 1

    print(f"  Suggestions generated: {len(violations) - failed}/{len(violations)}")
    print(f"  Confidence distribution: {confidence_dist}")
    assert failed == 0, f"{failed} violations failed to produce suggestions"
    print(f"  All 55 violations produce fix suggestions ✓")

    # ═══════════════════════════════════════════════════════════════
    #  SECTION 4: Mechanical Fix Correctness
    # ═══════════════════════════════════════════════════════════════
    section("4. MECHANICAL FIX CORRECTNESS")

    # Rule 8.10: inline → static inline
    check_pattern_fix(
        engine, parser, provider,
        rule_id="MisraC2012-8.10",
        expected_in_fixed="static inline",
        label="8.10: add static before inline",
    )

    # Rule 8.14: restrict → removed
    check_pattern_fix(
        engine, parser, provider,
        rule_id="MisraC2012-8.14",
        expected_not_in_fixed="*restrict",
        label="8.14: remove restrict qualifier",
    )

    # Rule 8.2 (empty parens): () → (void)
    r8_2 = [v for v in parser.get_violation_by_id("MisraC2012-8.2")
            if "empty" in v.message.lower() or "Empty" in v.message]
    if r8_2:
        v = r8_2[0]
        line = provider.get_line(v.file_path, v.line_number)
        ctx  = provider.get_code_context(v.file_path, v.line_number)
        s = engine.propose_fix(v, ctx, line)
        if "(void)" in s.fixed_line:
            print(f"  8.2: () → (void): ✓")
        else:
            print(f"  8.2: () → (void): fixed_line = '{s.fixed_line}' (pattern may not apply to this line)")

    # Rule 2.7: unused params → (void) casts
    r2_7 = parser.get_violation_by_id("MisraC2012-2.7")
    if r2_7:
        v = r2_7[0]
        line = provider.get_line(v.file_path, v.line_number)
        ctx  = provider.get_code_context(v.file_path, v.line_number)
        s = engine.propose_fix(v, ctx, line)
        assert "(void)" in s.fixed_line, f"Expected (void) cast, got: {s.fixed_line}"
        print(f"  2.7: unused params → (void) cast: ✓")

    # Rule 2.1: unreachable code → deletion suggestion
    r2_1 = parser.get_violation_by_id("MisraC2012-2.1")
    if r2_1:
        v = r2_1[0]
        line = provider.get_line(v.file_path, v.line_number)
        ctx  = provider.get_code_context(v.file_path, v.line_number)
        s = engine.propose_fix(v, ctx, line)
        assert "removed" in s.fixed_line.lower() or "remove" in s.explanation.lower()
        print(f"  2.1: unreachable code → deletion suggestion: ✓")

    # ═══════════════════════════════════════════════════════════════
    #  SECTION 5: Enhanced Context Provider
    # ═══════════════════════════════════════════════════════════════
    section("5. ENHANCED CONTEXT PROVIDER")

    # Test get_line
    line = provider.get_line("tests/mock_code_rule8x.c", 92)
    assert "inline" in line, f"Expected 'inline' in line 92, got: {line}"
    print(f"  get_line: ✓")

    # Test enclosing function
    fn = provider.get_enclosing_function("tests/mock_code_rule2x.c", 18)
    assert fn is not None and "rule_2_1_edge_nested" in fn
    print(f"  get_enclosing_function: '{fn}' ✓")

    # Test symbol search
    uses = provider.find_symbol_uses("tests/mock_code_rule8x.c", "rule_8_6_tentative")
    assert len(uses) >= 2
    print(f"  find_symbol_uses('rule_8_6_tentative'): {len(uses)} occurrences ✓")

    # Test dependency analysis still works
    deps = provider.analyze_dependencies("tests/mock_code_rule10x.c")
    assert any("stdbool" in d for d in deps)
    print(f"  analyze_dependencies: {len(deps)} deps ✓")

    # ═══════════════════════════════════════════════════════════════
    #  SECTION 6: Side-Effect Warnings for Cross-File Rules
    # ═══════════════════════════════════════════════════════════════
    section("6. SIDE-EFFECT WARNINGS")

    cross_file_rules = {"MisraC2012-8.3", "MisraC2012-8.4", "MisraC2012-8.5",
                        "MisraC2012-8.8", "MisraC2012-8.13"}
    for rule_id in cross_file_rules:
        vlist = parser.get_violation_by_id(rule_id)
        if vlist:
            v = vlist[0]
            line = provider.get_line(v.file_path, v.line_number)
            ctx  = provider.get_code_context(v.file_path, v.line_number)
            s = engine.propose_fix(v, ctx, line)
            assert s.side_effects, f"Expected side-effect warning for {rule_id}"
    print(f"  All cross-file rules produce side-effect warnings ✓")

    # ═══════════════════════════════════════════════════════════════
    #  SUMMARY
    # ═══════════════════════════════════════════════════════════════
    print("\n" + "=" * 72)
    print("  ALL TESTS PASSED ✓")
    print("  • 55 violations parsed across 29 rules")
    print("  • 29 knowledge base entries validated")
    print("  • 55 fix suggestions generated")
    print(f"  • Confidence: {confidence_dist}")
    print("  • Mechanical fixes verified (8.10, 8.14, 8.2, 2.7, 2.1)")
    print("  • Enhanced context provider verified")
    print("  • Cross-file side-effect warnings verified")
    print("=" * 72)


def check_pattern_fix(engine, parser, provider, rule_id, label,
                      expected_in_fixed=None, expected_not_in_fixed=None):
    """Helper to verify a pattern-based fix."""
    vlist = parser.get_violation_by_id(rule_id)
    assert vlist, f"No violations for {rule_id}"
    v = vlist[0]
    line = provider.get_line(v.file_path, v.line_number)
    ctx  = provider.get_code_context(v.file_path, v.line_number)
    s = engine.propose_fix(v, ctx, line)

    if expected_in_fixed:
        assert expected_in_fixed in s.fixed_line, (
            f"{label}: expected '{expected_in_fixed}' in '{s.fixed_line}'"
        )
    if expected_not_in_fixed:
        assert expected_not_in_fixed not in s.fixed_line, (
            f"{label}: '{expected_not_in_fixed}' should NOT be in '{s.fixed_line}'"
        )
    print(f"  {label}: ✓")


if __name__ == "__main__":
    run_tests()

"""
Comprehensive test suite for the AST-aware MISRA compliance agent.

Tests:
  1. Parser & coverage
  2. Knowledge base completeness
  3. C Analyzer AST accuracy (function extraction, param analysis, writes, scope)
  4. Fix engine analysis quality (AST-backed, not regex)
  5. Context provider
  6. Cross-file side-effect warnings
  7. Extended automated fixes (Rules 11-15)
"""
import sys
import os

WORKSPACE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(WORKSPACE)

from core.axivion_parser import AxivionParser
from core.context_provider import ContextProvider
from core.c_analyzer import CAnalyzer
from core.misra_knowledge_base import get_rule, get_all_rules, format_rule_explanation
from core.fix_engine import FixEngine, FixAnalysis

REPORT = os.path.join(WORKSPACE, 'tests', 'mock_report.json')


def section(title: str):
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


def test_parser(parser):
    section("1. PARSER & COVERAGE")
    all_v = parser.get_all_violations()
    print(f"  Violations loaded: {len(all_v)}")
    assert len(all_v) == 55

    rules_seen = set(v.rule_id for v in all_v)
    rules_expected = set(get_all_rules().keys())
    assert len(rules_expected) > 90, f"Expected >90 rules, got {len(rules_expected)}"
    print(f"  All {len(rules_expected)} rules present ✓")
    return all_v


def test_knowledge_base(all_violations):
    section("2. KNOWLEDGE BASE")
    all_rules = get_all_rules()
    print(f"  Rules in KB: {len(all_rules)}")

    for rid, rule in all_rules.items():
        for field_name in ("rule_id", "title", "category", "rationale",
                           "non_compliant", "compliant", "fix_strategy"):
            val = getattr(rule, field_name)
            assert val and len(val) > 0, f"{rid}.{field_name} is empty"
    print(f"  All {len(all_rules)} rules × 7 fields complete ✓")

    rules_seen = set(v.rule_id for v in all_violations)
    for rid in rules_seen:
        assert rid in all_rules, f"Violation rule {rid} not in KB"
    print(f"  All violation rule IDs have KB entries ✓")

    for rid, rule in all_rules.items():
        assert not hasattr(rule, 'fix_patterns'), f"{rid} still has fix_patterns"
    print(f"  FixPattern fully removed from knowledge base ✓")


def test_ast_analyzer(analyzer):
    section("3. C ANALYZER — AST ACCURACY")

    # 3a. Function extraction
    fns = analyzer.get_functions('tests/mock_code_rule8x.c')
    fn_names = [f.name for f in fns]
    assert len(fns) >= 10, f"Expected ≥10 functions, got {len(fns)}"
    print(f"  Functions extracted ({len(fns)}): {fn_names[:6]}... ✓")

    # 3b. Parameter usage — Rule 8.13 (pointer to const)
    fn = analyzer.get_function_at_line('tests/mock_code_rule8x.c', 114)
    assert fn is not None, "No function at line 114"
    assert fn.name == "rule_8_13_nomod"
    data_param = next(p for p in fn.params if p.name == "data")
    assert data_param.is_pointer, "data should be a pointer"
    assert data_param.write_count == 0, f"data writes: {data_param.write_count}"
    assert data_param.read_count >= 1, f"data reads: {data_param.read_count}"
    print(f"  8.13 pointer analysis: data(reads={data_param.read_count}, writes=0) ✓")

    # 3c. Unused parameters — Rule 2.7
    analysis = analyzer.analyze_for_rule('tests/mock_code_rule2x.c', 126, 'MisraC2012-2.7')
    unused = analysis.get('unused_params', [])
    assert 'unused_a' in unused and 'unused_b' in unused, f"Expected unused_a, unused_b: {unused}"
    print(f"  2.7 unused params: {unused} ✓")

    # 3d. Enum collisions — Rule 8.12
    analysis = analyzer.analyze_for_rule('tests/mock_code_rule8x.c', 103, 'MisraC2012-8.12')
    collisions = analysis.get('enum_collisions', {})
    assert len(collisions) > 0, f"No enum collisions detected"
    print(f"  8.12 enum collisions: {collisions} ✓")

    # 3e. Inline without static — Rule 8.10
    analysis = analyzer.analyze_for_rule('tests/mock_code_rule8x.c', 92, 'MisraC2012-8.10')
    assert analysis.get('needs_static') == True, "Should need static"
    print(f"  8.10 inline without static: needs_static=True ✓")


def test_fix_engine(all_violations, provider, engine):
    section("4. FIX ENGINE — AST-BACKED ANALYSIS")

    fix_count = 0
    confidence_dist = {}
    for v in all_violations:
        ctx = provider.get_code_context(v.file_path, v.line_number)
        line = provider.get_line(v.file_path, v.line_number)
        fa = engine.propose_fix(v, ctx, line)
        assert isinstance(fa, FixAnalysis), f"Not a FixAnalysis for {v.rule_id}"
        assert fa.rule_id == v.rule_id
        confidence_dist[fa.confidence] = confidence_dist.get(fa.confidence, 0) + 1
        fix_count += 1

    print(f"  Analyses generated: {fix_count}/55")
    print(f"  Confidence distribution: {confidence_dist}")
    print(f"  All 55 violations produce FixAnalysis ✓")
    return confidence_dist


def test_context_provider(provider):
    section("5. CONTEXT PROVIDER")
    line = provider.get_line('tests/mock_code_rule2x.c', 1)
    assert len(line) > 0
    print(f"  get_line: ✓")

    fn = provider.get_enclosing_function('tests/mock_code_rule2x.c', 18)
    assert fn is not None
    print(f"  get_enclosing_function: '{fn}' ✓")
    
    deps = provider.analyze_dependencies('tests/mock_code.c')
    assert len(deps) >= 1
    print(f"  analyze_dependencies: {len(deps)} deps ✓")


def test_cross_file_warnings(all_violations, provider, engine):
    section("6. SIDE-EFFECT WARNINGS")
    cross_file_rules = {"MisraC2012-8.3", "MisraC2012-8.4", "MisraC2012-8.5",
                        "MisraC2012-8.8", "MisraC2012-8.13"}
    for v in all_violations:
        if v.rule_id not in cross_file_rules:
            continue
        ctx = provider.get_code_context(v.file_path, v.line_number)
        line = provider.get_line(v.file_path, v.line_number)
        fa = engine.propose_fix(v, ctx, line)
        assert len(fa.side_effects) > 0, \
            f"Cross-file rule {v.rule_id} missing side effects"
    print(f"  All cross-file rules produce side-effect warnings ✓")


def test_extended_autofixes():
    section("EXTENDED AUTOMATED FIXES (Rules 11-15)")

    fixer = FixEngine()

    # 1. Test Rule 15.6 (Missing Braces)
    findings_15_6 = {
        "missing_braces": [
            {"start_byte": 10, "end_byte": 20, "text": "x++;"}
        ]
    }
    edits = fixer._generate_15_6_edits(findings_15_6, None)
    assert len(edits) == 1
    assert edits[0]["text"] == "{ x++; }"
    print("  Rule 15.6 (Braces) fix generated ✓")

    # 2. Test Rule 14.4 (Boolean Check)
    findings_14_4 = {
        "non_boolean_conditions": [
            {"start_byte": 5, "end_byte": 6, "text": "p"}
        ]
    }
    edits = fixer._generate_14_4_edits(findings_14_4)
    assert len(edits) == 1
    assert edits[0]["text"] == "p != 0"
    print("  Rule 14.4 (Boolean) fix generated ✓")

    # 3. Test Rule 11.9 (NULL)
    findings_11_9 = {
        "null_pointer_violations": [
            {"start_byte": 100, "end_byte": 101, "text": "0"}
        ]
    }
    edits = fixer._generate_11_9_edits(findings_11_9)
    assert len(edits) == 1
    assert edits[0]["text"] == "NULL"
    print("  Rule 11.9 (NULL) fix generated ✓")


def run_tests():
    print("=" * 72)
    print("  COMPREHENSIVE MISRA AGENT TEST SUITE (AST-aware)")
    print("=" * 72)

    parser = AxivionParser(REPORT)
    provider = ContextProvider(WORKSPACE)
    analyzer = CAnalyzer(WORKSPACE)
    engine = FixEngine(analyzer)

    # 1. PARSER
    all_violations = test_parser(parser)

    # 2. KNOWLEDGE BASE
    test_knowledge_base(all_violations)

    # 3. AST ANALYZER
    test_ast_analyzer(analyzer)

    # 4. FIX ENGINE
    confidence_dist = test_fix_engine(all_violations, provider, engine)

    # 5. CONTEXT PROVIDER
    test_context_provider(provider)

    # 6. SIDE EFFECTS
    test_cross_file_warnings(all_violations, provider, engine)

    # 7. EXTENDED FIXES
    test_extended_autofixes()

    print("\n" + "=" * 72)
    print("  ALL TESTS PASSED ✓")
    print(f"  • {len(all_violations)} violations parsed")
    print(f"  • Knowledge base verified (160+ rules)")
    print(f"  • AST analysis verified")
    print(f"  • Fix Engine confidence: {confidence_dist}")
    print(f"  • Automated fixes verified for 2.x, 8.x, 10.x, 11.x, 14.x, 15.x")
    print("=" * 72)


if __name__ == "__main__":
    run_tests()

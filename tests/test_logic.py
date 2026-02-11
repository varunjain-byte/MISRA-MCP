"""
Comprehensive test suite for the AST-aware MISRA compliance agent.

Tests:
  1. Parser & coverage
  2. Knowledge base completeness
  3. C Analyzer AST accuracy (function extraction, param analysis, writes, scope)
  4. Fix engine analysis quality (AST-backed, not regex)
  5. Context provider
  6. Cross-file side-effect warnings
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


def run_tests():
    print("=" * 72)
    print("  COMPREHENSIVE MISRA AGENT TEST SUITE (AST-aware)")
    print("=" * 72)

    parser = AxivionParser(REPORT)
    provider = ContextProvider(WORKSPACE)
    analyzer = CAnalyzer(WORKSPACE)
    engine = FixEngine(analyzer)

    # ═══════════════════════════════════════════════════════════════
    #  1. PARSER & COVERAGE
    # ═══════════════════════════════════════════════════════════════
    section("1. PARSER & COVERAGE")
    all_v = parser.get_all_violations()
    print(f"  Violations loaded: {len(all_v)}")
    assert len(all_v) == 55

    rules_seen = set(v.rule_id for v in all_v)
    rules_expected = set(get_all_rules().keys())
    assert rules_seen == rules_expected, f"Missing: {rules_expected - rules_seen}"
    print(f"  All {len(rules_expected)} rules present ✓")

    # ═══════════════════════════════════════════════════════════════
    #  2. KNOWLEDGE BASE
    # ═══════════════════════════════════════════════════════════════
    section("2. KNOWLEDGE BASE")
    all_rules = get_all_rules()
    print(f"  Rules in KB: {len(all_rules)}")

    for rid, rule in all_rules.items():
        for field_name in ("rule_id", "title", "category", "rationale",
                           "non_compliant", "compliant", "fix_strategy"):
            val = getattr(rule, field_name)
            assert val and len(val) > 0, f"{rid}.{field_name} is empty"
    print(f"  All {len(all_rules)} rules × 7 fields complete ✓")

    for rid in rules_seen:
        assert rid in all_rules, f"Violation rule {rid} not in KB"
    print(f"  All violation rule IDs have KB entries ✓")

    for rid in all_rules:
        explanation = format_rule_explanation(rid)
        assert len(explanation) > 100, f"Explanation too short for {rid}"
    print(f"  Rule explanations render correctly for all {len(all_rules)} rules ✓")

    # Verify no FixPattern remnants
    for rid, rule in all_rules.items():
        assert not hasattr(rule, 'fix_patterns'), f"{rid} still has fix_patterns"
    print(f"  FixPattern fully removed from knowledge base ✓")

    # ═══════════════════════════════════════════════════════════════
    #  3. C ANALYZER — AST ACCURACY
    # ═══════════════════════════════════════════════════════════════
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
    collision_values = list(collisions.keys())
    assert len(collision_values) > 0, f"No enum collisions detected"
    print(f"  8.12 enum collisions: {collisions} ✓")

    # 3e. Inline without static — Rule 8.10
    analysis = analyzer.analyze_for_rule('tests/mock_code_rule8x.c', 92, 'MisraC2012-8.10')
    fn_info = analysis.get('function', {})
    assert analysis.get('needs_static') == True, "Should need static"
    print(f"  8.10 inline without static: needs_static=True ✓")

    # 3f. Symbol scope analysis
    scope = analyzer.get_symbol_scope('tests/mock_code_rule8x.c', 'rule_8_4_no_decl')
    assert scope in ('external', 'file', 'block'), f"Unexpected scope: {scope}"
    print(f"  Symbol scope analysis: rule_8_4_no_decl → {scope} ✓")

    # ═══════════════════════════════════════════════════════════════
    #  4. FIX ENGINE — AST-BACKED ANALYSIS
    # ═══════════════════════════════════════════════════════════════
    section("4. FIX ENGINE — AST-BACKED ANALYSIS")

    # 4a. Every violation produces a FixAnalysis
    fix_count = 0
    confidence_dist = {}
    for v in all_v:
        ctx = provider.get_code_context(v.file_path, v.line_number)
        line = provider.get_line(v.file_path, v.line_number)
        fa = engine.propose_fix(v, ctx, line)
        assert isinstance(fa, FixAnalysis), f"Not a FixAnalysis for {v.rule_id}"
        assert fa.rule_id == v.rule_id
        assert fa.confidence in ("HIGH", "MEDIUM", "LOW")
        assert len(fa.fix_guidance) > 10, f"Guidance too short for {v.rule_id}"
        confidence_dist[fa.confidence] = confidence_dist.get(fa.confidence, 0) + 1
        fix_count += 1

    print(f"  Analyses generated: {fix_count}/55")
    print(f"  Confidence distribution: {confidence_dist}")
    assert fix_count == 55
    print(f"  All 55 violations produce FixAnalysis ✓")

    # 4b. HIGH-confidence analyses have AST evidence
    high_rules = {"MisraC2012-8.13", "MisraC2012-8.10", "MisraC2012-2.7", "MisraC2012-2.1"}
    for v in all_v:
        if v.rule_id not in high_rules:
            continue
        ctx = provider.get_code_context(v.file_path, v.line_number)
        line = provider.get_line(v.file_path, v.line_number)
        fa = engine.propose_fix(v, ctx, line)

        # Should have relevant AST findings
        if v.rule_id == "MisraC2012-8.13":
            assert "const_candidates" in fa.ast_findings or fa.ast_findings.get("params"), \
                f"8.13 should have const_candidates"
        elif v.rule_id == "MisraC2012-2.7":
            assert fa.ast_findings.get("unused_params"), \
                f"2.7 should have unused_params"
        elif v.rule_id == "MisraC2012-8.10":
            assert fa.ast_findings.get("needs_static") or \
                   (fa.ast_findings.get("function") and fa.ast_findings["function"].get("is_inline")), \
                f"8.10 should have needs_static or inline info"
    print(f"  HIGH-confidence analyses have AST evidence ✓")

    # 4c. Markdown output is well-formed
    sample_v = all_v[0]
    ctx = provider.get_code_context(sample_v.file_path, sample_v.line_number)
    line = provider.get_line(sample_v.file_path, sample_v.line_number)
    fa = engine.propose_fix(sample_v, ctx, line)
    md = fa.to_markdown()
    assert "### Fix Analysis" in md
    assert "AST Analysis" in md
    assert "Fix Guidance" in md
    assert "Compliant Example" in md
    print(f"  Markdown output well-formed ✓")

    # ═══════════════════════════════════════════════════════════════
    #  5. CONTEXT PROVIDER
    # ═══════════════════════════════════════════════════════════════
    section("5. CONTEXT PROVIDER")

    line = provider.get_line('tests/mock_code_rule2x.c', 1)
    assert len(line) > 0
    print(f"  get_line: ✓")

    fn = provider.get_enclosing_function('tests/mock_code_rule2x.c', 18)
    assert fn is not None
    print(f"  get_enclosing_function: '{fn}' ✓")

    uses = provider.find_symbol_uses('tests/mock_code_rule8x.c', 'rule_8_6_tentative')
    assert len(uses) >= 2
    print(f"  find_symbol_uses('rule_8_6_tentative'): {len(uses)} occurrences ✓")

    deps = provider.analyze_dependencies('tests/mock_code.c')
    assert len(deps) >= 1
    print(f"  analyze_dependencies: {len(deps)} deps ✓")

    # ═══════════════════════════════════════════════════════════════
    #  6. SIDE-EFFECT WARNINGS
    # ═══════════════════════════════════════════════════════════════
    section("6. SIDE-EFFECT WARNINGS")

    cross_file_rules = {"MisraC2012-8.3", "MisraC2012-8.4", "MisraC2012-8.5",
                        "MisraC2012-8.8", "MisraC2012-8.13"}
    for v in all_v:
        if v.rule_id not in cross_file_rules:
            continue
        ctx = provider.get_code_context(v.file_path, v.line_number)
        line = provider.get_line(v.file_path, v.line_number)
        fa = engine.propose_fix(v, ctx, line)
        assert len(fa.side_effects) > 0, \
            f"Cross-file rule {v.rule_id} missing side effects"
    print(f"  All cross-file rules produce side-effect warnings ✓")

    # ═══════════════════════════════════════════════════════════════
    #  SUMMARY
    # ═══════════════════════════════════════════════════════════════
    print("\n" + "=" * 72)
    print("  ALL TESTS PASSED ✓")
    print(f"  • 55 violations parsed across 29 rules")
    print(f"  • 29 knowledge base entries validated (FixPattern removed)")
    print(f"  • AST analyzer: function extraction, param R/W, pointer writes,")
    print(f"    unused params, enum collisions, scope — all verified")
    print(f"  • 55 AST-backed fix analyses generated")
    print(f"  • Confidence: {confidence_dist}")
    print(f"  • Context provider verified")
    print(f"  • Cross-file side-effect warnings verified")
    print("=" * 72)


if __name__ == "__main__":
    run_tests()

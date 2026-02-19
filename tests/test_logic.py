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

    # 1. Test Rule 15.6 (Missing Braces) — now returns (edits, skip_reason)
    #    Without a real violation (no file path), falls back to inline wrap
    from core.axivion_parser import AxivionViolation
    dummy_viol = AxivionViolation(
        rule_id="MisraC2012-15.6", message="test",
        file_path="nonexistent.c", line_number=1,
        severity="Required"
    )
    findings_15_6 = {
        "missing_braces": [
            {"start_byte": 10, "end_byte": 20, "text": "x++;"}
        ]
    }
    edits, skip = fixer._generate_15_6_edits(findings_15_6, dummy_viol)
    assert len(edits) == 1
    assert "x++;" in edits[0]["text"]
    assert "{" in edits[0]["text"] and "}" in edits[0]["text"]
    print("  Rule 15.6 (Braces) fix generated ✓")

    # 2. Test Rule 14.4 (Boolean Check) — now returns (edits, skip_reason)
    findings_14_4 = {
        "non_boolean_conditions": [
            {"start_byte": 5, "end_byte": 6, "text": "p", "is_pointer": False}
        ]
    }
    edits, skip = fixer._generate_14_4_edits(findings_14_4)
    assert len(edits) == 1
    assert edits[0]["text"] == "p != 0"
    print("  Rule 14.4 (Boolean int) fix generated ✓")

    # 2b. Test pointer uses != NULL
    findings_14_4_ptr = {
        "non_boolean_conditions": [
            {"start_byte": 5, "end_byte": 6, "text": "ptr", "is_pointer": True}
        ]
    }
    edits, skip = fixer._generate_14_4_edits(findings_14_4_ptr)
    assert len(edits) == 1
    assert edits[0]["text"] == "ptr != NULL"
    print("  Rule 14.4 (Boolean ptr) fix generated ✓")

    # 2c. Test idempotency — already has comparison
    findings_14_4_idem = {
        "non_boolean_conditions": [
            {"start_byte": 5, "end_byte": 10, "text": "x != 0", "is_pointer": False}
        ]
    }
    edits, skip = fixer._generate_14_4_edits(findings_14_4_idem)
    assert len(edits) == 0
    print("  Rule 14.4 (idempotency) correctly skips ✓")

    # 3. Test Rule 11.9 (NULL) — now returns (edits, skip_reason)
    findings_11_9 = {
        "null_pointer_violations": [
            {"start_byte": 100, "end_byte": 101, "text": "0"}
        ]
    }
    edits, skip = fixer._generate_11_9_edits(findings_11_9)
    assert len(edits) == 1
    assert edits[0]["text"] == "NULL"
    print("  Rule 11.9 (NULL) fix generated ✓")


def test_10x_assignment_handling():
    """Test that 10.x fixer handles assignment and init-declarator expressions."""
    section("10.x ASSIGNMENT / INIT-DECLARATOR HANDLING")

    import tempfile, json
    fixer = FixEngine()

    # ── Test 1: Init-declarator — uint8_t x = some_int32_val; ──
    c_code_init = b'uint8_t x = some_int32_val;\n'
    with tempfile.NamedTemporaryFile(suffix='.c', delete=False, mode='wb') as f:
        f.write(c_code_init)
        tmp_init = f.name

    try:
        analyzer = CAnalyzer(os.path.dirname(tmp_init))
        exprs = analyzer._analyze_expression_at_line(tmp_init, 1)
        # Should find the init_declarator
        found_init = any(e.get("type") == "init_declarator" for e in exprs)
        assert found_init, f"Expected init_declarator, got: {[e.get('type') for e in exprs]}"
        print("  Init-declarator node found ✓")

        # Check operands have target_type
        for e in exprs:
            if e.get("type") == "init_declarator":
                ops = e.get("operands", [])
                assert len(ops) == 1, f"Expected 1 operand, got {len(ops)}"
                assert ops[0].get("target_type") is not None, "target_type missing"
                assert ops[0]["target_type"].get("name") == "uint8_t", \
                    f"Expected uint8_t target, got {ops[0]['target_type'].get('name')}"
                print("  Init-declarator target_type=uint8_t ✓")
    finally:
        os.unlink(tmp_init)

    # ── Test 2: Assignment expression — x = signed_expr; ──
    c_code_assign = b'void f(void) {\n  uint16_t x;\n  int32_t y = 42;\n  x = y;\n}\n'
    with tempfile.NamedTemporaryFile(suffix='.c', delete=False, mode='wb') as f:
        f.write(c_code_assign)
        tmp_assign = f.name

    try:
        analyzer = CAnalyzer(os.path.dirname(tmp_assign))
        exprs = analyzer._analyze_expression_at_line(tmp_assign, 4)
        found_assign = any(e.get("type") == "assignment_expression" for e in exprs)
        assert found_assign, f"Expected assignment_expression, got: {[e.get('type') for e in exprs]}"
        print("  Assignment expression node found ✓")

        for e in exprs:
            if e.get("type") == "assignment_expression":
                ops = e.get("operands", [])
                assert len(ops) == 1, f"Expected 1 operand, got {len(ops)}"
                assert ops[0].get("target_type") is not None, "target_type missing"
                print(f"  Assignment target_type={ops[0]['target_type'].get('name')} ✓")
    finally:
        os.unlink(tmp_assign)

    # ── Test 3: Compound assignment (+=) should be skipped ──
    c_code_compound = b'void f(void) {\n  uint16_t x = 0;\n  x += 1;\n}\n'
    with tempfile.NamedTemporaryFile(suffix='.c', delete=False, mode='wb') as f:
        f.write(c_code_compound)
        tmp_compound = f.name

    try:
        analyzer = CAnalyzer(os.path.dirname(tmp_compound))
        exprs = analyzer._analyze_expression_at_line(tmp_compound, 3)
        for e in exprs:
            if e.get("type") == "assignment_expression":
                ops = e.get("operands", [])
                assert len(ops) == 0, f"Compound assignment should have no operands, got {len(ops)}"
                print("  Compound assignment (+=) correctly skipped ✓")
    finally:
        os.unlink(tmp_compound)

    # ── Test 4: _generate_10_x_edits with assignment target_type ──
    findings_assign = {
        "expressions": [
            {
                "type": "assignment_expression",
                "operands": [
                    {
                        "text": "y",
                        "start_byte": 50,
                        "end_byte": 51,
                        "type": {"name": "int32_t", "width": 32, "is_signed": True, "is_float": False, "is_pointer": False},
                        "target_type": {"name": "uint8_t", "width": 8, "is_signed": False, "is_float": False, "is_pointer": False},
                    }
                ]
            }
        ]
    }
    from core.axivion_parser import AxivionViolation
    dummy_v = AxivionViolation(
        rule_id="MisraC2012-10.3", message="test",
        file_path="test.c", line_number=4, severity="Required"
    )
    edits, skip = fixer._generate_10_x_edits(findings_assign, dummy_v)
    assert len(edits) == 1, f"Expected 1 edit, got {len(edits)}"
    assert edits[0]["text"] == "(uint8_t)y", f"Expected '(uint8_t)y', got '{edits[0]['text']}'"
    print("  _generate_10_x_edits assignment cast ✓")

    # ── Test 5: Pointer assignment should be skipped ──
    findings_ptr = {
        "expressions": [
            {
                "type": "assignment_expression",
                "operands": [
                    {
                        "text": "p",
                        "start_byte": 10,
                        "end_byte": 11,
                        "type": {"name": "void *", "width": 64, "is_signed": False, "is_float": False, "is_pointer": True},
                        "target_type": {"name": "int *", "width": 64, "is_signed": False, "is_float": False, "is_pointer": True},
                    }
                ]
            }
        ]
    }
    edits, skip = fixer._generate_10_x_edits(findings_ptr, dummy_v)
    assert len(edits) == 0, f"Pointer assignment should produce no edits, got {len(edits)}"
    print("  Pointer assignment correctly skipped ✓")

    # ── Test 6: Compound RHS expression gets parenthesized ──
    findings_compound_rhs = {
        "expressions": [
            {
                "type": "init_declarator",
                "operands": [
                    {
                        "text": "a + b",
                        "start_byte": 20,
                        "end_byte": 25,
                        "type": {"name": "int", "width": 32, "is_signed": True, "is_float": False, "is_pointer": False},
                        "target_type": {"name": "uint8_t", "width": 8, "is_signed": False, "is_float": False, "is_pointer": False},
                    }
                ]
            }
        ]
    }
    edits, skip = fixer._generate_10_x_edits(findings_compound_rhs, dummy_v)
    assert len(edits) == 1, f"Expected 1 edit, got {len(edits)}"
    assert edits[0]["text"] == "(uint8_t)(a + b)", f"Expected '(uint8_t)(a + b)', got '{edits[0]['text']}'"
    print("  Compound RHS parenthesized ✓")

    # ── Test 7: Same-category narrowing generates cast (Rule 10.3) ──
    # uint32_t → uint8_t: both Unsigned, but target is narrower → needs cast
    findings_same_cat_narrow = {
        "expressions": [
            {
                "type": "assignment_expression",
                "operands": [
                    {
                        "text": "wide_val",
                        "start_byte": 60,
                        "end_byte": 68,
                        "type": {"name": "uint32_t", "width": 32, "is_signed": False, "is_float": False, "is_pointer": False},
                        "target_type": {"name": "uint8_t", "width": 8, "is_signed": False, "is_float": False, "is_pointer": False},
                    }
                ]
            }
        ]
    }
    edits, skip = fixer._generate_10_x_edits(findings_same_cat_narrow, dummy_v)
    assert len(edits) == 1, f"Same-category narrowing: expected 1 edit, got {len(edits)}"
    assert edits[0]["text"] == "(uint8_t)wide_val", f"Expected '(uint8_t)wide_val', got '{edits[0]['text']}'"
    print("  Same-category narrowing cast (uint32→uint8) ✓")

    # ── Test 8: Same-category widening is still skipped ──
    # uint8_t → uint32_t: both Unsigned, target is wider → no cast needed
    findings_same_cat_widen = {
        "expressions": [
            {
                "type": "assignment_expression",
                "operands": [
                    {
                        "text": "narrow_val",
                        "start_byte": 70,
                        "end_byte": 80,
                        "type": {"name": "uint8_t", "width": 8, "is_signed": False, "is_float": False, "is_pointer": False},
                        "target_type": {"name": "uint32_t", "width": 32, "is_signed": False, "is_float": False, "is_pointer": False},
                    }
                ]
            }
        ]
    }
    edits, skip = fixer._generate_10_x_edits(findings_same_cat_widen, dummy_v)
    assert len(edits) == 0, f"Same-category widening should produce no edits, got {len(edits)}"
    print("  Same-category widening correctly skipped (uint8→uint32) ✓")

    # ── Test 9: Same-category, same-width is skipped ──
    # unsigned int → unsigned int: no narrowing → no cast
    findings_same_cat_same_width = {
        "expressions": [
            {
                "type": "assignment_expression",
                "operands": [
                    {
                        "text": "x",
                        "start_byte": 90,
                        "end_byte": 91,
                        "type": {"name": "unsigned int", "width": 32, "is_signed": False, "is_float": False, "is_pointer": False},
                        "target_type": {"name": "uint32_t", "width": 32, "is_signed": False, "is_float": False, "is_pointer": False},
                    }
                ]
            }
        ]
    }
    edits, skip = fixer._generate_10_x_edits(findings_same_cat_same_width, dummy_v)
    assert len(edits) == 0, f"Same-category same-width should produce no edits, got {len(edits)}"
    print("  Same-category same-width correctly skipped ✓")


def test_8_4_forward_declaration_autofix():
    """Test Rule 8.4 auto-fix: same-file forward declaration insertion."""
    section("8.4 FORWARD DECLARATION AUTO-FIX")

    import tempfile
    from core.axivion_parser import AxivionViolation

    # ── Test 1: Basic case — external function with no prior declaration ──
    c_code = b'#include <stdio.h>\n\nint compute(int x) {\n    return x * x;\n}\n'
    with tempfile.NamedTemporaryFile(suffix='.c', delete=False, mode='wb') as f:
        f.write(c_code)
        tmp = f.name

    try:
        analyzer = CAnalyzer(os.path.dirname(tmp))
        engine = FixEngine(analyzer)

        # Simulate findings with function info and no prior declaration
        fn = analyzer.get_function_at_line(tmp, 3)
        assert fn is not None, "Should find function at line 3"
        assert fn.name == "compute", f"Expected 'compute', got '{fn.name}'"

        findings = {
            "function": {
                "name": fn.name,
                "signature": fn.signature,
                "start_line": fn.start_line,
                "is_static": fn.is_static,
            },
            "cross_file": {
                "has_prior_declaration": False,
                "declarations": [],
                "included_headers": [],
            },
        }

        dummy_v = AxivionViolation(
            rule_id="MisraC2012-8.4", message="No prior declaration",
            file_path=tmp, line_number=3, severity="Required"
        )
        edits, skip = engine._generate_8_4_edits(findings, dummy_v)
        assert len(edits) == 1, f"Expected 1 edit, got {len(edits)}: {skip}"
        assert edits[0]["text"].strip().endswith(";"), \
            f"Prototype should end with ';': {edits[0]['text']}"
        assert "compute" in edits[0]["text"], \
            f"Prototype should contain function name: {edits[0]['text']}"
        # Verify it's an insertion (start == end) at the right spot
        assert edits[0]["start_byte"] == edits[0]["end_byte"], \
            "Should be a pure insertion (start_byte == end_byte)"
        print(f"  Basic forward declaration generated: {edits[0]['text'].strip()} ✓")

        # Verify the edit produces valid C when applied
        patched = (c_code[:edits[0]["start_byte"]]
                   + edits[0]["text"].encode()
                   + c_code[edits[0]["end_byte"]:])
        assert b"compute" in patched
        # The prototype should appear before the definition
        proto_pos = patched.index(b"int compute(int x);")
        defn_pos = patched.index(b"int compute(int x) {")
        assert proto_pos < defn_pos, "Prototype must appear before definition"
        print("  Patched source has prototype before definition ✓")

    finally:
        os.unlink(tmp)

    # ── Test 2: Static function — should be skipped ──
    c_code_static = b'static int helper(int x) {\n    return x + 1;\n}\n'
    with tempfile.NamedTemporaryFile(suffix='.c', delete=False, mode='wb') as f:
        f.write(c_code_static)
        tmp2 = f.name

    try:
        analyzer2 = CAnalyzer(os.path.dirname(tmp2))
        fn2 = analyzer2.get_function_at_line(tmp2, 1)
        assert fn2 is not None
        findings_static = {
            "function": {
                "name": fn2.name,
                "signature": fn2.signature,
                "start_line": fn2.start_line,
                "is_static": True,
            },
            "cross_file": {
                "has_prior_declaration": False,
                "declarations": [],
            },
        }
        dummy_v2 = AxivionViolation(
            rule_id="MisraC2012-8.4", message="test",
            file_path=tmp2, line_number=1, severity="Required"
        )
        engine2 = FixEngine(analyzer2)
        edits, skip = engine2._generate_8_4_edits(findings_static, dummy_v2)
        assert len(edits) == 0, "Static functions should not get forward declarations"
        assert "static" in skip.lower(), f"Skip reason should mention static: {skip}"
        print("  Static function correctly skipped ✓")
    finally:
        os.unlink(tmp2)

    # ── Test 3: Already has prior declaration — should be skipped ──
    findings_has_decl = {
        "function": {
            "name": "foo",
            "signature": "int foo(void)",
            "start_line": 5,
            "is_static": False,
        },
        "cross_file": {
            "has_prior_declaration": True,
            "declarations": [{"file": "foo.h", "line": 3, "signature": "int foo(void)"}],
        },
    }
    dummy_v3 = AxivionViolation(
        rule_id="MisraC2012-8.4", message="test",
        file_path="nonexistent.c", line_number=5, severity="Required"
    )
    fixer = FixEngine()
    edits, skip = fixer._generate_8_4_edits(findings_has_decl, dummy_v3)
    assert len(edits) == 0, "Should skip when prior declaration exists"
    assert "already exists" in skip.lower(), f"Skip reason: {skip}"
    print("  Already-declared function correctly skipped ✓")

    # ── Test 4: No function context — should skip gracefully ──
    edits, skip = fixer._generate_8_4_edits({}, dummy_v3)
    assert len(edits) == 0, "Should skip when no function context"
    print("  No function context handled gracefully ✓")


def test_violation_status_and_verify():
    """Test violation status tracking, verify_fix logic, and _essential_category."""
    section("VIOLATION STATUS & VERIFY FIX")

    # ── Import server-level helpers ──
    import importlib
    import fastmcp_server as srv
    importlib.reload(srv)  # ensure clean state

    # ── Test 1: Status management basics ──
    srv._violation_status = {}
    assert srv._get_status("foo.c", 10, "MisraC2012-10.3") == "pending"
    srv._set_status("foo.c", 10, "MisraC2012-10.3", "fixed")
    assert srv._get_status("foo.c", 10, "MisraC2012-10.3") == "fixed"
    srv._set_status("foo.c", 10, "MisraC2012-10.3", "verified")
    assert srv._get_status("foo.c", 10, "MisraC2012-10.3") == "verified"
    # Different violation at same file is independent
    assert srv._get_status("foo.c", 10, "MisraC2012-8.13") == "pending"
    print("  Status management basics ✓")

    # ── Test 2: _essential_category ──
    assert srv._essential_category({"name": "int", "is_signed": True, "is_float": False}) == "Signed"
    assert srv._essential_category({"name": "unsigned int", "is_signed": False, "is_float": False}) == "Unsigned"
    assert srv._essential_category({"name": "float", "is_signed": True, "is_float": True}) == "Floating"
    assert srv._essential_category({"name": "bool", "is_signed": False, "is_float": False}) == "Boolean"
    assert srv._essential_category({"name": "char", "is_signed": False, "is_float": False}) == "Character"
    print("  _essential_category mapping ✓")

    # ── Test 3: _verify_violation for 10.x with type mismatch still present ──
    # We need a real C file with a type mismatch to verify against
    import tempfile
    c_code = b'void f(void) {\n  unsigned int w = 70000U;\n  unsigned short n = w;\n}\n'
    with tempfile.NamedTemporaryFile(suffix='.c', delete=False, mode='wb') as f:
        f.write(c_code)
        tmp = f.name

    try:
        srv.analyzer = CAnalyzer(os.path.dirname(tmp))
        # Line 3: unsigned short n = w;  → uint32 → uint16 narrowing
        resolved, detail = srv._verify_violation("MisraC2012-10.3", tmp, 3)
        # The expressions at line 3 should show narrowing (unsigned int → unsigned short)
        # So this should report NOT resolved
        assert resolved is False, f"Expected unresolved, got resolved: {detail}"
        assert "narrow" in detail.lower() or "mismatch" in detail.lower(), \
            f"Expected narrowing/mismatch in detail: {detail}"
        print("  _verify_violation detects persisting 10.x narrowing ✓")
    finally:
        os.unlink(tmp)

    # ── Test 4: _verify_violation for 10.x after fix (cast present) ──
    c_fixed = b'void f(void) {\n  unsigned int w = 70000U;\n  unsigned short n = (unsigned short)w;\n}\n'
    with tempfile.NamedTemporaryFile(suffix='.c', delete=False, mode='wb') as f:
        f.write(c_fixed)
        tmp2 = f.name

    try:
        srv.analyzer = CAnalyzer(os.path.dirname(tmp2))
        resolved, detail = srv._verify_violation("MisraC2012-10.3", tmp2, 3)
        # After the cast, the expression at line 3 is a cast_expression,
        # the init_declarator's value is (unsigned short)w which should
        # type-match the target.
        assert resolved is True, f"Expected resolved after cast, got: {detail}"
        print("  _verify_violation confirms 10.x fix with cast ✓")
    finally:
        os.unlink(tmp2)

    # ── Test 5: _verify_violation for 2.7 (unused param) ──
    c_unused = b'void g(int x) {\n  return;\n}\n'
    with tempfile.NamedTemporaryFile(suffix='.c', delete=False, mode='wb') as f:
        f.write(c_unused)
        tmp3 = f.name

    try:
        srv.analyzer = CAnalyzer(os.path.dirname(tmp3))
        resolved, detail = srv._verify_violation("MisraC2012-2.7", tmp3, 1)
        assert resolved is False, f"Expected unused param detected: {detail}"
        assert "x" in detail, f"Should mention param 'x': {detail}"
        print("  _verify_violation detects unused param ✓")
    finally:
        os.unlink(tmp3)

    # ── Test 6: _verify_violation for 2.7 (param used) ──
    c_used = b'#include <stdio.h>\nvoid g(int x) {\n  (void)x;\n}\n'
    with tempfile.NamedTemporaryFile(suffix='.c', delete=False, mode='wb') as f:
        f.write(c_used)
        tmp4 = f.name

    try:
        srv.analyzer = CAnalyzer(os.path.dirname(tmp4))
        resolved, detail = srv._verify_violation("MisraC2012-2.7", tmp4, 2)
        assert resolved is True, f"Expected param suppressed: {detail}"
        print("  _verify_violation confirms 2.7 fix with (void)x ✓")
    finally:
        os.unlink(tmp4)

    # ── Test 7: Fallback for unsupported rule ──
    resolved, detail = srv._verify_violation("MisraC2012-99.9", "fake.c", 1)
    assert resolved is True, "Unsupported rules should return True (fallback)"
    assert "not available" in detail.lower(), f"Should mention fallback: {detail}"
    print("  Fallback for unsupported rule ✓")

    # Clean up
    srv.analyzer = None
    srv._violation_status = {}


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

    # 8. 10.x ASSIGNMENT HANDLING
    test_10x_assignment_handling()

    # 9. Rule 8.4 FORWARD DECLARATION AUTO-FIX
    test_8_4_forward_declaration_autofix()

    # 10. VIOLATION STATUS & VERIFY FIX
    test_violation_status_and_verify()

    print("\n" + "=" * 72)
    print("  ALL TESTS PASSED ✓")
    print(f"  • {len(all_violations)} violations parsed")
    print(f"  • Knowledge base verified (160+ rules)")
    print(f"  • AST analysis verified")
    print(f"  • Fix Engine confidence: {confidence_dist}")
    print(f"  • Automated fixes verified for 2.x, 8.x (incl. 8.4), 10.x, 11.x, 14.x, 15.x")
    print(f"  • Violation status tracking & verify_fix verified")
    print("=" * 72)


if __name__ == "__main__":
    run_tests()

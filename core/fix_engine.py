"""
MISRA Fix Engine — AST-aware redesign.

Instead of applying regex patches (context-blind), the engine:
  1. Uses CAnalyzer to parse the file into an AST
  2. Extracts deep structural context (function body, param usage,
     pointer writes, scope, reachability, type info)
  3. Combines the AST analysis with MISRA domain knowledge
  4. Outputs a rich FixAnalysis that the LLM (Copilot) uses to
     generate the actual code change

Design principle:  **The LLM is the fixer — our job is deep context.**
"""

import re
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

from core.misra_knowledge_base import get_rule, MisraRule
from core.axivion_parser import AxivionViolation
from core.c_analyzer import CAnalyzer
from core.context_provider import ContextProvider


# ═══════════════════════════════════════════════════════════════════════
#  Output data type
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class FixAnalysis:
    """Rich, structured analysis for the LLM to generate the actual fix."""
    rule_id: str
    confidence: str                    # HIGH / MEDIUM / LOW
    violation_line: str                # the flagged line of code
    function_context: str              # full function body (or surrounding context)
    ast_findings: Dict                 # structured AST analysis results
    rule_explanation: str              # from the knowledge base
    fix_guidance: str                  # what the LLM should do
    compliant_example: str             # from the knowledge base
    non_compliant_example: str         # from the knowledge base
    side_effects: List[str] = field(default_factory=list)
    edits: List[Dict[str, Any]] = field(default_factory=list)  # [{start, end, text}]
    edit_skip_reason: str = ""  # explains why auto-fix was not generated

    def to_markdown(self) -> str:
        md = f"### Fix Analysis — {self.rule_id}\n"
        md += f"**Confidence**: {self.confidence}\n\n"

        # Violation line
        md += "#### Violation Line\n```c\n"
        md += self.violation_line.rstrip() + "\n```\n\n"

        # AST findings
        md += "#### AST Analysis\n"
        md += self._format_findings() + "\n"

        # Edits (if avaiable)
        if self.edits:
            md += "#### 🛠️ Suggested Fix (Auto-Apply Available)\n"
            for edit in self.edits:
                md += f"- Insert/Replace at offset {edit['start_byte']}: `{edit['text']}`\n"
            md += "\n"

        # Function context
        if self.function_context:
            md += "#### Function Context\n```c\n"
            md += self.function_context.rstrip() + "\n```\n\n"

        # Fix guidance
        md += "#### Fix Guidance\n"
        md += self.fix_guidance + "\n\n"

        # Examples
        if self.compliant_example:
            md += "#### Compliant Example\n```c\n"
            md += self.compliant_example.rstrip() + "\n```\n\n"

        # Side effects
        if self.side_effects:
            md += "#### ⚠ Potential Side Effects\n"
            for se in self.side_effects:
                md += f"- {se}\n"

        return md

    def _format_findings(self) -> str:
        """Format AST findings into readable markdown."""
        lines = []

        # Macro specific analysis
        if self.ast_findings.get("macro_analysis"):
            lines.append("- **Macro Analysis**: definition parsed as expression.")
            ma = self.ast_findings["macro_analysis"]
            lines.append(f"  - Body structure: `{ma.get('type')}`")

        # Function info
        fn = self.ast_findings.get("function")
        if fn:
            lines.append(f"- **Function**: `{fn.get('signature', fn.get('name', '?'))}`")
            lines.append(f"  - Lines {fn.get('start_line', '?')}–{fn.get('end_line', '?')} "
                        f"({fn.get('body_lines', '?')} lines)")
            if fn.get("is_static"):
                lines.append("  - Storage: `static`")
            if fn.get("is_inline"):
                lines.append("  - Qualifier: `inline`")

        # Parameter analysis
        params = self.ast_findings.get("params", [])
        if params:
            lines.append("- **Parameters**:")
            for p in params:
                status = []
                if p.get("is_pointer"):
                    status.append("pointer")
                status.append(f"reads={p.get('read_count', 0)}")
                status.append(f"writes={p.get('write_count', 0)}")
                if p.get("unused"):
                    status.append("**UNUSED**")
                lines.append(f"  - `{p['name']}` ({p.get('type', '?')}): {', '.join(status)}")
                if p.get("read_lines"):
                    lines.append(f"    - Read on lines: {p['read_lines']}")
                if p.get("write_lines"):
                    lines.append(f"    - Written on lines: {p['write_lines']}")

        # Const candidates (8.13)
        candidates = self.ast_findings.get("const_candidates", [])
        if candidates:
            lines.append("- **Const analysis**:")
            for c in candidates:
                safe = "✅ safe to add `const`" if c.get("safe_to_add_const") else "❌ written through"
                lines.append(f"  - `{c['name']}` ({c.get('type', '?')}): "
                           f"reads={c.get('reads', 0)}, writes={c.get('writes', 0)} → {safe}")

        # Unused params (2.7)
        unused = self.ast_findings.get("unused_params", [])
        if unused:
            lines.append(f"- **Unused parameters**: `{'`, `'.join(unused)}`")

        # Unreachable reason (2.1)
        reason = self.ast_findings.get("unreachable_reason")
        if reason:
            lines.append(f"- **Unreachable**: {reason}")

        # Needs static (8.10)
        if self.ast_findings.get("needs_static"):
            lines.append("- **`inline` without `static`**: function has external linkage, "
                        "which is undefined behaviour if called from another TU")

        # Enum collisions (8.12)
        collisions = self.ast_findings.get("enum_collisions", {})
        if collisions:
            lines.append("- **Enum value collisions**:")
            for val, names in collisions.items():
                lines.append(f"  - Value {val}: `{'`, `'.join(names)}`")

        # Symbol scope
        scope = self.ast_findings.get("symbol_scope")
        if scope:
            lines.append(f"- **Symbol scope**: `{scope}`")

        # Declarations
        decls = self.ast_findings.get("declarations", [])
        if decls:
            lines.append(f"- **Declarations found**: {len(decls)}")
            for d in decls[:5]:
                kind = "definition" if d.get("is_definition") else "declaration"
                lines.append(f"  - Line {d['line']} ({kind}): `{d.get('context', '').strip()}`")

        # ── Cross-file evidence ──
        cross = self.ast_findings.get("cross_file", {})
        if cross:
            lines.append("- **Cross-file analysis**:")

            # 8.3: declaration vs definition diff
            if cross.get("mismatches"):
                lines.append("  - **Signature mismatches:**")
                for m in cross["mismatches"]:
                    lines.append(f"    - {m}")
                if cross.get("declaration"):
                    d = cross["declaration"]
                    lines.append(f"  - Declaration: `{d['file']}:{d['line']}` → `{d['signature']}`")
                if cross.get("definition"):
                    d = cross["definition"]
                    lines.append(f"  - Definition:  `{d['file']}:{d['line']}` → `{d['signature']}`")

            # 8.4: prior declaration search
            if "has_prior_declaration" in cross:
                if cross["has_prior_declaration"]:
                    for d in cross.get("declarations", []):
                        lines.append(f"  - Prototype in `{d['file']}:{d['line']}`")
                else:
                    lines.append("  - ⚠ No prototype found in any included header")

            # 8.5: duplicate extern
            if cross.get("has_duplicates"):
                lines.append("  - ⚠ Duplicate extern declarations:")
                for loc in cross.get("extern_locations", []):
                    lines.append(f"    - `{loc['file']}:{loc['line']}`")

            # 8.6: multiple definitions
            if cross.get("has_multiple_definitions"):
                lines.append("  - ⚠ Multiple definitions:")
                for loc in cross.get("definitions", []):
                    lines.append(f"    - `{loc['file']}:{loc['line']}`")

            # 8.8: external callers
            if "safe_to_add_static" in cross:
                if cross["safe_to_add_static"]:
                    lines.append("  - ✅ No external callers — safe to add `static`")
                else:
                    lines.append("  - ❌ Cannot add `static` — external callers exist:")
                    for c in cross.get("external_callers", [])[:5]:
                        lines.append(f"    - `{c['file']}:{c['line']}` in `{c['calling_function']}`")
                    if cross.get("declared_in_header"):
                        lines.append(f"  - Declared in header: `{cross['declared_in_header']}`")

            # 8.13: caller impact
            if cross.get("total_callers") is not None:
                total = cross["total_callers"]
                lines.append(f"  - **Callers to update**: {total}")
                for c in cross.get("callers", [])[:5]:
                    lines.append(f"    - `{c['file']}:{c['line']}` in `{c['calling_function']}`")
                if cross.get("header_to_update"):
                    lines.append(f"  - Header to update: `{cross['header_to_update']}`")
                affected = cross.get("files_affected", [])
                if affected:
                    lines.append(f"  - Files affected: {', '.join(f'`{f}`' for f in affected)}")

        if not lines:
            lines.append("- No additional AST analysis available for this rule.")

        return "\n".join(lines)


# Rules where the fix may affect other files / callers
_CROSS_FILE_RULES = {
    "MisraC2012-8.3", "MisraC2012-8.4", "MisraC2012-8.5",
    "MisraC2012-8.6", "MisraC2012-8.8", "MisraC2012-8.9",
    "MisraC2012-8.11", "MisraC2012-8.13", "MisraC2012-8.14",
}


# ═══════════════════════════════════════════════════════════════════════
#  Engine
# ═══════════════════════════════════════════════════════════════════════

class FixEngine:
    """Generates rich, AST-informed fix analyses for MISRA violations."""

    def __init__(self, analyzer: Optional[CAnalyzer] = None, context_provider: Optional[ContextProvider] = None):
        self.analyzer = analyzer
        self.context_provider = context_provider

    def propose_fix(
        self,
        violation: AxivionViolation,
        code_context: str,
        violation_line: str,
        dependencies: Optional[List[str]] = None,
    ) -> FixAnalysis:
        """
        Produce a FixAnalysis for the given violation.

        Uses the CAnalyzer for AST-level understanding when available,
        falls back to text-based heuristics otherwise.
        """
        rule = get_rule(violation.rule_id)

        # AST analysis
        ast_findings = {}
        function_context = ""
        if self.analyzer:
            try:
                ast_findings = self.analyzer.analyze_for_rule(
                    violation.file_path, violation.line_number, violation.rule_id
                )
                # Get full function body for context
                fn = self.analyzer.get_function_at_line(
                    violation.file_path, violation.line_number
                )
                if fn:
                    function_context = fn.signature + " " + fn.body_text
            except Exception as e:
                ast_findings = {"error": str(e)}

        if rule is None:
            return self._unknown_rule(violation, violation_line, ast_findings, function_context)

        # Determine confidence based on AST depth
        confidence = self._rate_confidence(rule, ast_findings)

        # Generate rule-specific guidance
        guidance = self._generate_guidance(rule, violation, ast_findings)

        # Determine side effects
        side_effects = self._assess_side_effects(rule, ast_findings, dependencies)
        
        # Generate concrete edits (returns edits + reason if skipped)
        edits, edit_skip_reason = self._generate_edits(rule, ast_findings, violation)

        return FixAnalysis(
            rule_id=rule.rule_id,
            confidence=confidence,
            violation_line=violation_line.rstrip() if violation_line else "",
            function_context=function_context,
            ast_findings=ast_findings,
            rule_explanation=rule.rationale,
            fix_guidance=guidance,
            compliant_example=rule.compliant,
            non_compliant_example=rule.non_compliant,
            side_effects=side_effects,
            edits=edits,
            edit_skip_reason=edit_skip_reason,
        )

    # ────────────────────────────────────────────────────────────────
    #  Concrete Edit Generation
    # ────────────────────────────────────────────────────────────────
    
    # ────────────────────────────────────────────────────────────────
    #  Typed return for edit generation
    # ────────────────────────────────────────────────────────────────

    # Every _generate_* helper returns (edits, skip_reason).
    # - edits non-empty  → auto-fix available, skip_reason is ""
    # - edits empty       → skip_reason explains WHY (never silent)

    _EditResult = tuple  # (List[Dict], str)

    _NO_ANALYZER = ([], "AST analyzer unavailable; cannot produce byte-level edits.")

    def _generate_edits(self, rule: MisraRule, findings: Dict,
                        violation: AxivionViolation) -> "tuple[List[Dict], str]":
        """Generate machine-readable code edits (start_byte, end_byte, text).

        Returns (edits, skip_reason).  When edits is empty, skip_reason is
        a human-readable explanation of why auto-fix was not generated.
        """
        rid = rule.rule_id

        # ── Rule 2.x — Unused Code ──────────────────────────────────
        if rid == "MisraC2012-2.1":
            return self._generate_2_1_edits(findings, violation)
        if rid == "MisraC2012-2.2":
            return ([], "Rule 2.2 (dead code) requires dataflow analysis to "
                        "confirm the expression has no side effects. "
                        "Blind deletion risks removing code with "
                        "observable behaviour (volatile reads, I/O calls). "
                        "Manual review required.")
        if rid in ("MisraC2012-2.3", "MisraC2012-2.4"):
            return self._generate_2_3_4_edits(findings, violation)
        if rid == "MisraC2012-2.5":
            return self._generate_2_5_edits(violation)
        if rid == "MisraC2012-2.6":
            return self._generate_2_6_edits(violation)
        if rid == "MisraC2012-2.7":
            return self._generate_2_7_edits(findings, violation)

        # ── Rule 8.x — Declarations & Definitions ───────────────────
        if rid == "MisraC2012-8.1":
            return ([], "Rule 8.1 (implicit types) requires semantic "
                        "knowledge of the intended type. The correct type "
                        "depends on the programmer's intent — no safe default "
                        "exists.")
        if rid == "MisraC2012-8.2":
            return self._generate_8_2_edits(findings, violation)
        if rid == "MisraC2012-8.3":
            return ([], "Rule 8.3 (compatible declarations) requires "
                        "cross-file analysis to identify which declaration is "
                        "canonical. Changing the wrong one breaks the API.")
        if rid == "MisraC2012-8.4":
            return ([], "Rule 8.4 (visible prior declaration) requires "
                        "adding a prototype in a header file. The choice of "
                        "which header to modify depends on the project's "
                        "include structure.")
        if rid == "MisraC2012-8.5":
            return ([], "Rule 8.5 (external declaration in one file) "
                        "requires moving declarations between files. "
                        "Automated move risks breaking include order or "
                        "creating circular dependencies.")
        if rid == "MisraC2012-8.6":
            return ([], "Rule 8.6 (one external definition) is a linker-"
                        "level issue requiring analysis of all translation "
                        "units. Cannot determine which definition to keep "
                        "from a single file.")
        if rid == "MisraC2012-8.7":
            return ([], "Rule 8.7 (no block-scope extern) requires moving "
                        "the extern declaration to file scope and verifying "
                        "no other block-scope references exist. Manual "
                        "restructuring recommended.")
        if rid == "MisraC2012-8.8":
            return self._generate_8_8_edits(findings, violation)
        if rid == "MisraC2012-8.9":
            return ([], "Rule 8.9 (define at block scope) requires moving "
                        "a file-scope variable into a function body. This "
                        "changes object lifetime and may break other "
                        "references within the translation unit.")
        if rid == "MisraC2012-8.10":
            return self._generate_8_10_edits(findings, violation)
        if rid == "MisraC2012-8.11":
            return ([], "Rule 8.11 (explicit array size) requires knowing "
                        "the intended array size, which depends on the "
                        "definition in another translation unit.")
        if rid == "MisraC2012-8.12":
            return self._generate_8_12_edits(findings, violation)
        if rid == "MisraC2012-8.13":
            return self._generate_8_13_edits(findings, violation)
        if rid == "MisraC2012-8.14":
            return self._generate_8_14_edits(violation)

        # ── Rule 10.x — Essential Type Model ────────────────────────
        if rid == "MisraC2012-10.5":
            return ([], "Rule 10.5 prohibits inappropriate casts. "
                        "Adding a cast would violate this rule — the fix "
                        "is to remove the existing cast or change the "
                        "destination type. Manual review required.")
        if rid.startswith("MisraC2012-10."):
            return self._generate_10_x_edits(findings, violation)

        if rid == "MisraC2012-11.9":
            return self._generate_11_9_edits(findings)
        if rid == "MisraC2012-14.4":
            return self._generate_14_4_edits(findings)
        if rid == "MisraC2012-15.6":
            return self._generate_15_6_edits(findings, violation)

        return ([], "")

    # ────────────────────────────────────────────────────────────────
    #  Shared helpers
    # ────────────────────────────────────────────────────────────────

    def _get_source_bytes(self, file_path: str) -> Optional[bytes]:
        """Read source bytes via the analyzer cache or directly."""
        if self.analyzer:
            source, _ = self.analyzer._get_tree(file_path)
            return source
        return None

    def _line_byte_range(self, source: bytes, line: int):
        """Return (start_byte, end_byte) for a 1-indexed line, including newline."""
        lines = source.split(b"\n")
        if line < 1 or line > len(lines):
            return None, None
        offset = sum(len(lines[i]) + 1 for i in range(line - 1))
        end = offset + len(lines[line - 1])
        # Include the trailing newline if present
        if end < len(source) and source[end:end + 1] == b"\n":
            end += 1
        return offset, end

    # ────────────────────────────────────────────────────────────────
    #  Edit generators — Rule 2.x (Unused Code)
    # ────────────────────────────────────────────────────────────────

    def _generate_2_1_edits(self, findings: Dict,
                            violation: AxivionViolation
                            ) -> "tuple[List[Dict], str]":
        """Rule 2.1: Unreachable code.

        Only auto-fix when the AST confirms the exact reason (e.g. code
        after an unconditional return/break/continue/goto).

        Removes ALL unreachable statements in the same block after the
        terminal statement, not just the single flagged line.  This
        prevents cascading 2.1 violations on the remaining lines.
        """
        reason = findings.get("unreachable_reason")
        if not reason:
            return ([], "Cannot confirm unreachability from AST alone. "
                        "The code may be reachable through indirect jumps, "
                        "setjmp/longjmp, or signal handlers. "
                        "Manual control-flow review needed.")

        source = self._get_source_bytes(violation.file_path)
        if source is None:
            return self._NO_ANALYZER

        # Try to determine the full unreachable range using AST
        unreachable_range = findings.get("unreachable_range")
        if unreachable_range:
            # AST gave us the exact (start_line, end_line) of the
            # unreachable block
            first = unreachable_range["start_line"]
            last = unreachable_range["end_line"]
            start, _ = self._line_byte_range(source, first)
            _, end = self._line_byte_range(source, last)
            if start is not None and end is not None:
                return ([{"start_byte": start, "end_byte": end, "text": ""}], "")

        # Fallback: scan forward from the flagged line to find the end of
        # the unreachable block (up to the closing brace of the enclosing
        # compound statement)
        raw_lines = source.split(b"\n")
        viol_line = violation.line_number
        start, _ = self._line_byte_range(source, viol_line)
        if start is None:
            return ([], "Could not resolve violation line in source.")

        # Scan forward: include all lines until we hit a line that's a
        # closing brace, a label, a case, or a preprocessor directive
        end_ln = viol_line
        for i in range(viol_line - 1, len(raw_lines)):
            text = raw_lines[i].decode("utf-8", errors="replace").strip()
            # Stop before closing brace or scope-ending constructs
            if text == "}" or text.startswith("case ") or text.startswith("default:"):
                break
            # Stop before labels (could be a goto target making code reachable)
            if re.match(r'^\w+\s*:', text) and not text.startswith("default"):
                break
            # Stop before preprocessor directives
            if text.startswith("#"):
                break
            end_ln = i + 1  # 1-indexed

        _, end = self._line_byte_range(source, end_ln)
        if end is None:
            end = start  # fallback to single line
            _, end = self._line_byte_range(source, viol_line)
            if end is None:
                return ([], "Could not compute byte range for unreachable block.")

        return ([{"start_byte": start, "end_byte": end, "text": ""}], "")

    def _generate_2_3_4_edits(self, findings: Dict,
                              violation: AxivionViolation
                              ) -> "tuple[List[Dict], str]":
        """Rule 2.3/2.4: Unused type/tag declaration.

        Multi-line structs, unions, and enums cannot be safely removed by
        deleting a single line.  Only remove single-line typedefs.
        """
        source = self._get_source_bytes(violation.file_path)
        if source is None:
            return self._NO_ANALYZER
        start, end = self._line_byte_range(source, violation.line_number)
        if start is None:
            return ([], "Could not resolve violation line in source.")
        line_text = source[start:end].decode("utf-8", errors="replace").strip()
        # Single-line typedef: "typedef int mytype;" — safe to remove
        if line_text.startswith("typedef") and line_text.endswith(";"):
            return ([{"start_byte": start, "end_byte": end, "text": ""}], "")
        # Multi-line struct/union/enum — refuse
        return ([], f"Declaration may span multiple lines "
                    f"(detected: `{line_text[:60]}…`). "
                    f"Removing only the flagged line would leave a syntax "
                    f"error. Identify the full declaration boundary and "
                    f"remove the entire block.")

    def _generate_2_5_edits(self, violation: AxivionViolation
                            ) -> "tuple[List[Dict], str]":
        """Rule 2.5: Unused macro (#define).

        Handles backslash-continued multi-line macros by scanning
        forward until a line does NOT end with '\\'.
        """
        source = self._get_source_bytes(violation.file_path)
        if source is None:
            return self._NO_ANALYZER
        raw_lines = source.split(b"\n")
        ln = violation.line_number
        if ln < 1 or ln > len(raw_lines):
            return ([], "Could not resolve violation line in source.")
        # Verify it actually IS a #define (not #ifdef, #include, etc.)
        first_line = raw_lines[ln - 1].decode("utf-8", errors="replace").strip()
        if not re.match(r'^#\s*define\b', first_line):
            return ([], f"Line {ln} is not a `#define` directive "
                        f"(`{first_line[:40]}…`). Cannot safely delete.")
        # Scan for continuation lines (trailing backslash)
        end_ln = ln
        while end_ln <= len(raw_lines):
            text = raw_lines[end_ln - 1].decode("utf-8", errors="replace").rstrip()
            if not text.endswith("\\"):
                break
            end_ln += 1
        start, _ = self._line_byte_range(source, ln)
        _, end = self._line_byte_range(source, end_ln)
        if start is None or end is None:
            return ([], "Could not compute byte range for macro.")
        return ([{"start_byte": start, "end_byte": end, "text": ""}], "")

    def _generate_2_6_edits(self, violation: AxivionViolation
                            ) -> "tuple[List[Dict], str]":
        """Rule 2.6: Unused label.

        Handles two forms:
        - Standalone label line ('cleanup:')  → delete entire line
        - Label prefixing a statement ('retry: x++;')  → strip label only
        """
        source = self._get_source_bytes(violation.file_path)
        if source is None:
            return self._NO_ANALYZER
        start, end = self._line_byte_range(source, violation.line_number)
        if start is None:
            return ([], "Could not resolve violation line in source.")
        line_text = source[start:end].decode("utf-8", errors="replace")
        stripped = line_text.strip()
        # Standalone label line
        if re.match(r'^\w+\s*:\s*$', stripped):
            return ([{"start_byte": start, "end_byte": end, "text": ""}], "")
        # Label prefixing code — remove just the label portion
        m = re.match(r'^(\s*)\w+\s*:\s*', line_text)
        if m:
            label_end = start + len(m.group(0).encode("utf-8"))
            indent = m.group(1)
            return ([{"start_byte": start, "end_byte": label_end,
                       "text": indent}], "")
        return ([], f"Could not isolate the label on line {violation.line_number}. "
                    f"The label may be embedded in a complex expression.")

    def _generate_2_7_edits(self, findings: Dict,
                            violation: AxivionViolation
                            ) -> "tuple[List[Dict], str]":
        """Rule 2.7: Unused parameter — insert (void)param; statements.

        Only generates edits when the AST confirms specific parameter
        names are unused throughout the function body.

        Idempotency: checks if (void)param; already exists in the body.
        """
        unused = findings.get("unused_params", [])
        if not unused:
            return ([], "AST did not identify any confirmed-unused "
                        "parameters. The parameter may be used in a macro "
                        "expansion or via a pointer alias.")
        source = self._get_source_bytes(violation.file_path)
        if source is None:
            return self._NO_ANALYZER
        source_text = source.decode("utf-8", errors="replace")

        # Idempotency: check if (void)param; already exists in the function
        fn_info = findings.get("function", {})
        body_text = ""
        if fn_info:
            start_line = fn_info.get("start_line", violation.line_number)
            end_line = fn_info.get("end_line", violation.line_number)
            lines = source_text.splitlines()
            body_text = "\n".join(lines[start_line - 1:end_line])

        truly_missing = []
        already_present = []
        for p in unused:
            if f"(void){p};" in body_text:
                already_present.append(p)
            else:
                truly_missing.append(p)

        if not truly_missing:
            return ([], f"All (void) casts already present for: "
                        f"{', '.join(already_present)}. Fix already applied.")

        # Locate the opening brace of the function body
        start_line = fn_info.get("start_line", violation.line_number)
        raw_lines = source.split(b"\n")
        brace_byte = None
        offset = sum(len(raw_lines[i]) + 1 for i in range(start_line - 1))
        for i in range(start_line - 1, min(start_line + 10, len(raw_lines))):
            pos = raw_lines[i].find(b"{")
            if pos >= 0:
                brace_byte = offset + pos + 1  # byte after '{'
                break
            offset += len(raw_lines[i]) + 1
        if brace_byte is None:
            return ([], "Could not locate the function body opening brace. "
                        "The function signature may span too many lines.")

        # Detect indentation from the first line after the brace
        indent = "    "  # default 4-space
        brace_line_idx = None
        for i in range(start_line - 1, min(start_line + 10, len(raw_lines))):
            if b"{" in raw_lines[i]:
                brace_line_idx = i
                break
        if brace_line_idx is not None and brace_line_idx + 1 < len(raw_lines):
            next_line = raw_lines[brace_line_idx + 1].decode("utf-8", errors="replace")
            m = re.match(r'^(\s+)', next_line)
            if m:
                indent = m.group(1)

        void_stmts = "\n".join(f"{indent}(void){p};" for p in truly_missing)
        return ([{"start_byte": brace_byte, "end_byte": brace_byte,
                  "text": "\n" + void_stmts}], "")

    # ────────────────────────────────────────────────────────────────
    #  Edit generators — Rule 8.x (Declarations & Definitions)
    # ────────────────────────────────────────────────────────────────

    def _generate_8_2_edits(self, findings: Dict,
                            violation: AxivionViolation
                            ) -> "tuple[List[Dict], str]":
        """Rule 8.2: Function types shall be in prototype form.

        Auto-fixes the common case: `int f()` → `int f(void)`.
        Only safe when the empty parens literally appear on the line.
        """
        source = self._get_source_bytes(violation.file_path)
        if source is None:
            return self._NO_ANALYZER
        start, end = self._line_byte_range(source, violation.line_number)
        if start is None:
            return ([], "Could not resolve violation line in source.")
        line_text = source[start:end].decode("utf-8", errors="replace")
        # Match empty parameter list: "name()" or "name( )"
        m = re.search(r'(\w+)\s*\(\s*\)', line_text)
        if m:
            paren_start = start + line_text.index("(") + 1
            paren_end = start + line_text.index(")")
            # Handle whitespace inside parens
            inner = source[paren_start:paren_end]
            return ([{"start_byte": paren_start, "end_byte": paren_end,
                       "text": "void"}], "")
        return ([], "Could not find empty parameter list `()` on the "
                    "violation line. The function may already have "
                    "parameters, or the signature may span multiple lines.")

    def _generate_8_8_edits(self, findings: Dict,
                            violation: AxivionViolation
                            ) -> "tuple[List[Dict], str]":
        """Rule 8.8: Missing 'static' for internal linkage.

        Only generates the edit when cross-file analysis explicitly
        confirms the function has no external callers and no header
        declaration.  Without that proof, adding 'static' could break
        other translation units.
        """
        fn_info = findings.get("function", {})
        if not fn_info:
            return ([], "No function context available at the violation "
                        "line. Cannot determine linkage.")
        if fn_info.get("is_static"):
            return ([], "Function is already declared static.")
        cross = findings.get("cross_file", {})
        if not cross:
            return ([], f"No cross-file analysis available for "
                        f"`{fn_info.get('name', '?')}`. Adding `static` "
                        f"without confirming zero external references "
                        f"would silently break any other TU that calls "
                        f"this function.")
        if not cross.get("safe_to_add_static", False):
            callers = cross.get("external_callers", [])
            header = cross.get("declared_in_header", "")
            parts = []
            if callers:
                names = [f"`{c.get('file', '?')}:{c.get('line', '?')}`"
                         for c in callers[:3]]
                parts.append(f"external callers: {', '.join(names)}")
            if header:
                parts.append(f"declared in header `{header}`")
            detail = "; ".join(parts) if parts else "has external references"
            return ([], f"Cannot add `static` — {detail}. "
                        f"Fix the callers first or keep external linkage.")
        # Double-check: even if "safe", refuse if there's a header declaration
        # that we can't auto-update (would create 8.3 mismatch)
        header = cross.get("declared_in_header", "")
        if header:
            return ([], f"Cross-file says no external callers, but function "
                        f"is declared in header `{header}`. Adding `static` "
                        f"to the definition without removing the header "
                        f"declaration creates an 8.3 violation. Remove the "
                        f"header declaration first.")
        # Safe — insert 'static '
        source = self._get_source_bytes(violation.file_path)
        if source is None:
            return self._NO_ANALYZER
        target_line = fn_info.get("start_line", violation.line_number)
        start, end = self._line_byte_range(source, target_line)
        if start is None:
            return ([], "Could not resolve function definition line.")
        line_text = source[start:end].decode("utf-8", errors="replace")
        m = re.match(r'^(\s*)', line_text)
        indent_len = len(m.group(1).encode("utf-8")) if m else 0
        insert_at = start + indent_len
        return ([{"start_byte": insert_at, "end_byte": insert_at,
                  "text": "static "}], "")

    def _generate_8_10_edits(self, findings: Dict,
                             violation: AxivionViolation
                             ) -> "tuple[List[Dict], str]":
        """Rule 8.10: Insert 'static' before 'inline'.

        An inline function without static in C has external linkage.
        If no other TU provides an external definition, this is UB
        (C11 §6.7.4¶7).  The fix is always to add 'static'.

        Safety: refuses if cross-file analysis finds a header declaration
        (would create 8.3 mismatch).
        """
        if not findings.get("needs_static"):
            fn = findings.get("function", {})
            if fn and fn.get("is_static"):
                return ([], "Function already has 'static'.")
            if fn and not fn.get("is_inline"):
                return ([], "Function is not 'inline' — rule 8.10 may "
                            "not apply here.")
            return ([], "AST did not confirm this function needs 'static'. "
                        "Verify the function is both 'inline' and missing "
                        "'static'.")

        # Check cross-file: if the function is declared in a header,
        # adding static here without updating the header creates 8.3
        cross = findings.get("cross_file", {})
        if cross:
            header = cross.get("declared_in_header", "")
            if header:
                return ([], f"Function is declared in header `{header}`. "
                            f"Adding `static` to the definition without "
                            f"updating the header creates an 8.3 violation. "
                            f"Update the header declaration first.")
            if not cross.get("safe_to_add_static", True):
                return ([], "Cross-file analysis found external callers. "
                            "Adding `static` would break other TUs.")

        source = self._get_source_bytes(violation.file_path)
        if source is None:
            return self._NO_ANALYZER
        start, end = self._line_byte_range(source, violation.line_number)
        if start is None:
            return ([], "Could not resolve violation line in source.")
        line_text = source[start:end].decode("utf-8", errors="replace")
        m = re.search(r'\binline\b', line_text)
        if m:
            insert_at = start + m.start()
            return ([{"start_byte": insert_at, "end_byte": insert_at,
                      "text": "static "}], "")
        return ([], "Could not locate 'inline' keyword on the violation "
                    "line. The keyword may be on a different line of a "
                    "multi-line declaration.")

    def _generate_8_12_edits(self, findings: Dict,
                             violation: AxivionViolation
                             ) -> "tuple[List[Dict], str]":
        """Rule 8.12: Implicit enum values shall be unique.

        The correct fix depends on the intended values, which only
        the developer knows.  We report the collisions but do not
        guess values.
        """
        collisions = findings.get("enum_collisions", {})
        if collisions:
            parts = [f"{val}: {', '.join(names)}"
                     for val, names in collisions.items()]
            return ([], f"Enum value collisions detected "
                        f"({'; '.join(parts)}). Assigning explicit values "
                        f"requires knowing the intended semantics — "
                        f"auto-fix would be guessing.")
        return ([], "No enum collisions detected by AST analysis.")

    def _generate_8_13_edits(self, findings: Dict,
                             violation: AxivionViolation
                             ) -> "tuple[List[Dict], str]":
        """Rule 8.13: Pointer parameters should point to const.

        Safety checks:
          1. AST confirms zero writes AND zero non-const function-call passes
          2. Parameter is not already const-qualified
          3. Function is static (no cross-file header to update) — otherwise
             refuse to avoid creating an 8.3 mismatch
          4. Regex verifies the parameter text before inserting
        """
        candidates = findings.get("const_candidates", [])
        if not candidates:
            return ([], "AST did not identify pointer parameters to "
                        "analyze for const-qualification.")

        # Filter: safe AND not already const
        safe = [c for c in candidates
                if c.get("safe_to_add_const") and not c.get("already_const")]
        already = [c for c in candidates if c.get("already_const")]
        unsafe = [c for c in candidates
                  if not c.get("safe_to_add_const") and not c.get("already_const")]

        if not safe:
            parts = []
            if unsafe:
                names = [f"`{c['name']}` (writes={c.get('writes', '?')})"
                         for c in unsafe]
                parts.append(f"written through: {', '.join(names)}")
            if already:
                names = [f"`{c['name']}`" for c in already]
                parts.append(f"already const: {', '.join(names)}")
            return ([], f"No parameters to add const to. {'; '.join(parts)}.")

        # Safety gate: if function has external linkage, adding const to the
        # definition without updating the header creates an 8.3 violation.
        fn_info = findings.get("function", {})
        if fn_info and not fn_info.get("is_static"):
            cross = findings.get("cross_file", {})
            header = (cross.get("header_to_update") or
                      cross.get("declared_in_header"))
            if header:
                names = [f"`{c['name']}`" for c in safe]
                return ([], f"Parameters {', '.join(names)} are safe to "
                            f"add `const` locally, but the function has "
                            f"external linkage with a declaration in "
                            f"`{header}`. Adding `const` only to the "
                            f"definition would create an 8.3 violation. "
                            f"Update the header declaration first.")

        source = self._get_source_bytes(violation.file_path)
        if source is None:
            return self._NO_ANALYZER
        source_text = source.decode("utf-8", errors="replace")
        start_line = fn_info.get("start_line", violation.line_number)

        # Build signature region (scan up to 10 lines for closing paren)
        lines = source_text.splitlines(keepends=True)
        sig_text = ""
        sig_start_byte = sum(len(l.encode("utf-8")) for l in lines[:start_line - 1])
        for i in range(start_line - 1, min(start_line + 10, len(lines))):
            sig_text += lines[i]
            if ")" in lines[i]:
                break

        edits = []
        for c in safe:
            param_name = c["name"]
            # Match the type + pointer + name, but NOT if already preceded
            # by 'const'. Handles: int *name, char *name, uint8_t *name
            # Does NOT handle: function pointers, double pointers, arrays
            pattern = rf'([,(]\s*)(?!const\b)(\w[\w\s]*?\*\s*{re.escape(param_name)}\b)'
            m = re.search(pattern, sig_text)
            if m:
                # Verify the matched text doesn't already contain const
                matched_type = m.group(2)
                if "const" in matched_type:
                    continue
                insert_offset = sig_start_byte + m.start(2)
                edits.append({"start_byte": insert_offset,
                              "end_byte": insert_offset,
                              "text": "const "})

        if not edits:
            return ([], "Could not locate the parameter declarations in "
                        "the function signature. The signature may use "
                        "complex types (function pointers, double pointers) "
                        "or span many lines.")
        return (edits, "")

    def _generate_8_14_edits(self, violation: AxivionViolation
                             ) -> "tuple[List[Dict], str]":
        """Rule 8.14: Remove 'restrict' qualifier.

        The restrict keyword is a C99 optimisation hint; removing it
        is always safe from a correctness standpoint.
        """
        source = self._get_source_bytes(violation.file_path)
        if source is None:
            return self._NO_ANALYZER
        start, end = self._line_byte_range(source, violation.line_number)
        if start is None:
            return ([], "Could not resolve violation line in source.")
        line_text = source[start:end].decode("utf-8", errors="replace")
        edits = []
        for m in re.finditer(r'\brestrict\b\s*', line_text):
            edit_start = start + m.start()
            edit_end = start + m.end()
            edits.append({"start_byte": edit_start, "end_byte": edit_end,
                          "text": ""})
        if not edits:
            return ([], "Could not locate 'restrict' keyword on the "
                        "violation line.")
        return (edits, "")

    # ────────────────────────────────────────────────────────────────
    #  Edit generators — Rules 11-15
    # ────────────────────────────────────────────────────────────────

    def _generate_11_9_edits(self, findings: Dict) -> "tuple[List[Dict], str]":
        """Rule 11.9: Replace '0' with 'NULL' for pointers.

        Only replaces literal '0' in pointer contexts confirmed by AST.
        Checks that NULL is available (via stddef.h/stdlib.h/stdio.h).
        """
        violations = findings.get("null_pointer_violations", [])
        if not violations:
            return ([], "AST did not identify any literal '0' used as a "
                        "null pointer constant in this function.")
        edits = []
        for viol in violations:
            edits.append({
                "start_byte": viol["start_byte"],
                "end_byte": viol["end_byte"],
                "text": "NULL"
            })
        return (edits, "")



    def _generate_14_4_edits(self, findings: Dict) -> "tuple[List[Dict], str]":
        """Rule 14.4: Add explicit boolean check.

        Uses type info to choose the right comparison:
          - Pointers → != NULL  (avoids creating 11.9 violation)
          - Integers → != 0
          - Already boolean / already has comparison → skip
        Guards against double-wrapping (idempotency).
        """
        conditions = findings.get("non_boolean_conditions", [])
        if not conditions:
            return ([], "AST did not identify any non-boolean controlling "
                        "expressions in this function.")
        edits = []
        for viol in conditions:
            orig = viol["text"].strip()
            # Idempotency: skip if already has a comparison operator
            if any(op in orig for op in ("!=", "==", "<=", ">=", "<", ">")):
                continue
            # Skip negation expressions — !x is already boolean-ish,
            # and wrapping as !x != 0 is redundant
            if orig.startswith("!"):
                continue
            # Use type hint from analyzer if available
            is_pointer = viol.get("is_pointer", False)
            suffix = " != NULL" if is_pointer else " != 0"
            edits.append({
                "start_byte": viol["start_byte"],
                "end_byte": viol["end_byte"],
                "text": f"{orig}{suffix}"
            })
        if not edits:
            return ([], "All controlling expressions already contain "
                        "comparison operators or are boolean negations.")
        return (edits, "")

    def _generate_15_6_edits(self, findings: Dict,
                             violation: AxivionViolation
                             ) -> "tuple[List[Dict], str]":
        """Rule 15.6: Add braces around single-statement bodies.

        Preserves indentation by reading the original source to detect
        the current indent level, then wraps as:
            {
                <original statement>
            }
        """
        bodies = findings.get("missing_braces", [])
        if not bodies:
            return ([], "AST did not identify any unbraced control-flow "
                        "bodies in this function.")
        source = self._get_source_bytes(violation.file_path)
        edits = []
        for miss in bodies:
            body_text = miss["text"]
            # Detect indentation from the original source
            indent = ""
            if source is not None:
                # Walk backwards from start_byte to find line start
                pos = miss["start_byte"]
                while pos > 0 and source[pos - 1:pos] not in (b"\n", b"\r"):
                    pos -= 1
                leading = source[pos:miss["start_byte"]].decode("utf-8", errors="replace")
                if leading.strip() == "":
                    indent = leading  # pure whitespace = the indent
            if indent:
                # Multi-line format with proper indentation
                # The brace goes at the indent level of the parent (one level up)
                # Detect indent unit (assume consistent)
                parent_indent = indent[:-4] if indent.endswith("    ") else indent[:-1]
                replacement = (f"{{\n{indent}{body_text}\n{parent_indent}}}")
            else:
                # Fallback: inline wrap
                replacement = f"{{ {body_text} }}"
            edits.append({
                "start_byte": miss["start_byte"],
                "end_byte": miss["end_byte"],
                "text": replacement,
            })
        return (edits, "")

    # ────────────────────────────────────────────────────────────────
    #  Edit generators — Rule 10.x (Essential Type Model)
    # ────────────────────────────────────────────────────────────────

    def _generate_10_x_edits(self, findings: Dict,
                             violation: AxivionViolation
                             ) -> "tuple[List[Dict], str]":
        """Generate casts to resolve essential type mismatches (10.1-10.4, 10.6-10.8).

        Key improvements over naive casts:
          1. Wraps complex operands in parentheses: (type)(a + b), not (type)a + b
          2. Correct cast direction per MISRA essential type rules:
             - 10.1/10.3: cast the operand to match the expected type
             - 10.4: cast the narrower operand to the wider type
             - 10.6/10.7: cast to the assignment target type
          3. Rule 10.5 is excluded (handled separately — refuses auto-fix)
        """
        roots = []
        if findings.get("macro_analysis"):
            roots.append(findings["macro_analysis"])
        if findings.get("expressions"):
            roots.extend(findings["expressions"])

        if not roots:
            return ([], "AST did not identify expression operands with "
                        "type information. The violation may be in a macro "
                        "expansion or complex expression that the analyzer "
                        "cannot decompose.")

        def get_category(t):
            if t.get("is_float"):
                return "Floating"
            if t.get("name") in ("bool", "_Bool"):
                return "Boolean"
            if t.get("name") in ("char", "signed char", "unsigned char"):
                return "Character"
            if t.get("is_signed"):
                return "Signed"
            return "Unsigned"

        def _is_compound(text: str) -> bool:
            """Check if an operand is a compound expression needing parens."""
            text = text.strip()
            # Simple: identifier, number, or already parenthesized
            if re.match(r'^[\w]+$', text):
                return False  # simple identifier
            if re.match(r'^[0-9]', text):
                return False  # numeric literal
            if text.startswith("(") and text.endswith(")"):
                return False  # already parenthesized
            return True  # compound expression like a + b

        edits = []
        for root in roots:
            operands = root.get("operands", [])
            if len(operands) < 2:
                continue

            left, right = operands[0], operands[1]
            t_left, t_right = left.get("type"), right.get("type")
            if not t_left or not t_right:
                continue

            cat_left = get_category(t_left)
            cat_right = get_category(t_right)
            if cat_left == cat_right:
                continue

            target_op = None
            cast_type_name = ""

            # Cast the operand that needs widening/conversion to match
            # the other operand's type (MISRA 10.4: same essential type)
            w_left = t_left.get("width", 0)
            w_right = t_right.get("width", 0)

            # Signed vs Unsigned mismatch
            if {cat_left, cat_right} == {"Signed", "Unsigned"}:
                # Cast the narrower operand to the wider type.
                # If same width, cast to the unsigned type (C promotion rules).
                if w_left >= w_right:
                    target_op = right
                    cast_type_name = t_left["name"]
                else:
                    target_op = left
                    cast_type_name = t_right["name"]

            # Float vs non-Float
            elif cat_left == "Floating" and cat_right != "Floating":
                target_op = right
                cast_type_name = t_left["name"]
            elif cat_right == "Floating" and cat_left != "Floating":
                target_op = left
                cast_type_name = t_right["name"]

            # Character vs Integer
            elif cat_left == "Character" and cat_right in ("Signed", "Unsigned"):
                target_op = left
                cast_type_name = t_right["name"]
            elif cat_right == "Character" and cat_left in ("Signed", "Unsigned"):
                target_op = right
                cast_type_name = t_left["name"]

            if target_op and cast_type_name:
                byte_start = target_op["start_byte"]
                byte_end = target_op["end_byte"]
                operand_text = target_op.get("text", "")

                # Map back through macro if needed
                if "macro_analysis" in findings and "body_start_byte" in root:
                    prefix_len = root.get("prefix_len", 0)
                    body_start = root.get("body_start_byte", 0)
                    byte_start = body_start + (byte_start - prefix_len)
                    byte_end = body_start + (byte_end - prefix_len)

                # Wrap compound expressions in parens to avoid precedence bugs
                if _is_compound(operand_text):
                    edits.append({
                        "start_byte": byte_start,
                        "end_byte": byte_end,
                        "text": f"({cast_type_name})({operand_text})",
                    })
                else:
                    edits.append({
                        "start_byte": byte_start,
                        "end_byte": byte_start,
                        "text": f"({cast_type_name})",
                    })

        if not edits:
            return ([], "Operand types are in the same essential-type "
                        "category; no cast needed, or the type combination "
                        "is not yet handled by the auto-fixer.")
        return (edits, "")

    # ────────────────────────────────────────────────────────────────
    #  Guidance generation — uses AST findings, not regex
    # ────────────────────────────────────────────────────────────────

    def _generate_guidance(self, rule: MisraRule, violation: AxivionViolation,
                           findings: Dict) -> str:
        """Generate context-aware fix guidance based on AST analysis."""

        rid = rule.rule_id

        # ── Rule 2.1: Unreachable code ──
        if rid == "MisraC2012-2.1":
            reason = findings.get("unreachable_reason")
            if reason:
                return (
                    f"**Confirmed unreachable**: {reason}.\n\n"
                    f"Remove this code or restructure the control flow so it can be reached. "
                    f"If the code is intentional dead code (e.g., defensive programming), "
                    f"add a comment explaining why."
                )
            return rule.fix_strategy

        # ── Rule 2.7: Unused parameters ──
        if rid == "MisraC2012-2.7":
            unused = findings.get("unused_params", [])
            if unused:
                params_str = ", ".join(f"`{p}`" for p in unused)
                return (
                    f"**AST confirms** parameters {params_str} are never read or written "
                    f"in the function body.\n\n"
                    f"**Options:**\n"
                    f"1. Add `(void)param_name;` at the top of the function body for each\n"
                    f"2. If the parameter is genuinely unnecessary, consider removing it "
                    f"(but check all callers first)\n"
                    f"3. Use compiler-specific attributes like `__attribute__((unused))`"
                )
            return rule.fix_strategy

        # ── Rule 8.10: Inline without static ──
        if rid == "MisraC2012-8.10":
            fn_info = findings.get("function", {})
            if fn_info and fn_info.get("is_inline") and not fn_info.get("is_static"):
                return (
                    f"**AST confirms**: `{fn_info.get('name', '?')}` is declared `inline` "
                    f"but NOT `static`.\n\n"
                    f"An `inline` function without `static` has external linkage — "
                    f"if no other TU provides an external definition, this is undefined behaviour "
                    f"(C11 §6.7.4¶7).\n\n"
                    f"**Fix**: Add `static` before `inline`."
                )
            return rule.fix_strategy

        # ── Rule 8.13: Pointer to const ──
        if rid == "MisraC2012-8.13":
            candidates = findings.get("const_candidates", [])
            if candidates:
                parts = []
                for c in candidates:
                    if c.get("safe_to_add_const"):
                        parts.append(
                            f"- `{c['name']}` ({c.get('type', '?')}): "
                            f"{c.get('reads', 0)} reads, {c.get('writes', 0)} writes → "
                            f"**safe to add `const`**"
                        )
                    else:
                        parts.append(
                            f"- `{c['name']}` ({c.get('type', '?')}): "
                            f"written on lines {c.get('write_lines', [])} → "
                            f"**cannot add `const`**"
                        )
                analysis_block = "\n".join(parts)
                return (
                    f"**Pointer write-through analysis:**\n{analysis_block}\n\n"
                    f"For each parameter marked **safe to add `const`**, change the "
                    f"parameter type from `type *name` to `const type *name` in both "
                    f"the declaration and definition."
                )
            return rule.fix_strategy

        # ── Rule 8.12: Enum collisions ──
        if rid == "MisraC2012-8.12":
            collisions = findings.get("enum_collisions", {})
            if collisions:
                parts = []
                for val, names in collisions.items():
                    parts.append(f"- Value `{val}`: {', '.join(f'`{n}`' for n in names)}")
                collision_block = "\n".join(parts)
                return (
                    f"**Enum value collisions detected:**\n{collision_block}\n\n"
                    f"Assign explicit, unique values to all enumerators to avoid "
                    f"implicit value collisions."
                )
            return rule.fix_strategy

        # ── Rule 8.3: Declaration mismatch ──
        if rid == "MisraC2012-8.3":
            cross = findings.get("cross_file", {})
            if cross and cross.get("mismatches"):
                parts = [f"- {m}" for m in cross["mismatches"]]
                decl_info = ""
                if cross.get("declaration"):
                    d = cross["declaration"]
                    decl_info += f"\n- Declaration in `{d['file']}:{d['line']}`"
                    decl_info += f"\n  `{d['signature']}`"
                if cross.get("definition"):
                    d = cross["definition"]
                    decl_info += f"\n- Definition in `{d['file']}:{d['line']}`"
                    decl_info += f"\n  `{d['signature']}`"
                return (
                    f"**Cross-file signature mismatches:**\n"
                    + "\n".join(parts)
                    + decl_info + "\n\n"
                    f"Ensure the declaration in the header matches the definition exactly."
                )
            # Fallback to same-file check
            decls = findings.get("declarations", [])
            if len(decls) >= 2:
                parts = [
                    f"- Line {d['line']}: `{d.get('context', '').strip()}`"
                    for d in decls
                ]
                return (
                    f"**Mismatched declarations found:**\n" + "\n".join(parts) + "\n\n"
                    f"Ensure all declarations use identical parameter names and type "
                    f"qualifiers."
                )
            return rule.fix_strategy

        # ── Rule 8.4: No prior declaration ──
        if rid == "MisraC2012-8.4":
            fn_info = findings.get("function", {})
            cross = findings.get("cross_file", {})
            if cross and cross.get("has_prior_declaration"):
                decls = cross.get("declarations", [])
                files_str = ", ".join(f"`{d['file']}`" for d in decls)
                return (
                    f"Prototype found in: {files_str}\n\n"
                    f"Verify the declaration is compatible with the definition."
                )
            if fn_info:
                searched = ""
                if cross and cross.get("included_headers"):
                    searched = (f"\n\nSearched {len(cross['included_headers'])} "
                                f"included headers — none contain a prototype.")
                return (
                    f"Function `{fn_info.get('name', '?')}` has external linkage but "
                    f"no prior compatible declaration is visible.{searched}\n\n"
                    f"**Fix**: Add a prototype in the appropriate header file:\n"
                    f"```c\n{fn_info.get('signature', '?')};\n```"
                )
            return rule.fix_strategy

        # ── Rule 8.8: Missing static ──
        if rid == "MisraC2012-8.8":
            fn_info = findings.get("function", {})
            cross = findings.get("cross_file", {})
            if cross:
                if cross.get("safe_to_add_static"):
                    return (
                        f"**Cross-file analysis confirms**: `{fn_info.get('name', '?')}` "
                        f"has no external callers and no header declaration.\n\n"
                        f"**Fix**: Add `static` storage class specifier — safe to do."
                    )
                else:
                    callers = cross.get("external_callers", [])
                    caller_strs = [f"- `{c['file']}:{c['line']}` ({c['calling_function']})"
                                   for c in callers[:5]]
                    header = cross.get("declared_in_header")
                    warnings = []
                    if caller_strs:
                        warnings.append(
                            f"**External callers ({len(callers)}):**\n" +
                            "\n".join(caller_strs)
                        )
                    if header:
                        warnings.append(f"Declared in header: `{header}`")
                    return (
                        f"Function `{fn_info.get('name', '?')}` should use `static` "
                        f"but **cannot be safely changed** without updating:\n\n"
                        + "\n\n".join(warnings)
                    )
            if fn_info and not fn_info.get("is_static"):
                return (
                    f"Function `{fn_info.get('name', '?')}` has internal linkage "
                    f"(only used in this TU) but is missing `static`.\n\n"
                    f"**Fix**: Add `static` storage class specifier to the declaration."
                )
            return rule.fix_strategy

        # ── Type rules 10.x ──
        if rid.startswith("MisraC2012-10."):
            fn_info = findings.get("function", {})
            context = ""
            if fn_info:
                context = f" in function `{fn_info.get('name', '?')}`"
            return f"{rule.fix_strategy}\n\n**Context**: Violation{context}."

        # ── Deletion rules (2.2–2.6) ──
        if rid.startswith("MisraC2012-2."):
            return (
                f"{rule.fix_strategy}\n\n"
                f"**Verify** that removing this code doesn't break any build or test, "
                f"then delete it."
            )

        # ── General fallback ──
        scope = findings.get("symbol_scope")
        fn_info = findings.get("function")
        extra = ""
        if scope:
            extra += f"\n- Symbol scope: `{scope}`"
        if fn_info:
            extra += f"\n- Enclosing function: `{fn_info.get('name', '?')}`"
        return rule.fix_strategy + extra

    # ────────────────────────────────────────────────────────────────
    #  Confidence scoring — based on AST depth
    # ────────────────────────────────────────────────────────────────

    @staticmethod
    def _rate_confidence(rule: MisraRule, findings: Dict) -> str:
        """
        Rate confidence based on how much AST evidence we have.
        HIGH  = AST confirms the exact fix needed
        MEDIUM = AST provides context but fix needs human judgement
        LOW   = no AST data available, guidance only
        """
        if findings.get("error"):
            return "LOW"

        rid = rule.rule_id

        # HIGH: AST gives us definitive answer
        if rid == "MisraC2012-8.10" and findings.get("needs_static"):
            return "HIGH"
        if rid == "MisraC2012-8.13":
            candidates = findings.get("const_candidates", [])
            if any(c.get("safe_to_add_const") for c in candidates):
                return "HIGH"
        if rid == "MisraC2012-2.7" and findings.get("unused_params"):
            return "HIGH"
        if rid == "MisraC2012-2.1" and findings.get("unreachable_reason"):
            return "HIGH"
        if rid == "MisraC2012-8.12" and findings.get("enum_collisions"):
            return "HIGH"
            
        # 10.x with macro analysis is high confidence
        if rid.startswith("MisraC2012-10.") and findings.get("macro_analysis"):
            return "HIGH"

        # MEDIUM: We have function context
        if findings.get("function"):
            return "MEDIUM"

        return "LOW"

    # ────────────────────────────────────────────────────────────────
    #  Side-effect assessment
    # ────────────────────────────────────────────────────────────────

    @staticmethod
    def _assess_side_effects(rule: MisraRule, findings: Dict,
                             dependencies: Optional[List[str]]) -> List[str]:
        effects = []
        cross = findings.get("cross_file", {})

        if rule.rule_id in _CROSS_FILE_RULES:
            if cross:
                # Use specific cross-file evidence
                affected = cross.get("files_affected", [])
                if affected:
                    effects.append(
                        f"Files that need updating: {', '.join(f'`{f}`' for f in affected)}"
                    )

                ext_callers = cross.get("external_callers", [])
                if ext_callers:
                    effects.append(
                        f"{len(ext_callers)} external caller(s) must be reviewed."
                    )

                header = cross.get("declared_in_header") or cross.get("header_to_update")
                if header:
                    effects.append(f"Header `{header}` must be updated to match.")
            else:
                effects.append(
                    "This fix may require corresponding changes in other files "
                    "(headers, callers, or other translation units)."
                )

        # Rule 8.13: const addition affects API
        if rule.rule_id == "MisraC2012-8.13":
            total_callers = cross.get("total_callers", 0) if cross else 0
            if total_callers > 0:
                effects.append(
                    f"Adding `const` changes the API — {total_callers} caller(s) and "
                    f"the header declaration must be updated."
                )
            else:
                effects.append(
                    "Adding `const` to a function parameter changes its signature — "
                    "update the declaration in the header file and all callers."
                )

        # Scope changes
        fn_info = findings.get("function", {})
        if fn_info and rule.rule_id in ("MisraC2012-8.8", "MisraC2012-8.10"):
            if cross and cross.get("safe_to_add_static"):
                effects.append(
                    f"Cross-file analysis confirms `{fn_info.get('name', '?')}` is "
                    f"not used externally — `static` is safe."
                )
            elif cross and cross.get("has_external_callers"):
                effects.append(
                    f"Adding `static` to `{fn_info.get('name', '?')}` will break "
                    f"external callers — fix those first or keep external linkage."
                )
            else:
                effects.append(
                    f"Adding `static` to `{fn_info.get('name', '?')}` removes external "
                    f"linkage — ensure no other TU calls this function."
                )

        return effects

    # ────────────────────────────────────────────────────────────────
    #  Fallback for unknown rules
    # ────────────────────────────────────────────────────────────────

    @staticmethod
    def _unknown_rule(violation: AxivionViolation, line: str,
                      findings: Dict, function_context: str) -> FixAnalysis:
        return FixAnalysis(
            rule_id=violation.rule_id,
            confidence="LOW",
            violation_line=line.rstrip() if line else "",
            function_context=function_context,
            ast_findings=findings,
            rule_explanation=f"Rule {violation.rule_id} is not in the knowledge base.",
            fix_guidance=(
                f"Violation message: {violation.message}\n\n"
                f"Consult the MISRA C:2012 standard for this rule."
            ),
            compliant_example="",
            non_compliant_example="",
        )

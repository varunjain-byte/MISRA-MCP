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
from typing import Optional, List, Dict
from dataclasses import dataclass, field

from core.misra_knowledge_base import get_rule, MisraRule
from core.axivion_parser import AxivionViolation
from core.c_analyzer import CAnalyzer


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

    def to_markdown(self) -> str:
        md = f"### Fix Analysis — {self.rule_id}\n"
        md += f"**Confidence**: {self.confidence}\n\n"

        # Violation line
        md += "#### Violation Line\n```c\n"
        md += self.violation_line.rstrip() + "\n```\n\n"

        # AST findings
        md += "#### AST Analysis\n"
        md += self._format_findings() + "\n"

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

    def __init__(self, analyzer: Optional[CAnalyzer] = None):
        self.analyzer = analyzer

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
        )

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

"""
MISRA Fix Engine

Combines the knowledge base with code context to produce actionable,
confidence-scored fix suggestions.  Supports:

  • Mechanical regex-based fixes for rules with deterministic patterns
  • Context-aware guidance for rules requiring human judgement
  • Impact analysis for fixes that may affect other files
  • Confidence scoring (HIGH / MEDIUM / LOW)
"""

import re
from typing import Optional, List
from dataclasses import dataclass, field
from core.misra_knowledge_base import get_rule, MisraRule, FixPattern
from core.axivion_parser import AxivionViolation


# ═══════════════════════════════════════════════════════════════════════
#  Data Types
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class FixSuggestion:
    rule_id: str
    confidence: str            # "HIGH" | "MEDIUM" | "LOW"
    original_line: str         # the violating line of code
    fixed_line: str            # the suggested replacement
    explanation: str           # human-readable explanation of the change
    fix_strategy: str          # broader guidance from the knowledge base
    side_effects: List[str] = field(default_factory=list)

    def to_markdown(self) -> str:
        md = f"""### Fix Suggestion — {self.rule_id}
**Confidence**: {self.confidence}

#### Before
```c
{self.original_line}
```

#### After
```c
{self.fixed_line}
```

#### Explanation
{self.explanation}

#### Fix Strategy
{self.fix_strategy}
"""
        if self.side_effects:
            md += "\n#### ⚠ Potential Side Effects\n"
            for se in self.side_effects:
                md += f"- {se}\n"
        return md


# ═══════════════════════════════════════════════════════════════════════
#  Rules that have HIGH-confidence mechanical fixes
# ═══════════════════════════════════════════════════════════════════════

_MECHANICAL_RULES = {
    "MisraC2012-8.10", "MisraC2012-8.14", "MisraC2012-8.2",
}

# Rules where the fix may affect other files / callers
_CROSS_FILE_RULES = {
    "MisraC2012-8.3", "MisraC2012-8.4", "MisraC2012-8.5",
    "MisraC2012-8.6", "MisraC2012-8.8", "MisraC2012-8.13",
}

# Rules where the fix is "just delete it"
_DELETION_RULES = {
    "MisraC2012-2.1", "MisraC2012-2.2", "MisraC2012-2.3",
    "MisraC2012-2.4", "MisraC2012-2.5", "MisraC2012-2.6",
}


# ═══════════════════════════════════════════════════════════════════════
#  Engine
# ═══════════════════════════════════════════════════════════════════════

class FixEngine:
    """Generates fix suggestions by combining knowledge base + code context."""

    def propose_fix(
        self,
        violation: AxivionViolation,
        code_context: str,
        violation_line: str,
        dependencies: Optional[List[str]] = None,
    ) -> FixSuggestion:
        """
        Produce a FixSuggestion for the given violation.

        Args:
            violation:      The parsed violation record.
            code_context:   Multi-line code snippet around the violation.
            violation_line: The specific line that triggered the violation.
            dependencies:   #include / import lines from the file.
        """
        rule = get_rule(violation.rule_id)
        if rule is None:
            return self._unknown_rule(violation, violation_line)

        # 1. Try mechanical (regex) fix first
        fixed = self._try_pattern_fix(rule, violation_line)
        if fixed is not None:
            return self._build_suggestion(
                rule, violation, violation_line, fixed,
                confidence=self._rate_confidence(rule, pattern_matched=True),
                extra_explanation=self._pattern_explanation(rule),
            )

        # 2. Try rule-specific heuristics
        heuristic_fix = self._try_heuristic(rule, violation, violation_line, code_context)
        if heuristic_fix is not None:
            return heuristic_fix

        # 3. Fall back to knowledge-base guidance
        return self._guidance_only(rule, violation, violation_line)

    # ────────────────────────────────────────────────────────────────
    #  Pattern-based fixing
    # ────────────────────────────────────────────────────────────────

    @staticmethod
    def _try_pattern_fix(rule: MisraRule, line: str) -> Optional[str]:
        """Apply the first matching FixPattern from the rule's knowledge."""
        for fp in rule.fix_patterns:
            try:
                if re.search(fp.search, line):
                    fixed = re.sub(fp.search, fp.replace, line)
                    if fixed != line:
                        return fixed
            except re.error:
                continue
        return None

    @staticmethod
    def _pattern_explanation(rule: MisraRule) -> str:
        if rule.fix_patterns:
            return rule.fix_patterns[0].description
        return ""

    # ────────────────────────────────────────────────────────────────
    #  Rule-specific heuristics
    # ────────────────────────────────────────────────────────────────

    def _try_heuristic(
        self, rule: MisraRule, violation: AxivionViolation,
        line: str, context: str,
    ) -> Optional[FixSuggestion]:
        """Rule-specific heuristics for rules without simple patterns."""

        # ── Deletion rules (2.1, 2.2, 2.3, 2.4, 2.5, 2.6) ──
        if rule.rule_id in _DELETION_RULES:
            return self._build_suggestion(
                rule, violation, line,
                fixed_line=f"/* {rule.rule_id}: removed — {rule.title} */",
                confidence="MEDIUM",
                extra_explanation=(
                    f"Delete this code.  {rule.title}: the code has no effect "
                    f"on program behaviour."
                ),
            )

        # ── Rule 2.7: Unused parameter → (void) cast ──
        if rule.rule_id == "MisraC2012-2.7":
            return self._fix_unused_params(rule, violation, line, context)

        # ── Rule 8.1: Add missing return type ──
        if rule.rule_id == "MisraC2012-8.1":
            # Try to add 'int' before function name
            match = re.match(r'^(\s*)(\w+)\s*\(', line)
            if match and match.group(2) not in ('void', 'int', 'char', 'float',
                                                  'double', 'unsigned', 'signed',
                                                  'long', 'short', 'static',
                                                  'extern', 'inline', 'const'):
                fixed = re.sub(r'^(\s*)(\w+)\s*\(', r'\1int \2(', line)
                return self._build_suggestion(
                    rule, violation, line, fixed,
                    confidence="MEDIUM",
                    extra_explanation="Added explicit 'int' return type (implicit int is C89 only).",
                )

        # ── Rule 8.3: const/name mismatch ──
        if rule.rule_id == "MisraC2012-8.3":
            explanation = (
                "The function's declaration and definition have mismatched "
                "parameter names or qualifiers.  Update the definition to "
                "match the declaration exactly."
            )
            return self._build_suggestion(
                rule, violation, line, line,
                confidence="MEDIUM",
                extra_explanation=explanation,
                side_effects=["Update the corresponding declaration in the header file"],
            )

        # ── Rule 8.7: Move extern to file scope ──
        if rule.rule_id == "MisraC2012-8.7":
            # Remove indentation to suggest file-scope placement
            fixed = line.lstrip()
            return self._build_suggestion(
                rule, violation, line, f"/* Move to file scope: */  {fixed}",
                confidence="MEDIUM",
                extra_explanation="Move this extern declaration out of the function body to file scope.",
            )

        # ── Rule 8.9: Move to block scope ──
        if rule.rule_id == "MisraC2012-8.9":
            return self._build_suggestion(
                rule, violation, line,
                f"    /* Move inside the function that uses it: */\n    {line.strip()}",
                confidence="LOW",
                extra_explanation=(
                    "This file-scope variable is only used in one function. "
                    "Move it inside that function as a local (possibly static) variable."
                ),
            )

        # ── Rule 8.11: Add array size ──
        if rule.rule_id == "MisraC2012-8.11":
            fixed = re.sub(r'\[\s*\]', '[/* SIZE */]', line)
            return self._build_suggestion(
                rule, violation, line, fixed,
                confidence="MEDIUM",
                extra_explanation="Add an explicit size to the extern array declaration.",
            )

        # ── Rule 8.12: Enum value collision ──
        if rule.rule_id == "MisraC2012-8.12":
            return self._build_suggestion(
                rule, violation, line, line,
                confidence="MEDIUM",
                extra_explanation=(
                    "An implicit enum value collides with an explicit one. "
                    "Assign explicit, unique values to all enumerators."
                ),
            )

        # ── Rule 10.1: Inappropriate essential type ──
        if rule.rule_id == "MisraC2012-10.1":
            return self._fix_inappropriate_type(rule, violation, line)

        # ── Rule 10.2: Character arithmetic ──
        if rule.rule_id == "MisraC2012-10.2":
            return self._build_suggestion(
                rule, violation, line, line,
                confidence="MEDIUM",
                extra_explanation=(
                    "Cast character operands to (int) before arithmetic. "
                    "Cast the result back to char if needed."
                ),
            )

        # ── Rule 10.3: Narrowing assignment ──
        if rule.rule_id == "MisraC2012-10.3":
            return self._fix_narrowing(rule, violation, line)

        # ── Rules 10.4, 10.5, 10.6, 10.7, 10.8 ──
        if rule.rule_id.startswith("MisraC2012-10."):
            return self._build_suggestion(
                rule, violation, line, line,
                confidence="MEDIUM",
                extra_explanation=rule.fix_strategy,
            )

        return None

    # ────────────────────────────────────────────────────────────────
    #  Specific fixers
    # ────────────────────────────────────────────────────────────────

    def _fix_unused_params(
        self, rule: MisraRule, violation: AxivionViolation,
        line: str, context: str,
    ) -> FixSuggestion:
        """Generate (void) casts for unused parameters."""
        # Extract parameter names from the violation message
        msg = violation.message.lower()
        # Pattern: "Parameters 'a', 'b', 'c' are never referenced"
        params = re.findall(r"'(\w+)'", violation.message)
        if not params:
            # Try to extract from the line itself
            params = re.findall(r'(?:int|char|float|double|void\s*\*)\s+(\w+)', line)

        if params:
            void_casts = "\n".join(f"    (void){p};" for p in params)
            fixed = f"{line}\n{void_casts}"
            explanation = (
                f"Add (void) casts for unused parameters: {', '.join(params)}.  "
                f"This documents the intentional omission and silences warnings."
            )
        else:
            void_casts = "    (void)param_name;  /* cast each unused param */"
            fixed = f"{line}\n{void_casts}"
            explanation = "Cast each unused parameter to (void) at the top of the function body."

        return self._build_suggestion(
            rule, violation, line, fixed,
            confidence="HIGH",
            extra_explanation=explanation,
        )

    def _fix_inappropriate_type(
        self, rule: MisraRule, violation: AxivionViolation, line: str,
    ) -> FixSuggestion:
        """Fix Rule 10.1 — boolean/enum/signed in wrong context."""
        msg = violation.message.lower()
        if "bool" in msg:
            explanation = "Convert boolean to int via ternary (flag ? 1 : 0) before arithmetic."
        elif "enum" in msg:
            explanation = "Cast the enum to an unsigned integer type before bitwise operations."
        elif "signed" in msg or "shift" in msg:
            explanation = "Use unsigned types for shift operands to avoid undefined behaviour."
        else:
            explanation = "Ensure operands have the appropriate essential type for this operator."

        return self._build_suggestion(
            rule, violation, line, line,
            confidence="MEDIUM",
            extra_explanation=explanation,
        )

    def _fix_narrowing(
        self, rule: MisraRule, violation: AxivionViolation, line: str,
    ) -> FixSuggestion:
        """Fix Rule 10.3 — narrowing assignment."""
        msg = violation.message.lower()
        if "sign" in msg:
            explanation = "Add a range check before assigning signed to unsigned, or use an explicit cast."
        elif "float" in msg or "truncat" in msg:
            explanation = "Add an explicit (int) cast to document the intentional truncation."
        else:
            explanation = "Add an explicit cast to the target type to document the intentional narrowing."

        return self._build_suggestion(
            rule, violation, line, line,
            confidence="MEDIUM",
            extra_explanation=explanation,
        )

    # ────────────────────────────────────────────────────────────────
    #  Confidence scoring
    # ────────────────────────────────────────────────────────────────

    @staticmethod
    def _rate_confidence(rule: MisraRule, pattern_matched: bool = False) -> str:
        """Rate the confidence of a mechanical fix."""
        if pattern_matched and rule.rule_id in _MECHANICAL_RULES:
            return "HIGH"
        if pattern_matched:
            return "MEDIUM"
        if rule.rule_id in _DELETION_RULES:
            return "MEDIUM"
        return "LOW"

    # ────────────────────────────────────────────────────────────────
    #  Helpers
    # ────────────────────────────────────────────────────────────────

    def _build_suggestion(
        self,
        rule: MisraRule,
        violation: AxivionViolation,
        original: str,
        fixed_line: str,
        confidence: str,
        extra_explanation: str = "",
        side_effects: Optional[List[str]] = None,
    ) -> FixSuggestion:
        se = side_effects or []
        if rule.rule_id in _CROSS_FILE_RULES:
            se.append(
                "This fix may require corresponding changes in other files "
                "(headers, callers, or other translation units)."
            )
        return FixSuggestion(
            rule_id=rule.rule_id,
            confidence=confidence,
            original_line=original.rstrip(),
            fixed_line=fixed_line.rstrip(),
            explanation=extra_explanation or rule.fix_strategy,
            fix_strategy=rule.fix_strategy,
            side_effects=se,
        )

    def _unknown_rule(self, violation: AxivionViolation, line: str) -> FixSuggestion:
        return FixSuggestion(
            rule_id=violation.rule_id,
            confidence="LOW",
            original_line=line.rstrip(),
            fixed_line=line.rstrip(),
            explanation=(
                f"Rule {violation.rule_id} is not in the knowledge base.  "
                f"Violation message: {violation.message}"
            ),
            fix_strategy="Consult the MISRA C:2012 standard for this rule.",
        )

    def _guidance_only(self, rule: MisraRule, violation: AxivionViolation, line: str) -> FixSuggestion:
        """Fallback: return knowledge-base guidance without a concrete fix."""
        return FixSuggestion(
            rule_id=rule.rule_id,
            confidence="LOW",
            original_line=line.rstrip(),
            fixed_line=line.rstrip(),
            explanation=f"No mechanical fix available.  {rule.fix_strategy}",
            fix_strategy=rule.fix_strategy,
            side_effects=(
                ["Review the code context carefully — this fix requires human judgement."]
            ),
        )

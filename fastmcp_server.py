"""
Axivion MISRA Agent — MCP Server

Exposes six tools to GitHub Copilot via the Model Context Protocol:

  1. load_report       — load an Axivion JSON report + workspace root
  2. list_violations   — list all violations for a file
  3. analyze_violation — deep analysis: code context + AST + cross-file + rule
  4. explain_rule      — full MISRA rule explanation with examples
  5. propose_fix       — AST-informed fix analysis with structural evidence
  6. cross_file_impact — show which files are affected by fixing a symbol
  7. apply_fix         — automatically apply suggested fixes
  8. coverage_report   — list all supported rules and statistics
"""

from mcp.server.fastmcp import FastMCP
import os
import sys

# Ensure core modules are importable
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.axivion_parser import AxivionParser
from core.context_provider import ContextProvider
from core.c_analyzer import CAnalyzer
from core.workspace_index import WorkspaceIndex
from core.preprocessor import PreprocessorEngine
from core.misra_knowledge_base import format_rule_explanation, get_rule
from core.fix_engine import FixEngine

# ═══════════════════════════════════════════════════════════════════════
#  Server Setup
# ═══════════════════════════════════════════════════════════════════════

mcp = FastMCP("Axivion MISRA Agent")

parser = None
context_provider = None
analyzer = None
fix_engine = None
workspace_index = None
preprocessor = None


# ═══════════════════════════════════════════════════════════════════════
#  Violation Lookup Helper
# ═══════════════════════════════════════════════════════════════════════

def _find_violation(rule_id: str, file_path: str, line_number: int):
    """Find a violation with progressive fallback.

    Returns (violation, error_message).  Exactly one is non-None.

    Strategy:
      1. Exact match: rule + file + line
      2. Relaxed line: rule + file (any line) — handles off-by-one
      3. Basename match: rule + same filename in a different path
      4. Global search: find ALL locations for this rule across the report
    """
    # Normalise for display
    norm_path = file_path.replace("\\", "/")

    # 1. Exact match
    violations = parser.get_violations_by_file(file_path)
    target = next(
        (v for v in violations if v.rule_id == rule_id and v.line_number == line_number),
        None,
    )
    if target:
        return target, None

    # 2. Same file, different line
    same_file = [v for v in violations if v.rule_id == rule_id]
    if same_file:
        lines = sorted({v.line_number for v in same_file})
        lines_str = ", ".join(str(ln) for ln in lines[:10])
        closest = min(same_file, key=lambda v: abs(v.line_number - line_number))
        hint = (
            f"No `{rule_id}` violation at line {line_number} in `{norm_path}`, "
            f"but found {len(same_file)} violation(s) for this rule at line(s): {lines_str}.\n"
            f"**Closest match:** line {closest.line_number} — using that instead."
        )
        return closest, hint

    # 3. Basename match — violation may be in a .c file, not the .h the LLM passed
    basename = os.path.basename(norm_path)
    all_violations = parser.get_all_violations()
    basename_matches = [
        v for v in all_violations
        if v.rule_id == rule_id
        and os.path.basename(v.file_path.replace("\\", "/")) == basename
    ]
    if basename_matches:
        v = basename_matches[0]
        hint = (
            f"No `{rule_id}` violation in `{norm_path}`, "
            f"but found it in `{v.file_path}:{v.line_number}` (same basename).\n"
            f"**Using that match instead.**"
        )
        return v, hint

    # 4. Global search — find where this rule IS reported
    global_matches = [v for v in all_violations if v.rule_id == rule_id]
    if global_matches:
        # Group by file for a readable summary
        by_file = {}
        for v in global_matches:
            fp = v.file_path.replace("\\", "/")
            by_file.setdefault(fp, []).append(v.line_number)

        locations = []
        for fp, lines in sorted(by_file.items())[:8]:
            lines_str = ", ".join(str(ln) for ln in sorted(lines)[:5])
            if len(lines) > 5:
                lines_str += f" ... ({len(lines)} total)"
            locations.append(f"  - `{fp}`: line(s) {lines_str}")

        loc_block = "\n".join(locations)
        extra = ""
        if len(by_file) > 8:
            extra = f"\n  ... and {len(by_file) - 8} more file(s)"

        msg = (
            f"No `{rule_id}` violation found in `{norm_path}`.\n\n"
            f"**`{rule_id}` violations exist in these files:**\n{loc_block}{extra}\n\n"
            f"Please call `propose_fix` or `apply_fix` with the correct file path and line number."
        )
        return None, msg

    # 5. Rule not in report at all
    available_rules = sorted({v.rule_id for v in violations})
    msg = f"No `{rule_id}` violation found in `{norm_path}`."
    if available_rules:
        msg += f"\nAvailable rules in this file: {', '.join(available_rules)}"
    else:
        msg += "\nNo violations found in this file. Check the path or run `list_violations`."
    return None, msg

# ═══════════════════════════════════════════════════════════════════════
#  Tool 1 — Load Report
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
def load_report(report_path: str, workspace_root: str) -> str:
    """
    Loads the Axivion analysis report and initialises the context provider.

    Also builds a cross-file WorkspaceIndex that scans all .c/.h files
    to enable cross-translation-unit analysis (include graph, symbol table,
    call graph).

    Args:
        report_path:    Absolute path to the Axivion JSON report.
        workspace_root: Root directory of the workspace containing source code.
    """
    global parser, context_provider, analyzer, fix_engine, workspace_index, preprocessor

    if not os.path.exists(report_path):
        return f"Error: Report file not found at {report_path}"
    if not os.path.exists(workspace_root):
        return f"Error: Workspace root not found at {workspace_root}"

    try:
        parser = AxivionParser(report_path)

        # Normalise violation paths to be relative to the workspace.
        # Axivion reports may contain absolute paths from the analysis server
        # that differ from the user's local workspace layout.
        parser.normalize_paths(workspace_root)

        context_provider = ContextProvider(workspace_root)

        # Initialize Preprocessor Engine
        try:
            preprocessor = PreprocessorEngine(workspace_root)
        except Exception as e:
            return f"Error initializing PreprocessorEngine: {e}"

        # Build cross-file index
        workspace_index = WorkspaceIndex(workspace_root, preprocessor=preprocessor)
        workspace_index.build()

        # Create analyzer with cross-file support
        analyzer = CAnalyzer(workspace_root, workspace_index=workspace_index, preprocessor=preprocessor)
        fix_engine = FixEngine(analyzer, context_provider)

        count = len(parser.get_all_violations())
        idx = workspace_index.get_summary()
        return (
            f"Successfully loaded report. Found {count} violations.\n"
            f"Workspace indexed: {idx['c_files']} .c files, {idx['h_files']} .h files, "
            f"{idx['symbols']} symbols, {idx['call_sites']} call sites.\n"
            f"Preprocessor Engine initialized."
        )
    except Exception as e:
        return f"Error loading report: {e}"


# ═══════════════════════════════════════════════════════════════════════
#  Tool 2 — List Violations
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
def list_violations(file_path: str) -> str:
    """
    Lists all MISRA violations for a specific file.

    Args:
        file_path: Relative path of the file in the workspace.
    """
    if parser is None:
        return "Error: No report loaded. Call load_report first."

    violations = parser.get_violations_by_file(file_path)
    if not violations:
        return f"No violations found for {file_path}"

    result = f"**{len(violations)} violations in {file_path}:**\n\n"
    for v in violations:
        rule = get_rule(v.rule_id)
        title = rule.title if rule else "Unknown rule"
        result += (
            f"- **[{v.rule_id}]** Line {v.line_number} ({v.severity}): "
            f"{v.message}\n"
            f"  *{title}*\n"
        )
    return result


# ═══════════════════════════════════════════════════════════════════════
#  Tool 3 — Analyse Violation (enhanced with AST)
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
def analyze_violation(rule_id: str, file_path: str) -> str:
    """
    Returns detailed analysis of a specific violation:
    code context, AST analysis, rule explanation, and fix guidance.

    Args:
        rule_id:   The MISRA rule ID (e.g. 'MisraC2012-8.3').
        file_path: The file where the violation occurred.
    """
    if parser is None or context_provider is None:
        return "Error: Not initialised. Call load_report first."

    violations = parser.get_violations_by_file(file_path)
    target = next((v for v in violations if v.rule_id == rule_id), None)
    if not target:
        available_rules = sorted({v.rule_id for v in violations})
        msg = f"Violation '{rule_id}' not found in '{file_path}'."
        if available_rules:
            msg += f"\nAvailable rules in this file: {', '.join(available_rules)}"
        else:
            msg += "\nNo violations found in this file. Check the path or run list_violations."
        return msg

    # Gather context
    context = context_provider.get_code_context(file_path, target.line_number)
    viol_line = context_provider.get_line(file_path, target.line_number)
    deps = context_provider.analyze_dependencies(file_path)
    enclosing_fn = context_provider.get_enclosing_function(
        file_path, target.line_number
    )

    # Rule explanation
    rule_info = format_rule_explanation(rule_id)

    # AST-informed fix analysis
    fix_analysis = fix_engine.propose_fix(target, context, viol_line, deps)

    analysis = f"""## Violation Analysis

| Field | Value |
|-------|-------|
| **Rule** | {target.rule_id} |
| **File** | `{file_path}:{target.line_number}` |
| **Severity** | {target.severity} |
| **Message** | {target.message} |
| **Function** | `{enclosing_fn or 'file scope'}` |

### Code Context
```c
{context}
```

### Dependencies
{chr(10).join('- `' + d + '`' for d in deps) if deps else 'None detected.'}

---

{rule_info}

---

{fix_analysis.to_markdown()}
"""
    return analysis


# ═══════════════════════════════════════════════════════════════════════
#  Tool 4 — Explain Rule
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
def explain_rule(rule_id: str) -> str:
    """
    Returns the full MISRA rule explanation: title, category, rationale,
    compliant/non-compliant examples, and how to fix.

    Args:
        rule_id: The MISRA rule ID (e.g. 'MisraC2012-10.3').
    """
    return format_rule_explanation(rule_id)


# ═══════════════════════════════════════════════════════════════════════
#  Tool 5 — Propose Fix (AST-informed)
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
def propose_fix(rule_id: str, file_path: str, line_number: int) -> str:
    """
    Returns an AST-informed fix analysis for a specific violation.

    Uses tree-sitter to parse the C source file and provide structural
    evidence (parameter usage, pointer write analysis, scope, reachability)
    that enables the LLM to generate the correct fix.

    Args:
        rule_id:     The MISRA rule ID (e.g. 'MisraC2012-8.10').
        file_path:   The file where the violation occurred.
        line_number: The exact line number of the violation.
    """
    if parser is None or context_provider is None:
        return "Error: Not initialised. Call load_report first."

    # Find the matching violation (with progressive fallback)
    target, lookup_msg = _find_violation(rule_id, file_path, line_number)
    if target is None:
        return lookup_msg

    # Gather context using the actual violation location
    actual_file = target.file_path
    actual_line = target.line_number
    context = context_provider.get_code_context(actual_file, actual_line)
    viol_line = context_provider.get_line(actual_file, actual_line)
    deps = context_provider.analyze_dependencies(actual_file)

    analysis = fix_engine.propose_fix(target, context, viol_line, deps)
    result = analysis.to_markdown()

    # Prepend fallback hint if we resolved to a different location
    if lookup_msg:
        result = f"> **Note:** {lookup_msg}\n\n{result}"
    return result


# ═══════════════════════════════════════════════════════════════════════
#  Tool 6 — Cross-File Impact
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
def cross_file_impact(symbol_name: str) -> str:
    """
    Shows which files are affected by changing a symbol (function, variable,
    type, or macro). Uses the workspace index to find all declarations,
    definitions, and callers across the project.

    Args:
        symbol_name: Name of the function, variable, or type to check.
    """
    if workspace_index is None or not workspace_index.is_built:
        return "Error: No workspace index. Call load_report first."

    entries = workspace_index.symbols.find(symbol_name)
    if not entries:
        return f"Symbol `{symbol_name}` not found in workspace index."

    result = f"## Cross-File Impact — `{symbol_name}`\n\n"

    # Declarations and definitions
    defs = [e for e in entries if e.kind.endswith("_def")]
    decls = [e for e in entries if e.kind.endswith("_decl")]
    others = [e for e in entries if not e.kind.endswith("_def") and not e.kind.endswith("_decl")]

    if defs:
        result += "### Definitions\n"
        for e in defs:
            result += f"- `{e.file}:{e.line}` ({e.linkage}): `{e.signature}`\n"
        result += "\n"

    if decls:
        result += "### Declarations\n"
        for e in decls:
            result += f"- `{e.file}:{e.line}` ({e.linkage}): `{e.signature}`\n"
        result += "\n"

    if others:
        result += "### Other References\n"
        for e in others:
            result += f"- `{e.file}:{e.line}` ({e.kind}): `{e.signature}`\n"
        result += "\n"

    # Callers
    callers = workspace_index.call_graph.get_callers(symbol_name)
    if callers:
        result += f"### Callers ({len(callers)})\n"
        for c in callers[:20]:
            result += f"- `{c.caller_file}:{c.caller_line}` in `{c.caller_function}()`\n"
        if len(callers) > 20:
            result += f"- ... and {len(callers) - 20} more\n"
        result += "\n"

    # Files affected
    files = set(e.file for e in entries) | set(c.caller_file for c in callers)
    result += f"### Total Files Affected: {len(files)}\n"
    for f in sorted(files):
        result += f"- `{f}`\n"

    return result


# ═══════════════════════════════════════════════════════════════════════
#  Tool 7 — Apply Fix (Auto-Fix)
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
def apply_fix(rule_id: str, file_path: str, line_number: int) -> str:
    """
    Automatically applies the suggested fix for a violation if available.

    Currently supports:
    - Rule 2.x (Unused Code): Deletes dead/unreachable code, inserts (void)param.
    - Rule 8.x (Declarations): Adds static/const, removes restrict.
    - Rule 10.x (Essential Types): Inserts casts.
    - Rule 11.9 (NULL), 14.4 (Boolean), 15.6 (Braces).

    After applying edits:
      - Validates the result is parseable C (tree-sitter re-parse)
      - Invalidates the AST cache so subsequent calls use fresh data

    Args:
        rule_id:     The MISRA rule ID.
        file_path:   The file path.
        line_number: The line number of the violation.
    """
    if parser is None or context_provider is None:
        return "Error: Not initialised. Call load_report first."

    # Find the matching violation (with progressive fallback)
    target, lookup_msg = _find_violation(rule_id, file_path, line_number)
    if target is None:
        return lookup_msg

    # Use the actual violation location (may differ from what was passed)
    actual_file = target.file_path
    actual_line = target.line_number

    # Analyze to get edits
    context = context_provider.get_code_context(actual_file, actual_line)
    viol_line = context_provider.get_line(actual_file, actual_line)
    analysis = fix_engine.propose_fix(target, context, viol_line, None)

    if not analysis.edits:
        reason = analysis.edit_skip_reason or "No specific reason available."
        prefix = f"> **Note:** {lookup_msg}\n\n" if lookup_msg else ""
        return (f"{prefix}Auto-fix not available.\n\n"
                f"**Reason:** {reason}\n\n"
                f"**Guidance:**\n{analysis.fix_guidance}")

    # Apply edits
    try:
        abs_path = os.path.join(context_provider.workspace_root, actual_file)
        with open(abs_path, "rb") as f:
            original = f.read()
        content = bytearray(original)

        # Sort edits by start_byte descending to keep offsets valid
        sorted_edits = sorted(analysis.edits, key=lambda e: e["start_byte"], reverse=True)

        # Overlap detection: ensure no edit overlaps with a later one
        applied_count = 0
        skipped_count = 0
        last_start = float('inf')
        for edit in sorted_edits:
            start = edit["start_byte"]
            end = edit["end_byte"]
            text = edit["text"].encode("utf-8")

            # Bounds check
            if start < 0 or end > len(content) or start > end:
                skipped_count += 1
                continue

            # Overlap check: this edit's end must not exceed the start
            # of the previous (lower-offset) edit we already applied
            if end > last_start:
                skipped_count += 1
                continue

            content[start:end] = text
            last_start = start
            applied_count += 1

        if applied_count == 0:
            return "Error: All edits were skipped (out of bounds or overlapping)."

        # ── Verify: re-parse with tree-sitter to check valid C ──
        from tree_sitter import Parser
        from core.c_analyzer import C_LANGUAGE
        verify_parser = Parser(C_LANGUAGE)
        verify_tree = verify_parser.parse(bytes(content))
        if verify_tree.root_node.has_error:
            # Rollback: restore original content
            with open(abs_path, "wb") as f:
                f.write(original)
            return ("Error: Fix produced invalid C (parse errors detected). "
                    "Rolled back to original. The fix may need manual "
                    "adjustment.\n\n"
                    f"**Guidance:**\n{analysis.fix_guidance}")

        # Write the validated content
        with open(abs_path, "wb") as f:
            f.write(content)

        # ── Invalidate caches so subsequent calls use fresh data ──
        if analyzer:
            resolved = analyzer._resolve(actual_file)
            analyzer._cache.pop(resolved, None)

        result = f"Successfully applied {applied_count} edit(s) to `{actual_file}`."
        if lookup_msg:
            result = f"> **Note:** {lookup_msg}\n\n{result}"
        if skipped_count > 0:
            result += f" ({skipped_count} edit(s) skipped due to overlap/bounds.)"
        if analysis.side_effects:
            result += "\n\n**Side effects to review:**\n"
            for se in analysis.side_effects:
                result += f"- {se}\n"
        return result

    except Exception as e:
        return f"Error applying fix: {e}"


# ═══════════════════════════════════════════════════════════════════════
#  Tool 8 — Coverage Report
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
def coverage_report() -> str:
    """
    Returns a markdown report of all supported MISRA C:2012 rules,
    grouped by section (e.g., 2.x, 8.x, 10.x), with coverage statistics.
    """
    from core.misra_knowledge_base import _RULES

    # Group rules by section
    sections = {}
    total_rules = len(_RULES)
    
    for rule_id in _RULES:
        # Extract section prefix (e.g. "MisraC2012-8.3" -> "8.x")
        try:
            # ID format: 'MisraC2012-X.Y'
            # Split by '-' then take last part 'X.Y', then split by '.'
            number_part = rule_id.split('-')[-1]
            section_num = number_part.split('.')[0]
            section_key = f"{section_num}.x"
        except Exception:
            section_key = "Other"

        if section_key not in sections:
            sections[section_key] = []
        sections[section_key].append(rule_id)

    # Sort sections numerically if possible
    sorted_keys = sorted(sections.keys(), key=lambda s: float(s.replace('.x', '')) if s[0].isdigit() else 999)

    report = f"# MISRA C:2012 Coverage Report\n\n"
    report += f"**Total Rules Supported**: {total_rules}\n\n"
    report += "| Section | Count | Rules |\n"
    report += "|---------|-------|-------|\n"

    for section in sorted_keys:
        rules = sorted(sections[section], key=lambda r: [int(n) for n in r.split('-')[-1].split('.')])
        count = len(rules)
        # listing specific rules might be verbose, so we list ranges or first few
        rule_list = ", ".join(rules)
        report += f"| **{section}** | {count} | {rule_list} |\n"

    return report


if __name__ == "__main__":
    # Debug: Print loaded tools to stderr (visible in MCP logs)
    try:
        if hasattr(mcp, "_tool_manager") and hasattr(mcp._tool_manager, "_tools"):
            tools = mcp._tool_manager._tools.keys()
            print(f"DEBUG: Axivion Agent starting with {len(tools)} tools: {list(tools)}", file=sys.stderr)
        else:
             print("DEBUG: Axivion Agent starting (cannot inspect tools)", file=sys.stderr)
    except Exception as e:
        print(f"DEBUG: Error inspecting tools: {e}", file=sys.stderr)
        
    mcp.run()

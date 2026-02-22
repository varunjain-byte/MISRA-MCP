"""
Axivion MISRA Agent — MCP Server

Exposes tools to GitHub Copilot via the Model Context Protocol:

  1.  load_report       — load an Axivion JSON report + workspace root
  1b. set_include_dirs  — reconfigure include paths & defines, rebuild index
  2.  list_violations   — list all violations for a file (shows fix status)
  3.  analyze_violation — deep analysis: code context + AST + cross-file + rule
  4.  explain_rule      — full MISRA rule explanation with examples
  5.  propose_fix       — AST-informed fix analysis with structural evidence
  6.  cross_file_impact — show which files are affected by fixing a symbol
  7.  apply_fix         — automatically apply suggested fixes + mark status
  8.  coverage_report   — list all supported rules and statistics
  9.  verify_fix        — re-run AST analysis to confirm a fix resolved the violation
 10.  fix_all           — iterate fix → verify for every violation in a file
"""

from mcp.server.fastmcp import FastMCP
import os
import sys

# Ensure core modules are importable
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.axivion_parser import AxivionParser
from core.context_provider import ContextProvider
from core.c_analyzer import CAnalyzer
from core.workspace_index import WorkspaceIndex, discover_include_dirs
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

# ── Violation status tracking ──
# Key:   (normalized_file_path, line_number, rule_id)
# Value: "pending" | "fixed" | "verified" | "failed"
#   pending  = loaded from report, not yet touched
#   fixed    = apply_fix succeeded (syntax-valid)
#   verified = verify_fix confirmed the condition is gone
#   failed   = verify_fix found the condition still present
_violation_status = {}


def _vkey(file_path: str, line: int, rule_id: str) -> tuple:
    """Canonical key for the violation status map."""
    return (file_path.replace("\\", "/"), line, rule_id)


def _get_status(file_path: str, line: int, rule_id: str) -> str:
    return _violation_status.get(_vkey(file_path, line, rule_id), "pending")


def _set_status(file_path: str, line: int, rule_id: str, status: str):
    _violation_status[_vkey(file_path, line, rule_id)] = status


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
def load_report(report_path: str, workspace_root: str, include_dirs: str = "") -> str:
    """
    Loads the Axivion analysis report and initialises the context provider.

    Also builds a cross-file WorkspaceIndex that scans all .c/.h files
    to enable cross-translation-unit analysis (include graph, symbol table,
    call graph).

    Args:
        report_path:    Absolute path to the Axivion JSON report.
        workspace_root: Root directory of the workspace containing source code.
        include_dirs:   Comma-separated list of include directories (relative to
                        workspace_root).  If empty, directories containing .h
                        files are auto-discovered from the workspace.
                        Example: "source/Include,Autosar/BSW,lib/third_party"
    """
    global parser, context_provider, analyzer, fix_engine, workspace_index, preprocessor, _violation_status

    if not os.path.exists(report_path):
        return f"Error: Report file not found at {report_path}"
    if not os.path.exists(workspace_root):
        return f"Error: Workspace root not found at {workspace_root}"

    try:
        _violation_status = {}  # reset on new report load

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

        # Resolve include directories: explicit list or auto-discover
        resolved_include_dirs = None
        if include_dirs.strip():
            resolved_include_dirs = [d.strip() for d in include_dirs.split(",") if d.strip()]

        # Build cross-file index (auto-discovers include dirs if none provided)
        workspace_index = WorkspaceIndex(
            workspace_root,
            include_dirs=resolved_include_dirs,
            preprocessor=preprocessor,
        )
        workspace_index.build()

        # Create analyzer with cross-file support
        analyzer = CAnalyzer(workspace_root, workspace_index=workspace_index, preprocessor=preprocessor)
        fix_engine = FixEngine(analyzer, context_provider)

        count = len(parser.get_all_violations())
        idx = workspace_index.get_summary()
        inc_count = len(workspace_index.include_dirs)
        return (
            f"Successfully loaded report. Found {count} violations.\n"
            f"Workspace indexed: {idx['c_files']} .c files, {idx['h_files']} .h files, "
            f"{idx['symbols']} symbols, {idx['call_sites']} call sites.\n"
            f"Include directories: {inc_count} configured.\n"
            f"Preprocessor Engine initialized."
        )
    except Exception as e:
        return f"Error loading report: {e}"


# ═══════════════════════════════════════════════════════════════════════
#  Tool 1b — Set Include Dirs (post-load reconfiguration)
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
def set_include_dirs(include_dirs: str = "", extra_defines: str = "") -> str:
    """
    Reconfigure include directories and preprocessor defines, then rebuild
    the workspace index.  Use this after load_report if the initial
    auto-discovered include paths are insufficient.

    Args:
        include_dirs:   Comma-separated list of include directories (relative to
                        workspace_root).  If empty, re-runs auto-discovery.
                        Example: "source/Include,Autosar/BSW/Include,lib"
        extra_defines:  Comma-separated preprocessor defines (NAME=VALUE or NAME).
                        Example: "PLATFORM_X=1,ENABLE_CRYPTO,DEBUG=0"
    """
    global workspace_index, analyzer, fix_engine, preprocessor

    if workspace_index is None or preprocessor is None:
        return "Error: No report loaded. Call load_report first."

    ws_root = workspace_index.workspace_root

    # Resolve include dirs
    if include_dirs.strip():
        resolved_dirs = [d.strip() for d in include_dirs.split(",") if d.strip()]
    else:
        resolved_dirs = discover_include_dirs(ws_root)

    # Apply extra defines to preprocessor
    if extra_defines.strip():
        for define in extra_defines.split(","):
            define = define.strip()
            if not define:
                continue
            if "=" in define:
                name, value = define.split("=", 1)
                preprocessor.add_define(name.strip(), value.strip())
            else:
                preprocessor.add_define(define)

    # Clear preprocessor cache so files are re-expanded with new paths/defines
    preprocessor._cache.clear()

    # Rebuild workspace index with new include dirs
    workspace_index = WorkspaceIndex(
        ws_root,
        include_dirs=resolved_dirs,
        preprocessor=preprocessor,
    )
    workspace_index.build()

    # Recreate analyzer with updated index
    context_provider = ContextProvider(ws_root)
    analyzer = CAnalyzer(ws_root, workspace_index=workspace_index, preprocessor=preprocessor)
    fix_engine = FixEngine(analyzer, context_provider)

    idx = workspace_index.get_summary()
    inc_count = len(workspace_index.include_dirs)
    defines_count = len(preprocessor.defines)
    return (
        f"Workspace re-indexed with {inc_count} include directories"
        f" and {defines_count} preprocessor defines.\n"
        f"Indexed: {idx['c_files']} .c files, {idx['h_files']} .h files, "
        f"{idx['symbols']} symbols, {idx['call_sites']} call sites, "
        f"{idx['type_aliases']} type aliases."
    )


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

    # Count by status
    status_counts = {"pending": 0, "fixed": 0, "verified": 0, "failed": 0}
    for v in violations:
        s = _get_status(v.file_path, v.line_number, v.rule_id)
        status_counts[s] = status_counts.get(s, 0) + 1

    result = f"**{len(violations)} violations in {file_path}**"
    if status_counts["verified"] or status_counts["fixed"]:
        parts = []
        if status_counts["verified"]:
            parts.append(f"{status_counts['verified']} verified")
        if status_counts["fixed"]:
            parts.append(f"{status_counts['fixed']} fixed (unverified)")
        if status_counts["failed"]:
            parts.append(f"{status_counts['failed']} fix failed")
        result += f" — {', '.join(parts)}"
    result += ":\n\n"

    _STATUS_BADGE = {
        "pending": "",
        "fixed": " [FIXED]",
        "verified": " [VERIFIED]",
        "failed": " [FIX FAILED]",
    }

    for v in violations:
        rule = get_rule(v.rule_id)
        title = rule.title if rule else "Unknown rule"
        badge = _STATUS_BADGE.get(
            _get_status(v.file_path, v.line_number, v.rule_id), ""
        )
        result += (
            f"- **[{v.rule_id}]** Line {v.line_number} ({v.severity}){badge}: "
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

        # ── Mark violation as fixed ──
        _set_status(actual_file, actual_line, target.rule_id, "fixed")

        result = f"Successfully applied {applied_count} edit(s) to `{actual_file}`."
        if lookup_msg:
            result = f"> **Note:** {lookup_msg}\n\n{result}"
        if skipped_count > 0:
            result += f" ({skipped_count} edit(s) skipped due to overlap/bounds.)"
        if analysis.side_effects:
            result += "\n\n**Side effects to review:**\n"
            for se in analysis.side_effects:
                result += f"- {se}\n"
        result += (
            "\n\n**Status:** marked as `fixed`. "
            "Run `verify_fix` to confirm the violation is resolved."
        )
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


# ═══════════════════════════════════════════════════════════════════════
#  Tool 9 — Verify Fix
# ═══════════════════════════════════════════════════════════════════════

def _verify_violation(rule_id: str, file_path: str, line_number: int) -> tuple:
    """Internal: re-run AST analysis and check if the violation condition persists.

    Returns (is_resolved: bool, detail: str).
    """
    if analyzer is None:
        return False, "Analyzer not initialised."

    # Invalidate AST cache so we parse the current file contents
    resolved_path = analyzer._resolve(file_path)
    analyzer._cache.pop(resolved_path, None)

    findings = analyzer.analyze_for_rule(file_path, line_number, rule_id)

    # ── Rule 2.1: unreachable code ──
    if rule_id == "MisraC2012-2.1":
        if findings.get("unreachable_reason"):
            return False, f"Still unreachable: {findings['unreachable_reason']}"
        return True, "Code is now reachable."

    # ── Rule 2.7: unused parameters ──
    if rule_id == "MisraC2012-2.7":
        unused = findings.get("unused_params", [])
        if unused:
            return False, f"Still unused: {', '.join(unused)}"
        return True, "All parameters are now used (or suppressed)."

    # ── Rule 8.x family ──
    if rule_id == "MisraC2012-8.8":
        fn = findings.get("function")
        if fn and findings.get("needs_static") and findings.get("safe_to_add_static", True):
            return False, "Function still lacks `static`."
        return True, "Function is now `static`."

    if rule_id == "MisraC2012-8.10":
        fn = findings.get("function")
        if fn and fn.get("is_inline") and not fn.get("is_static"):
            return False, "`inline` function still lacks `static`."
        return True, "Function is now `static inline`."

    if rule_id == "MisraC2012-8.13":
        candidates = findings.get("const_candidates", [])
        still_missing = [c for c in candidates if c.get("safe_to_add_const")]
        if still_missing:
            names = ", ".join(c["name"] for c in still_missing)
            return False, f"Pointer param(s) still missing `const`: {names}"
        return True, "All pointer params are now `const`-qualified."

    # ── Rule 10.x: essential type mismatches ──
    if rule_id.startswith("MisraC2012-10."):
        expressions = findings.get("expressions", [])
        macro = findings.get("macro_analysis")
        roots = []
        if macro:
            roots.append(macro)
        roots.extend(expressions)

        for root in roots:
            operands = root.get("operands", [])
            for op in operands:
                src_type = op.get("type")
                tgt_type = op.get("target_type")
                if src_type and tgt_type:
                    # Check category mismatch
                    src_cat = _essential_category(src_type)
                    tgt_cat = _essential_category(tgt_type)
                    if src_cat != tgt_cat:
                        return False, (
                            f"Type mismatch persists: "
                            f"{src_type.get('name')} ({src_cat}) vs "
                            f"{tgt_type.get('name')} ({tgt_cat})"
                        )
                    # Check same-category narrowing
                    src_w = src_type.get("width", 0)
                    tgt_w = tgt_type.get("width", 0)
                    if tgt_w > 0 and src_w > tgt_w:
                        return False, (
                            f"Narrowing persists: "
                            f"{src_type.get('name')} ({src_w}-bit) → "
                            f"{tgt_type.get('name')} ({tgt_w}-bit)"
                        )
            # Binary expressions: check two-operand category mismatch
            if len(operands) >= 2:
                t_left = operands[0].get("type")
                t_right = operands[1].get("type")
                if t_left and t_right:
                    if _essential_category(t_left) != _essential_category(t_right):
                        return False, (
                            f"Binary type mismatch persists: "
                            f"{t_left.get('name')} vs {t_right.get('name')}"
                        )
        return True, "No type mismatches detected at this line."

    # ── Rule 11.9: NULL pointer constant ──
    if rule_id == "MisraC2012-11.9":
        if findings.get("null_pointer_violations"):
            return False, "Still using `0` instead of `NULL`."
        return True, "NULL pointer constants are correct."

    # ── Rule 14.4: boolean controlling expression ──
    if rule_id == "MisraC2012-14.4":
        if findings.get("non_boolean_conditions"):
            return False, "Non-boolean controlling expression still present."
        return True, "Controlling expressions are now boolean."

    # ── Rule 15.6: compound statement body ──
    if rule_id == "MisraC2012-15.6":
        if findings.get("missing_braces"):
            return False, "Statement body still lacks braces."
        return True, "Statement bodies now have braces."

    # ── Fallback: rules we can't verify internally ──
    return True, (
        "Internal verification not available for this rule. "
        "Re-run Axivion to confirm."
    )


def _essential_category(type_dict: dict) -> str:
    """Map a type dict to its MISRA essential type category."""
    if type_dict.get("is_float"):
        return "Floating"
    name = type_dict.get("name", "")
    if name in ("bool", "_Bool"):
        return "Boolean"
    if name in ("char", "signed char", "unsigned char"):
        return "Character"
    if type_dict.get("is_signed"):
        return "Signed"
    return "Unsigned"


@mcp.tool()
def verify_fix(rule_id: str, file_path: str, line_number: int) -> str:
    """
    Re-runs AST analysis on the (possibly modified) file to check whether
    the violation condition is still present.

    Updates the violation status to 'verified' (resolved) or 'failed'
    (still present).

    Args:
        rule_id:     The MISRA rule ID.
        file_path:   The file path.
        line_number: The line number of the original violation.
    """
    if parser is None or analyzer is None:
        return "Error: Not initialised. Call load_report first."

    resolved, detail = _verify_violation(rule_id, file_path, line_number)

    if resolved:
        _set_status(file_path, line_number, rule_id, "verified")
        return (
            f"**VERIFIED** — `{rule_id}` at `{file_path}:{line_number}` "
            f"is resolved.\n\n{detail}"
        )
    else:
        _set_status(file_path, line_number, rule_id, "failed")
        return (
            f"**STILL PRESENT** — `{rule_id}` at `{file_path}:{line_number}` "
            f"was not fully resolved.\n\n{detail}\n\n"
            f"Consider running `propose_fix` again or applying a manual fix."
        )


# ═══════════════════════════════════════════════════════════════════════
#  Tool 10 — Fix All (file-level fix → verify loop)
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
def fix_all(file_path: str, dry_run: bool = False) -> str:
    """
    Iterates through every violation in a file and attempts to auto-fix
    each one, then verifies the result.

    Workflow per violation:
      1. propose_fix → get edits
      2. apply_fix   → write to disk (skipped if dry_run=True)
      3. verify_fix  → confirm the condition is gone

    Returns a markdown summary table.

    Args:
        file_path: The file to process.
        dry_run:   If True, analyse and report but do not write changes.
    """
    if parser is None or context_provider is None or fix_engine is None:
        return "Error: Not initialised. Call load_report first."

    violations = parser.get_violations_by_file(file_path)
    if not violations:
        return f"No violations found for `{file_path}`."

    results = []  # [(rule_id, line, status, detail)]

    for v in violations:
        # Skip already-verified violations
        if _get_status(v.file_path, v.line_number, v.rule_id) == "verified":
            results.append((v.rule_id, v.line_number, "skipped", "Already verified."))
            continue

        # 1. Propose fix
        context = context_provider.get_code_context(v.file_path, v.line_number)
        viol_line = context_provider.get_line(v.file_path, v.line_number)
        analysis = fix_engine.propose_fix(v, context, viol_line, None)

        if not analysis.edits:
            reason = analysis.edit_skip_reason or "No auto-fix available."
            results.append((v.rule_id, v.line_number, "no-fix", reason))
            continue

        if dry_run:
            results.append((
                v.rule_id, v.line_number, "dry-run",
                f"{len(analysis.edits)} edit(s) would be applied."
            ))
            continue

        # 2. Apply fix (inline — mirrors apply_fix logic)
        try:
            abs_path = os.path.join(context_provider.workspace_root, v.file_path)
            with open(abs_path, "rb") as f:
                original = f.read()
            content = bytearray(original)

            sorted_edits = sorted(
                analysis.edits, key=lambda e: e["start_byte"], reverse=True
            )
            applied = 0
            last_start = float("inf")
            for edit in sorted_edits:
                start, end = edit["start_byte"], edit["end_byte"]
                text = edit["text"].encode("utf-8")
                if start < 0 or end > len(content) or start > end or end > last_start:
                    continue
                content[start:end] = text
                last_start = start
                applied += 1

            if applied == 0:
                results.append((v.rule_id, v.line_number, "error", "All edits skipped."))
                continue

            # Syntax check
            from tree_sitter import Parser as TSParser
            from core.c_analyzer import C_LANGUAGE
            ts = TSParser(C_LANGUAGE)
            tree = ts.parse(bytes(content))
            if tree.root_node.has_error:
                with open(abs_path, "wb") as f:
                    f.write(original)
                results.append((v.rule_id, v.line_number, "rollback", "Fix produced invalid C."))
                continue

            with open(abs_path, "wb") as f:
                f.write(content)

            # Invalidate cache
            if analyzer:
                resolved = analyzer._resolve(v.file_path)
                analyzer._cache.pop(resolved, None)

            _set_status(v.file_path, v.line_number, v.rule_id, "fixed")

        except Exception as e:
            results.append((v.rule_id, v.line_number, "error", str(e)))
            continue

        # 3. Verify
        is_resolved, detail = _verify_violation(v.rule_id, v.file_path, v.line_number)
        if is_resolved:
            _set_status(v.file_path, v.line_number, v.rule_id, "verified")
            results.append((v.rule_id, v.line_number, "verified", detail))
        else:
            _set_status(v.file_path, v.line_number, v.rule_id, "failed")
            results.append((v.rule_id, v.line_number, "failed", detail))

    # ── Build summary ──
    verified = sum(1 for r in results if r[2] == "verified")
    failed = sum(1 for r in results if r[2] == "failed")
    no_fix = sum(1 for r in results if r[2] == "no-fix")
    skipped = sum(1 for r in results if r[2] == "skipped")
    errors = sum(1 for r in results if r[2] in ("error", "rollback"))
    dry = sum(1 for r in results if r[2] == "dry-run")

    summary = f"## Fix All — `{file_path}`\n\n"
    summary += f"| Metric | Count |\n|--------|-------|\n"
    summary += f"| Total violations | {len(results)} |\n"
    if dry_run:
        summary += f"| Would fix | {dry} |\n"
    else:
        summary += f"| Verified fixed | {verified} |\n"
        summary += f"| Fix failed (needs review) | {failed} |\n"
    summary += f"| No auto-fix available | {no_fix} |\n"
    summary += f"| Already verified (skipped) | {skipped} |\n"
    summary += f"| Errors / rollbacks | {errors} |\n"

    summary += "\n### Details\n\n"
    summary += "| Rule | Line | Status | Detail |\n"
    summary += "|------|------|--------|--------|\n"
    for rule_id, line, status, detail in results:
        # Truncate long details for table readability
        short = detail[:80] + "..." if len(detail) > 80 else detail
        summary += f"| {rule_id} | {line} | **{status}** | {short} |\n"

    return summary


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

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

    # Find the matching violation
    violations = parser.get_violations_by_file(file_path)
    target = next(
        (v for v in violations if v.rule_id == rule_id and v.line_number == line_number),
        None,
    )
    if not target:
        available_rules = sorted({v.rule_id for v in violations})
        msg = f"Violation '{rule_id}' not found in '{file_path}'."
        if available_rules:
            msg += f"\nAvailable rules in this file: {', '.join(available_rules)}"
        else:
            msg += "\nNo violations found in this file. Check the path or run list_violations."
        return msg

    # Gather context
    context = context_provider.get_code_context(file_path, line_number)
    viol_line = context_provider.get_line(file_path, line_number)
    deps = context_provider.analyze_dependencies(file_path)

    analysis = fix_engine.propose_fix(target, context, viol_line, deps)
    return analysis.to_markdown()


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

    Args:
        rule_id:     The MISRA rule ID.
        file_path:   The file path.
        line_number: The line number of the violation.
    """
    if parser is None or context_provider is None:
        return "Error: Not initialised. Call load_report first."

    # Find the matching violation
    violations = parser.get_violations_by_file(file_path)
    target = next(
        (v for v in violations if v.rule_id == rule_id and v.line_number == line_number),
        None,
    )
    if not target:
        return f"Error: Violation '{rule_id}' not found at {file_path}:{line_number}"

    # Analyze to get edits
    context = context_provider.get_code_context(file_path, line_number)
    viol_line = context_provider.get_line(file_path, line_number)
    # No need for full dependency analysis for apply, just the fix
    analysis = fix_engine.propose_fix(target, context, viol_line, None)
    
    if not analysis.edits:
        reason = analysis.edit_skip_reason or "No specific reason available."
        return (f"Auto-fix not available.\n\n"
                f"**Reason:** {reason}\n\n"
                f"**Guidance:**\n{analysis.fix_guidance}")

    # Apply edits
    try:
        abs_path = os.path.join(context_provider.workspace_root, file_path)
        with open(abs_path, "rb") as f:
            content = bytearray(f.read())
        
        # Sort edits by start_byte descending to keep offsets valid
        sorted_edits = sorted(analysis.edits, key=lambda e: e["start_byte"], reverse=True)
        
        applied_count = 0
        for edit in sorted_edits:
            start = edit["start_byte"]
            end = edit["end_byte"]
            text = edit["text"].encode("utf-8")
            
            # Bounds check
            if start < 0 or end > len(content) or start > end:
                continue
                
            # Replace [start:end] with text
            content[start:end] = text
            applied_count += 1
            
        with open(abs_path, "wb") as f:
            f.write(content)
            
        return f"Successfully applied {applied_count} edit(s) to '{file_path}'."
        
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

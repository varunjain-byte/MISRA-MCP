"""
Axivion MISRA Agent — MCP Server

Exposes five tools to GitHub Copilot via the Model Context Protocol:

  1. load_report       — load an Axivion JSON report + workspace root
  2. list_violations   — list all violations for a file
  3. analyze_violation — deep analysis: code context + rule explanation + fix
  4. explain_rule      — full MISRA rule explanation with examples
  5. propose_fix       — concrete, confidence-scored fix suggestion
"""

from mcp.server.fastmcp import FastMCP
import os
import sys

# Ensure core modules are importable
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.axivion_parser import AxivionParser
from core.context_provider import ContextProvider
from core.misra_knowledge_base import format_rule_explanation, get_rule
from core.fix_engine import FixEngine

# ═══════════════════════════════════════════════════════════════════════
#  Server Setup
# ═══════════════════════════════════════════════════════════════════════

mcp = FastMCP("Axivion MISRA Agent")

parser = None
context_provider = None
fix_engine = FixEngine()

# ═══════════════════════════════════════════════════════════════════════
#  Tool 1 — Load Report
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
def load_report(report_path: str, workspace_root: str) -> str:
    """
    Loads the Axivion analysis report and initialises the context provider.

    Args:
        report_path:    Absolute path to the Axivion JSON report.
        workspace_root: Root directory of the workspace containing source code.
    """
    global parser, context_provider

    if not os.path.exists(report_path):
        return f"Error: Report file not found at {report_path}"
    if not os.path.exists(workspace_root):
        return f"Error: Workspace root not found at {workspace_root}"

    try:
        parser = AxivionParser(report_path)
        context_provider = ContextProvider(workspace_root)
        count = len(parser.get_all_violations())
        return f"Successfully loaded report. Found {count} violations."
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
#  Tool 3 — Analyse Violation (enhanced)
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
def analyze_violation(rule_id: str, file_path: str) -> str:
    """
    Returns detailed analysis of a specific violation:
    code context, rule explanation, and a concrete fix suggestion.

    Args:
        rule_id:   The MISRA rule ID (e.g. 'MisraC2012-8.3').
        file_path: The file where the violation occurred.
    """
    if parser is None or context_provider is None:
        return "Error: Not initialised. Call load_report first."

    violations = parser.get_violations_by_file(file_path)
    target = next((v for v in violations if v.rule_id == rule_id), None)
    if not target:
        return f"Violation {rule_id} not found in {file_path}"

    # Gather context
    context = context_provider.get_code_context(file_path, target.line_number)
    viol_line = context_provider.get_line(file_path, target.line_number)
    deps = context_provider.analyze_dependencies(file_path)
    enclosing_fn = context_provider.get_enclosing_function(
        file_path, target.line_number
    )

    # Rule explanation
    rule_info = format_rule_explanation(rule_id)

    # Fix suggestion
    suggestion = fix_engine.propose_fix(target, context, viol_line, deps)

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

{suggestion.to_markdown()}
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
#  Tool 5 — Propose Fix
# ═══════════════════════════════════════════════════════════════════════

@mcp.tool()
def propose_fix(rule_id: str, file_path: str, line_number: int) -> str:
    """
    Returns a concrete, confidence-scored fix suggestion for a specific
    violation at a given line.

    Includes: the violating line, the suggested replacement, an explanation
    of the change, the broader fix strategy, and any side-effect warnings.

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
        return (
            f"No violation {rule_id} found at {file_path}:{line_number}.  "
            f"Use list_violations to see available violations."
        )

    # Gather context
    context = context_provider.get_code_context(file_path, line_number)
    viol_line = context_provider.get_line(file_path, line_number)
    deps = context_provider.analyze_dependencies(file_path)

    suggestion = fix_engine.propose_fix(target, context, viol_line, deps)
    return suggestion.to_markdown()


# ═══════════════════════════════════════════════════════════════════════
#  Entry Point
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    mcp.run()

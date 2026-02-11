# Axivion MISRA C:2012 Compliance Agent — MCP Server

An MCP (Model Context Protocol) server that turns GitHub Copilot into a **MISRA C:2012 compliance assistant**.  It loads Axivion static-analysis reports, explains violations with full rule rationale, and proposes concrete, confidence-scored fixes.

> **Disclaimer**: The MISRA rule knowledge in this tool is derived from publicly
> available summaries and documentation.  It is **not** a substitute for the
> official [MISRA C:2012](https://misra.org.uk/) standard.  For authoritative
> rule text, consult your licensed copy.

---

## Features

| Capability | Description |
|-----------|-------------|
| **Report parsing** | Auto-detects multiple Axivion JSON formats (`issues`, `findings`, `warnings`, `results`, bare arrays) |
| **Rule knowledge base** | 29 MISRA C:2012 rules (2.x, 8.x, 10.x) with rationale, compliant/non-compliant examples, and fix strategies |
| **Fix engine** | Pattern-matching fixes for mechanical rules + context-aware guidance for complex ones |
| **Confidence scoring** | Each fix suggestion is rated HIGH / MEDIUM / LOW |
| **Side-effect warnings** | Cross-file impact analysis for rules affecting headers and callers |

## Architecture

```
┌──────────────────────────────────────────────────┐
│                  GitHub Copilot                   │
│              (MCP Client / LLM Host)              │
└──────────────┬───────────────────────────────────┘
               │  stdio (JSON-RPC)
┌──────────────▼───────────────────────────────────┐
│              fastmcp_server.py                    │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────┐  │
│  │load_report│ │list_viols│ │analyze_violation │  │
│  └──────────┘ └──────────┘ └──────────────────┘  │
│  ┌──────────────┐ ┌──────────────┐               │
│  │ explain_rule  │ │ propose_fix  │               │
│  └──────────────┘ └──────────────┘               │
├──────────────────────────────────────────────────┤
│  core/                                            │
│  ├── axivion_parser.py       (JSON → violations)  │
│  ├── context_provider.py     (code context)       │
│  ├── misra_knowledge_base.py (29 rules)           │
│  └── fix_engine.py           (fix suggestions)    │
└──────────────────────────────────────────────────┘
```

## Prerequisites

- **Python 3.10 or higher** (required by the `mcp` SDK)
- **VS Code** with **GitHub Copilot** extension
- An Axivion JSON report (or use the included mock reports for testing)

## Setup

```bash
# 1. Clone
git clone <your-repo-url>
cd MCP-MISRA

# 2. Create virtual environment (Python 3.10+)
python3.10 -m venv venv
source venv/bin/activate        # macOS / Linux
# venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

## VS Code Configuration

Add the following to your VS Code `settings.json` (User or Workspace):

```json
{
  "mcpServers": {
    "axivion-misra": {
      "command": "/absolute/path/to/venv/bin/python",
      "args": [
        "/absolute/path/to/fastmcp_server.py"
      ],
      "env": {}
    }
  }
}
```

> Replace `/absolute/path/to/` with the actual paths on your machine.

## MCP Tools

### 1. `load_report`
Loads an Axivion JSON report and sets the workspace root for code context.

```
load_report(report_path="/path/to/report.json", workspace_root="/path/to/source")
→ "Successfully loaded report. Found 55 violations."
```

### 2. `list_violations`
Lists all violations in a specific file, with rule titles.

```
list_violations(file_path="src/module.c")
→ **15 violations in src/module.c:**
  - [MisraC2012-8.10] Line 92 (medium): Inline without static
    *Inline function shall be declared static*
  ...
```

### 3. `analyze_violation`
Deep analysis: code context + rule explanation + fix suggestion in one call.

```
analyze_violation(rule_id="MisraC2012-8.10", file_path="src/module.c")
→ Violation Analysis table
  + 30-line code snippet
  + Full rule explanation (rationale, examples)
  + Fix suggestion with confidence score
```

### 4. `explain_rule`
Full MISRA rule reference: title, category, rationale, compliant/non-compliant examples, and fix strategy.

```
explain_rule(rule_id="MisraC2012-10.3")
→ ## MisraC2012-10.3 — Assignment to narrower or different essential type
  **Category**: Required
  ### Rationale ...
  ### Non-Compliant Example ...
  ### Compliant Example ...
  ### How to Fix ...
```

### 5. `propose_fix`
Concrete, confidence-scored fix with before/after code and side-effect warnings.

```
propose_fix(rule_id="MisraC2012-8.10", file_path="src/module.c", line_number=92)
→ ### Fix Suggestion — MisraC2012-8.10
  **Confidence**: HIGH
  #### Before:  inline int square(int x) { ... }
  #### After:   static inline int square(int x) { ... }
  #### ⚠ Potential Side Effects: ...
```

## Supported Axivion JSON Formats

The parser auto-detects these structures:

```jsonc
// Format 1: {"issues": [...]}
{"issues": [{"ruleId": "...", "location": {"path": "...", "startLine": 10}, ...}]}

// Format 2: {"findings": [...]}
{"findings": [{"rule": "...", "file": "...", "line": 10, ...}]}

// Format 3: Top-level array
[{"ruleId": "...", "location": {"path": "...", "startLine": 10}, ...}]
```

Each issue can use various key names — the parser normalises them:
- **Rule ID**: `ruleId`, `rule_id`, `rule`, `checkId`
- **File path**: `location.path`, `location.file`, `file`, `path`
- **Line number**: `location.startLine`, `location.line`, `line`, `startLine`
- **Severity**: `severity`, `priority`, `level`

## MISRA Rules Covered

### Rule 2.x — Unused Code (7 rules)
2.1 Unreachable code · 2.2 Dead code · 2.3 Unused type · 2.4 Unused tag · 2.5 Unused macro · 2.6 Unused label · 2.7 Unused parameter

### Rule 8.x — Declarations & Definitions (14 rules)
8.1 Explicit types · 8.2 Prototype form · 8.3 Consistent declarations · 8.4 Compatible declaration · 8.5 Single extern · 8.6 One external definition · 8.7 No block-scope extern · 8.8 Static for internal · 8.9 Block scope if single use · 8.10 Static inline · 8.11 Extern array size · 8.12 Unique enum values · 8.13 Pointer to const · 8.14 No restrict

### Rule 10.x — Essential Type Model (8 rules)
10.1 Appropriate operand type · 10.2 Character arithmetic · 10.3 Narrowing assignment · 10.4 Same type category · 10.5 Appropriate cast type · 10.6 Composite to wider · 10.7 Composite operand width · 10.8 Composite cast category

## Running Tests

```bash
source venv/bin/activate
python tests/test_logic.py
```

The test suite validates:
- Parser loads 55 violations across 29 rules
- Knowledge base has complete entries for all 29 rules
- Fix engine produces suggestions for every violation
- Mechanical fixes are correct (8.10, 8.14, 8.2, 2.7, 2.1)
- Enhanced context provider features work
- Cross-file side-effect warnings fire for affected rules

## Project Structure

```
MCP-MISRA/
├── fastmcp_server.py           # MCP server entry point (5 tools)
├── requirements.txt            # Python dependencies
├── README.md
├── LICENSE                     # MIT
├── .gitignore
├── core/
│   ├── __init__.py
│   ├── axivion_parser.py       # Multi-format JSON parser
│   ├── context_provider.py     # Code context + function extraction
│   ├── misra_knowledge_base.py # 29 MISRA rules with examples
│   └── fix_engine.py           # Fix suggestions + confidence scoring
└── tests/
    ├── __init__.py
    ├── test_logic.py           # Comprehensive test suite
    ├── mock_report.json        # 55-violation sample report
    ├── mock_code.c             # Basic C mock
    ├── mock_code_rule2x.c      # Rule 2.x edge cases
    ├── mock_code_rule8x.c      # Rule 8.x edge cases
    └── mock_code_rule10x.c     # Rule 10.x edge cases
```

## License

MIT — see [LICENSE](LICENSE).

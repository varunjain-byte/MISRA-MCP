# Axivion MISRA C:2012 Compliance Agent — MCP Server

An MCP (Model Context Protocol) server that turns GitHub Copilot into a **MISRA C:2012 compliance assistant**.  It loads Axivion static-analysis reports, performs **cross-file AST analysis** using tree-sitter, explains violations with full rule rationale, and proposes concrete, confidence-scored fixes — all within your editor.

> **Disclaimer**: The MISRA rule knowledge in this tool is derived from publicly
> available summaries and documentation.  It is **not** a substitute for the
> official [MISRA C:2012](https://misra.org.uk/) standard.  For authoritative
> rule text, consult your licensed copy.

---

## Features

| Capability | Description |
|-----------|-------------|
| **Preprocessor Support** | Handles macro expansion and conditional compilation (`#ifdef`) before analysis, ensuring accurate symbol resolution and dead code elimination |
| **Report parsing** | Auto-detects multiple Axivion JSON formats (`issues`, `findings`, `warnings`, `results`, bare arrays) |
| **Cross-file AST analysis** | tree-sitter-powered workspace indexing: include graph, symbol table, call graph, typedef registry |
| **Rule knowledge base** | 29 MISRA C:2012 rules (2.x, 8.x, 10.x) with rationale, compliant/non-compliant examples, and fix strategies |
| **AST-informed fix engine** | Structural analysis (parameter usage, pointer writes, scope, reachability) for precise fixes |
| **Confidence scoring** | Each fix suggestion is rated HIGH / MEDIUM / LOW based on AST evidence depth |
| **Cross-file impact** | Side-effect warnings showing which files and callers are affected by a change |
| **Windows compatible** | POSIX-normalised path handling with case-insensitive matching for Windows filesystems |

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    GitHub Copilot                     │
│                (MCP Client / LLM Host)                │
└──────────────┬───────────────────────────────────────┘
               │  stdio (JSON-RPC)
┌──────────────▼───────────────────────────────────────┐
│              fastmcp_server.py  (6 tools)             │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────────┐  │
│  │load_report│ │list_viols│ │ analyze_violation    │  │
│  └──────────┘ └──────────┘ └──────────────────────┘  │
│  ┌────────────┐ ┌────────────┐ ┌──────────────────┐  │
│  │explain_rule│ │propose_fix │ │cross_file_impact │  │
│  └────────────┘ └────────────┘ └──────────────────┘  │
├──────────────────────────────────────────────────────┤
│  core/                                                │
│  ├── axivion_parser.py       JSON → violations        │
│  ├── context_provider.py     code context retrieval   │
│  ├── c_analyzer.py           tree-sitter AST analysis │
│  ├── workspace_index.py      cross-file index engine  │
│  ├── misra_knowledge_base.py 29 rules with examples   │
│  └── fix_engine.py           AST-informed fixes       │
└──────────────────────────────────────────────────────┘
```

### Cross-File Analysis Pipeline

When `load_report` is called, the server builds a **WorkspaceIndex** that scans all `.c` and `.h` files:

```
workspace_root/
    ├── *.c, *.h files
    │
    ▼
┌─────────────┐   ┌─────────────┐   ┌───────────┐   ┌──────────────┐
│IncludeGraph │   │SymbolTable  │   │ CallGraph │   │TypeRegistry  │
│             │   │             │   │           │   │              │
│#include     │   │declarations │   │caller →   │   │typedef chain │
│resolution + │   │definitions  │   │callee     │   │resolution    │
│transitive   │   │linkage info │   │mapping    │   │              │
│closure      │   │per file     │   │           │   │              │
└─────────────┘   └─────────────┘   └───────────┘   └──────────────┘
```

This enables 15+ MISRA rules that require cross-translation-unit context  (8.3, 8.4, 8.5, 8.6, 8.8, 8.13, etc.).

## Prerequisites

- **Python 3.10+** (required by the `mcp` SDK)
- **VS Code** with **GitHub Copilot** extension
- An Axivion JSON report (or use the included mock reports for testing)

## Setup

```bash
# 1. Clone
git clone https://github.com/varunjain-byte/MISRA-MCP.git
cd MISRA-MCP

# 2. Create virtual environment
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

> **Windows**: use `venv\\Scripts\\python.exe` for the command path.

## MCP Tools

### 1. `load_report`
Loads an Axivion JSON report, normalises file paths against the workspace, and builds the cross-file index.

```
load_report(report_path="/path/to/report.json", workspace_root="/path/to/source")
→ "Successfully loaded report. Found 55 violations.
   Workspace indexed: 12 .c files, 8 .h files, 94 symbols, 37 call sites."
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
Deep analysis: code context + AST findings + rule explanation + fix suggestion in one call.

```
analyze_violation(rule_id="MisraC2012-8.10", file_path="src/module.c")
→ Violation Analysis table
  + 30-line code snippet
  + Full rule explanation (rationale, examples)
  + AST-informed fix suggestion with confidence score
  + Cross-file impact warnings
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
AST-informed fix with structural evidence, before/after code, and side-effect warnings.

```
propose_fix(rule_id="MisraC2012-8.10", file_path="src/module.c", line_number=92)
→ ### Fix Suggestion — MisraC2012-8.10
  **Confidence**: HIGH
  #### Before:  inline int square(int x) { ... }
  #### After:   static inline int square(int x) { ... }
  #### ⚠ Potential Side Effects: ...
```

### 6. `cross_file_impact`
Shows which files are affected by changing a symbol — declarations, definitions, and callers across the project.

```
cross_file_impact(symbol_name="compute_sum")
→ ### Cross-File Impact: compute_sum
  **Declarations**: utils.h:5
  **Definitions**: utils.c:12
  **Callers**: main.c:25, test_runner.c:40
  **Files affected**: 4
```

### 7. `coverage_report`
Generates a summary of all active MISRA rules.

```
coverage_report()
→ # MISRA C:2012 Coverage Report
  **Total Rules Supported**: 160
  ...
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
- **Rule ID**: `ruleId`, `rule_id`, `rule`, `checkId`, `errorNumber`
- **File path**: `location.path`, `location.file`, `file`, `path`
- **Line number**: `location.startLine`, `location.line`, `line`, `startLine`
- **Severity**: `severity`, `priority`, `level`

## MISRA Rules Covered

The agent now supports **160+ rules** across all major MISRA C:2012 sections.

| Section | Topic | Supported Rules |
|---------|-------|-----------------|
| **2.x** | Unused Code | 2.1 – 2.7 (All) |
| **5.x** | Identifiers | 5.1 – 5.9 |
| **6.x** | Types | 6.1 – 6.2 |
| **7.x** | Literals | 7.1 – 7.4 |
| **8.x** | Declarations | 8.1 – 8.14 (All) |
| **9.x** | Initialization | 9.1 – 9.5 |
| **10.x**| Essential Types | 10.1 – 10.8 (All) |
| **11.x**| Pointer Casting | 11.1 – 11.9 |
| **12.x**| Expressions | 12.1 – 12.4 |
| **13.x**| Side Effects | 13.1 – 13.6 |
| **14.x**| Control Flow | 14.1 – 14.4 |
| **15.x**| Control Flow | 15.1 – 15.7 |
| **16.x**| Switch | 16.1 – 16.7 |
| **17.x**| Functions | 17.1 – 17.8 |
| **18.x**| Pointers | 18.1 – 18.8 |
| **19.x**| Overlapping | 19.1, 19.2 |
| **20.x**| Preprocessor | 20.1 – 20.14 |
| **21.x**| Stdlib | 21.1 – 21.21 |
| **22.x**| Resources | 22.1 – 22.10 |

Run the `coverage_report` tool to see the full list of enabled rules.

## Known Limitations

### Preprocessor

| Limitation | Detail |
|-----------|--------|
| **Macro debugging** | Violations in macros are analyzed by parsing the macro body as an expression. Complex multi-line macros may still require manual verification of the expanded code. |
| **Partial Config** | The preprocessor uses a default configuration. Project-specific defines must be inferred or passed via `include_dirs`. |

### Cross-File Analysis

| Limitation | Detail |
|-----------|--------|
| **No linker-level analysis** | The symbol table is built from AST parsing, not from object files. Symbols introduced by the linker or via weak symbols are not visible. |
| **Include path resolution** | Only `#include "..."` (relative to current file) and workspace-root includes are resolved. System headers (`<stdio.h>`) and external library headers are skipped. Custom include paths can be passed via `include_dirs` parameter. |
| **Typedef depth** | Typedef chains are resolved iteratively up to a reasonable depth, but deeply nested or recursive typedefs through macros may not fully resolve. |
| **Call graph scope** | Call sites are identified syntactically (function call expressions in AST). Indirect calls via function pointers are **not** tracked. |

### Parser & Language Support

| Limitation | Detail |
|-----------|--------|
| **C only** | Supports C89/C99/C11 syntax via tree-sitter-c. C++ features (templates, namespaces, overloading) are not supported. |
| **tree-sitter edge cases** | Very unusual C constructs (K&R function definitions, computed `goto`, GCC statement expressions) may not parse identically to a full compiler. |
| **Binary files** | Files containing null bytes in the first 8 KB are skipped as binary. |
| **Large files** | Context provider caps file reads at 100,000 lines. |

### Fix Engine

| Limitation | Detail |
|-----------|--------|
| **Guidance, not auto-fix** | The engine provides fix suggestions and structural evidence; it does **not** automatically modify source files. The LLM (Copilot) generates the actual code change. |
| **Rule coverage** | Detailed AST-informed analysis is implemented for rules 2.1, 2.7, 8.3–8.14, 10.3. Other rules in the knowledge base use text-based heuristics. |
| **No build integration** | The tool does not compile the code or invoke a build system. It cannot verify that a proposed fix compiles cleanly. |

### Platform

| Limitation | Detail |
|-----------|--------|
| **Path normalisation** | All internal paths are normalised to POSIX forward slashes. Edge cases with UNC paths (`\\\\server\\share`) or very long Windows paths (>260 chars) are untested. |
| **Encoding** | Source files are read as UTF-8 with `errors="replace"`. Non-UTF-8 files will have garbled characters but will not crash. |

## Running Tests

```bash
source venv/bin/activate

# Unit + integration tests
python -m unittest discover tests -v

# Legacy logic tests
python tests/test_logic.py
```

The test suite validates:
- Axivion parser loads 55 violations across 29 rules
- Knowledge base has complete entries for all 29 rules
- Fix engine produces suggestions for every violation
- **Cross-file analysis** (46 tests): workspace indexing, include graph, symbol table, call graph, type registry, and rule-specific checks (8.3, 8.4, 8.5, 8.6, 8.8, 8.13)

## Project Structure

```
MISRA-MCP/
├── fastmcp_server.py           # MCP server entry point (6 tools)
├── requirements.txt            # Python dependencies
├── README.md
├── LICENSE                     # MIT
├── .gitignore
├── core/
│   ├── __init__.py
│   ├── axivion_parser.py       # Multi-format JSON parser + path normalisation
│   ├── context_provider.py     # Code context + function extraction
│   ├── c_analyzer.py           # tree-sitter AST analysis (single-file)
│   ├── workspace_index.py      # Cross-file index (IncludeGraph, SymbolTable,
│   │                           #   CallGraph, TypeRegistry)
│   ├── misra_knowledge_base.py # 29 MISRA rules with examples
│   └── fix_engine.py           # AST-informed fix suggestions
└── tests/
    ├── __init__.py
    ├── test_logic.py           # Unit + integration tests
    ├── test_cross_file.py      # Cross-file analysis tests (46 tests)
    ├── mock_report.json        # 55-violation sample report
    ├── mock_code.c             # Basic C mock
    ├── mock_code_rule2x.c      # Rule 2.x edge cases
    ├── mock_code_rule8x.c      # Rule 8.x edge cases
    ├── mock_code_rule10x.c     # Rule 10.x edge cases
    └── mock_project/           # Multi-file mock for cross-file tests
        ├── config.h
        ├── utils.h
        ├── utils.c
        ├── main.c
        └── other.c
```

## License

MIT — see [LICENSE](LICENSE).

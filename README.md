# Axivion MISRA C:2012 Compliance Agent — MCP Server

An MCP (Model Context Protocol) server that turns **GitHub Copilot into a MISRA C:2012 compliance assistant**. It loads Axivion static-analysis reports, performs **cross-file AST analysis** using tree-sitter, explains violations with full rule rationale, and proposes concrete, confidence-scored fixes — all within your editor.

It goes beyond one-shot fixes: a built-in **fix → verify → retry** loop lets the agent auto-fix violations, re-run AST analysis to confirm resolution, and report what worked, what failed, and what needs manual attention.

> **Disclaimer**: The MISRA rule knowledge in this tool is derived from publicly
> available summaries and documentation. It is **not** a substitute for the
> official [MISRA C:2012](https://misra.org.uk/) standard. For authoritative
> rule text, consult your licensed copy.

---

## Features

| Capability | Description |
|-----------|-------------|
| **10 MCP tools** | Full workflow: load → list → analyze → fix → verify → report |
| **Fix → Verify loop** | `apply_fix` marks status, `verify_fix` re-runs AST checks, `fix_all` automates the full cycle |
| **Violation status tracking** | Every violation is tracked as `pending → fixed → verified / failed`; `list_violations` shows live badges |
| **Preprocessor support** | Handles macro expansion and conditional compilation (`#ifdef`) before analysis |
| **Report parsing** | Auto-detects multiple Axivion JSON formats (`issues`, `findings`, `warnings`, `results`, bare arrays) |
| **Cross-file AST analysis** | tree-sitter-powered workspace indexing: include graph, symbol table, call graph, typedef registry |
| **Rule knowledge base** | 160+ MISRA C:2012 rules with rationale, compliant/non-compliant examples, and fix strategies |
| **AST-informed fix engine** | Structural analysis (parameter usage, pointer writes, scope, reachability, type narrowing) for precise fixes |
| **Confidence scoring** | Each fix is rated HIGH / MEDIUM / LOW based on AST evidence depth |
| **Cross-file impact** | Side-effect warnings showing which files and callers are affected by a change |
| **Windows compatible** | POSIX-normalised path handling with case-insensitive matching |

---

## Architecture

### High-Level Overview

```
┌───────────────────────────────────────────────────────────────┐
│                       GitHub Copilot                           │
│                    (MCP Client / LLM Host)                     │
└───────────────┬───────────────────────────────────────────────┘
                │  stdio (JSON-RPC)
┌───────────────▼───────────────────────────────────────────────┐
│                  fastmcp_server.py  (10 tools)                 │
│                                                                │
│  ┌───────────┐ ┌───────────────┐ ┌───────────────────────┐    │
│  │load_report│ │list_violations│ │ analyze_violation     │    │
│  └───────────┘ └───────────────┘ └───────────────────────┘    │
│  ┌────────────┐ ┌────────────┐ ┌──────────────────┐          │
│  │explain_rule│ │propose_fix │ │cross_file_impact │          │
│  └────────────┘ └────────────┘ └──────────────────┘          │
│  ┌──────────┐ ┌────────────────┐ ┌──────────┐ ┌───────┐     │
│  │apply_fix │ │coverage_report │ │verify_fix│ │fix_all│     │
│  └──────────┘ └────────────────┘ └──────────┘ └───────┘     │
│                                                                │
│  _violation_status: { (file, line, rule) → status }           │
├────────────────────────────────────────────────────────────────┤
│  core/                                                         │
│  ├── axivion_parser.py       JSON → AxivionViolation objects   │
│  ├── context_provider.py     Code context + function lookup    │
│  ├── preprocessor.py         pcpp-based macro expansion        │
│  ├── c_analyzer.py           tree-sitter AST (types, params,   │
│  │                           scope, reachability, expressions) │
│  ├── workspace_index.py      Cross-file index engine           │
│  │   ├── IncludeGraph        #include DAG + transitive closure │
│  │   ├── SymbolTable         declarations / definitions        │
│  │   ├── CallGraph           caller → callee mapping           │
│  │   └── TypeRegistry        typedef chain resolution          │
│  ├── misra_knowledge_base.py 29 core rules (2.x, 8.x, 10.x)  │
│  ├── misra_rules_extended.py 72 extended rules (5.x–22.x)     │
│  ├── fix_engine.py           AST-informed fixes + auto-edits   │
│  └── batch_fixer.py          Multi-file edit application       │
└────────────────────────────────────────────────────────────────┘
```

### How a Fix Flows Through the System

```
User: "fix_all(file_path='src/module.c')"
  │
  ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. LOAD & PARSE                                             │
│    AxivionParser reads JSON report                          │
│    → List[AxivionViolation] (rule_id, file, line, message)  │
│    → Paths normalised to workspace-relative POSIX           │
└──────────────┬──────────────────────────────────────────────┘
               ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. WORKSPACE INDEXING  (built once on load_report)          │
│                                                              │
│    PreprocessorEngine ──→ macro expansion, #ifdef handling   │
│         ↓                                                    │
│    WorkspaceIndex scans all .c/.h files via tree-sitter:     │
│    ┌──────────────┐ ┌────────────┐ ┌──────────┐ ┌────────┐ │
│    │IncludeGraph  │ │SymbolTable │ │CallGraph │ │TypeReg │ │
│    │              │ │            │ │          │ │        │ │
│    │ file A → B,C │ │ fn: decl/  │ │ main()→  │ │uint32→ │ │
│    │ transitive   │ │ def, line, │ │ compute()│ │unsigned│ │
│    │ closure      │ │ linkage    │ │ file:line│ │int     │ │
│    └──────────────┘ └────────────┘ └──────────┘ └────────┘ │
└──────────────┬──────────────────────────────────────────────┘
               ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. AST ANALYSIS  (per violation)                             │
│                                                              │
│    CAnalyzer.analyze_for_rule(file, line, rule_id):          │
│    ├── Parse file with tree-sitter-c                         │
│    ├── Extract FunctionInfo (signature, params, body range)  │
│    ├── Analyse ParamInfo (read/write counts, pointer writes) │
│    ├── Rule-specific enrichment:                             │
│    │   ├── 2.1:  unreachable code detection                  │
│    │   ├── 2.7:  unused parameter identification             │
│    │   ├── 8.x:  cross-file symbol/linkage checks            │
│    │   ├── 10.x: expression type extraction + width model    │
│    │   ├── 11.9: null pointer constant detection             │
│    │   ├── 14.4: boolean controlling expression check        │
│    │   └── 15.6: compound statement body detection           │
│    └── Returns: Dict of structured findings                  │
└──────────────┬──────────────────────────────────────────────┘
               ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. FIX GENERATION                                            │
│                                                              │
│    FixEngine.propose_fix(violation, context, ...):           │
│    ├── Calls CAnalyzer for structural evidence               │
│    ├── Matches rule family → specific generator:             │
│    │   ├── _generate_2_1_edits   (remove dead code)          │
│    │   ├── _generate_2_7_edits   (void-cast unused params)   │
│    │   ├── _generate_8_x_edits   (static/const/restrict)     │
│    │   ├── _generate_8_4_edits   (forward declaration)       │
│    │   ├── _generate_10_x_edits  (type casts, narrowing)     │
│    │   ├── _generate_11_9_edits  (0 → NULL)                  │
│    │   ├── _generate_14_4_edits  (boolean comparisons)       │
│    │   └── _generate_15_6_edits  (brace insertion)           │
│    ├── Produces edits: [{start_byte, end_byte, text}, ...]   │
│    ├── Computes confidence: HIGH / MEDIUM / LOW              │
│    └── Returns: FixAnalysis (edits, guidance, side_effects)  │
└──────────────┬──────────────────────────────────────────────┘
               ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. APPLY & VALIDATE                                          │
│                                                              │
│    apply_fix / fix_all:                                      │
│    ├── Sort edits by byte offset (descending)                │
│    ├── Apply edits to file content (bytearray)               │
│    ├── tree-sitter re-parse to confirm valid C syntax        │
│    │   ├── Valid   → write file, invalidate AST cache        │
│    │   └── Invalid → rollback to original content            │
│    └── Mark violation status: "fixed"                        │
└──────────────┬──────────────────────────────────────────────┘
               ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. VERIFY                                                    │
│                                                              │
│    verify_fix / fix_all:                                     │
│    ├── Invalidate AST cache (force re-parse)                 │
│    ├── Re-run analyze_for_rule on the modified file          │
│    ├── Rule-specific condition check:                        │
│    │   ├── 10.x: type mismatch / narrowing still present?    │
│    │   ├── 2.7:  param still unused?                         │
│    │   ├── 8.x:  still missing static/const?                 │
│    │   └── etc.                                              │
│    ├── Condition gone → status = "verified"  ✓               │
│    └── Condition persists → status = "failed" ✗              │
└─────────────────────────────────────────────────────────────┘
```

### Violation Status State Machine

```
                 load_report
                     │
                     ▼
               ┌──────────┐
               │ pending  │  ← initial state for all violations
               └────┬─────┘
                    │ apply_fix succeeds
                    ▼
               ┌──────────┐
               │  fixed   │  ← syntax-valid edit written to disk
               └────┬─────┘
                    │ verify_fix
              ┌─────┴──────┐
              ▼            ▼
        ┌──────────┐ ┌──────────┐
        │ verified │ │  failed  │
        │    ✓     │ │    ✗     │
        └──────────┘ └──────────┘

list_violations shows:  [FIXED]  [VERIFIED]  [FIX FAILED]
```

---

## How the Code Works

### Core Modules

#### `axivion_parser.py` (277 lines)

Parses Axivion JSON reports into `AxivionViolation` objects. Auto-detects 5+ JSON structures (`issues`, `findings`, `warnings`, `results`, bare arrays) and normalises key names (`ruleId` / `rule_id` / `rule` / `checkId`). Handles path normalisation against the workspace root, including Windows case-insensitivity and suffix-matching fallback.

#### `preprocessor.py` (256 lines)

Wraps [pcpp](https://github.com/ned14/pcpp) to provide C macro expansion and conditional compilation handling. Emits `#line` directives and builds a line mapping so analysis results on expanded source point back to the correct user-facing lines. Used by both `CAnalyzer` and `WorkspaceIndex` for cleaner symbol resolution.

#### `c_analyzer.py` (1,644 lines)

The core AST analysis engine. Uses `tree-sitter-c` to parse C source files and extract:

- **`FunctionInfo`** — name, signature, return type, start/end lines, `static`/`inline` qualifiers
- **`ParamInfo`** — per-parameter read/write counts, pointer-write-through detection, line numbers
- **`CType` / `TypeSystem`** — heuristic type model (8/16/32/64-bit widths), MISRA essential type categories (Boolean, Signed, Unsigned, Floating, Character), and arithmetic promotion rules
- **`SymbolRef`** — scope classification (file, block, external), linkage detection
- **`EnumConstant`** — enumeration values with implicit/explicit tracking

Key methods:
- `analyze_for_rule(file, line, rule_id)` — main entry point; returns rule-specific structured findings
- `_analyze_expression_at_line(file, line)` — extracts binary/assignment/init expressions with type info
- `get_expression_type(node, source)` — infers types from literals, identifiers, cast expressions
- `is_unreachable(file, line)` — dead code detection via control flow analysis

When a `WorkspaceIndex` is attached, cross-file evidence is injected for rules 8.2, 8.3, 8.4, 8.5, 8.6, 8.8, 8.11, and 8.13.

#### `workspace_index.py` (1,261 lines)

Builds four in-memory indices by scanning all `.c` and `.h` files:

| Index | Class | What it tracks |
|-------|-------|----------------|
| **IncludeGraph** | `IncludeGraph` | `#include` resolution + transitive closure; reverse lookup (who includes this file?) |
| **SymbolTable** | `SymbolTable` | Global symbols: declarations vs definitions, file, line, linkage (external/internal/none), signature |
| **CallGraph** | `CallGraph` | Caller → callee relationships; `get_callers(fn)` returns all call sites across the project |
| **TypeRegistry** | `TypeRegistry` | Typedef chain resolution (e.g. `uint32_t_custom → unsigned int`); depth-limited to prevent infinite loops |

Also provides rule-specific check methods: `check_rule_8_3()`, `check_rule_8_4()`, `check_rule_8_5()`, `check_rule_8_6()`, `check_rule_8_8()`, `check_rule_8_11()`, `check_rule_8_13()`.

#### `fix_engine.py` (1,811 lines)

Consumes AST findings from `CAnalyzer` and produces `FixAnalysis` objects containing:

- **Confidence score** — `HIGH` (full AST evidence), `MEDIUM` (partial), `LOW` (heuristic)
- **Edits** — byte-offset-based text replacements: `[{start_byte, end_byte, text}]`
- **Guidance** — human-readable fix description for the LLM
- **Side effects** — warnings about cross-file impact

Rule-specific generators:

| Generator | Rules | What it does |
|-----------|-------|-------------|
| `_generate_2_1_edits` | 2.1 | Removes unreachable code blocks |
| `_generate_2_7_edits` | 2.7 | Inserts `(void)param;` for unused parameters |
| `_generate_8_x_edits` | 8.8, 8.10, 8.13, 8.14 | Adds `static`, `const`, removes `restrict` |
| `_generate_8_4_edits` | 8.4 | Inserts forward declaration before definition |
| `_generate_10_x_edits` | 10.1–10.4, 10.6–10.8 | Inserts explicit type casts (handles narrowing within same category) |
| `_generate_11_9_edits` | 11.9 | Replaces `0` with `NULL` in pointer context |
| `_generate_14_4_edits` | 14.4 | Wraps non-boolean conditions with `!= 0` / `!= NULL` |
| `_generate_15_6_edits` | 15.6 | Wraps single-statement bodies with `{ }` |

For rules without auto-fix support, `_generate_guidance()` produces text-only fix suggestions.

#### `misra_knowledge_base.py` + `misra_rules_extended.py` (1,832 lines combined)

Stores 160+ MISRA C:2012 rules as `MisraRule` dataclass objects:

```python
@dataclass
class MisraRule:
    rule_id: str           # "MisraC2012-10.3"
    title: str             # "Assignment to narrower or different essential type"
    category: str          # "Required" | "Advisory" | "Mandatory"
    rationale: str         # Why this rule exists
    non_compliant: str     # Bad code example
    compliant: str         # Good code example
    fix_strategy: str      # How to fix
    cross_references: list # Related rules
```

The base knowledge base covers 29 core rules (2.x, 8.x, 10.x) with deep examples. The extended module adds 72 rules across sections 5.x–22.x.

#### `fastmcp_server.py` (980 lines)

The MCP server entry point. Exposes 10 tools via `FastMCP` and manages:

- **Module-level state**: parser, analyzer, fix_engine, workspace_index, preprocessor
- **Violation status tracking**: `_violation_status` dict with `_get_status()` / `_set_status()` helpers
- **Progressive violation lookup**: exact match → relaxed line → basename → global search
- **Fix verification**: `_verify_violation()` re-runs AST analysis per rule family

---

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

### Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `mcp[cli]` | >= 1.0.0 | Model Context Protocol SDK |
| `pydantic` | >= 2.0.0 | Data validation for violation models |
| `tree-sitter` | >= 0.23.0 | AST parsing engine |
| `tree-sitter-c` | >= 0.23.0 | C language grammar for tree-sitter |
| `pcpp` | >= 1.30.0 | C preprocessor (macro expansion, `#ifdef`) |

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

---

## MCP Tools

### 1. `load_report`
Loads an Axivion JSON report, normalises file paths against the workspace, and builds the cross-file index. Resets all violation statuses.

```
load_report(report_path="/path/to/report.json", workspace_root="/path/to/source")
→ "Successfully loaded report. Found 55 violations.
   Workspace indexed: 12 .c files, 8 .h files, 94 symbols, 37 call sites.
   Preprocessor Engine initialized."
```

### 2. `list_violations`
Lists all violations in a file with rule titles and **live status badges**.

```
list_violations(file_path="src/module.c")
→ **15 violations in src/module.c** — 3 verified, 1 fixed (unverified):
  - [MisraC2012-8.10] Line 92 (medium) [VERIFIED]: Inline without static
  - [MisraC2012-10.3] Line 45 (high) [FIXED]: Narrower type assignment
  - [MisraC2012-2.7] Line 20 (low) [FIX FAILED]: Unused parameter
  - [MisraC2012-8.13] Line 30 (medium): Pointer could be const
  ...
```

### 3. `analyze_violation`
Deep analysis: code context + AST findings + rule explanation + fix suggestion in one call.

```
analyze_violation(rule_id="MisraC2012-8.10", file_path="src/module.c")
→ Violation Analysis table + code snippet + rule explanation + AST fix analysis
```

### 4. `explain_rule`
Full MISRA rule reference: title, category, rationale, compliant/non-compliant examples, and fix strategy.

```
explain_rule(rule_id="MisraC2012-10.3")
→ ## MisraC2012-10.3 — Assignment to narrower or different essential type
  **Category**: Required ...
```

### 5. `propose_fix`
AST-informed fix with structural evidence, byte-offset edits, and side-effect warnings.

```
propose_fix(rule_id="MisraC2012-8.10", file_path="src/module.c", line_number=92)
→ Confidence: HIGH
  Edits: Insert "(unsigned short)" at offset 142
  Side effects: 3 callers in other files
```

### 6. `cross_file_impact`
Shows which files are affected by changing a symbol — declarations, definitions, and callers.

```
cross_file_impact(symbol_name="compute_sum")
→ Definitions: utils.c:12 | Declarations: utils.h:5
  Callers: main.c:25, test_runner.c:40 | Files affected: 4
```

### 7. `apply_fix`
Applies the auto-fix edits to disk, validates with tree-sitter re-parse, and marks the violation as `fixed`.

```
apply_fix(rule_id="MisraC2012-10.3", file_path="src/module.c", line_number=67)
→ Successfully applied 1 edit(s) to src/module.c.
  Status: marked as "fixed". Run verify_fix to confirm.
```

### 8. `coverage_report`
Summary of all 160+ supported MISRA rules grouped by section.

### 9. `verify_fix`
Re-runs AST analysis on the modified file to confirm the violation condition is gone. Updates status to `verified` or `failed`.

```
verify_fix(rule_id="MisraC2012-10.3", file_path="src/module.c", line_number=67)
→ **VERIFIED** — MisraC2012-10.3 at src/module.c:67 is resolved.
  No type mismatches detected at this line.
```

### 10. `fix_all`
Iterates every violation in a file: propose → apply → verify. Returns a summary table. Supports `dry_run=True`.

```
fix_all(file_path="src/module.c")
→ ## Fix All — src/module.c
  | Metric                    | Count |
  |---------------------------|-------|
  | Total violations          | 15    |
  | Verified fixed            | 8     |
  | Fix failed (needs review) | 2     |
  | No auto-fix available     | 4     |
  | Already verified (skipped)| 1     |
  | Errors / rollbacks        | 0     |
```

---

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

The agent supports **160+ rules** across all major MISRA C:2012 sections.

| Section | Topic | Supported Rules | Auto-Fix |
|---------|-------|-----------------|----------|
| **2.x** | Unused Code | 2.1 – 2.7 (All) | 2.1, 2.7 |
| **5.x** | Identifiers | 5.1 – 5.9 | — |
| **6.x** | Types | 6.1 – 6.2 | — |
| **7.x** | Literals | 7.1 – 7.4 | — |
| **8.x** | Declarations | 8.1 – 8.14 (All) | 8.4, 8.8, 8.10, 8.13, 8.14 |
| **9.x** | Initialization | 9.1 – 9.5 | — |
| **10.x**| Essential Types | 10.1 – 10.8 (All) | 10.1–10.4, 10.6–10.8 |
| **11.x**| Pointer Casting | 11.1 – 11.9 | 11.9 |
| **12.x**| Expressions | 12.1 – 12.4 | — |
| **13.x**| Side Effects | 13.1 – 13.6 | — |
| **14.x**| Control Flow | 14.1 – 14.4 | 14.4 |
| **15.x**| Control Flow | 15.1 – 15.7 | 15.6 |
| **16.x**| Switch | 16.1 – 16.7 | — |
| **17.x**| Functions | 17.1 – 17.8 | — |
| **18.x**| Pointers | 18.1 – 18.8 | — |
| **19.x**| Overlapping | 19.1, 19.2 | — |
| **20.x**| Preprocessor | 20.1 – 20.14 | — |
| **21.x**| Stdlib | 21.1 – 21.21 | — |
| **22.x**| Resources | 22.1 – 22.10 | — |

**Auto-Fix** = the fix engine generates byte-offset edits that can be applied automatically. All other rules provide text-based guidance for the LLM to generate fixes.

Run `coverage_report` to see the full list.

---

## Known Limitations

### Preprocessor

| Limitation | Detail |
|-----------|--------|
| **Macro debugging** | Violations in macros are analyzed by parsing the macro body as an expression. Complex multi-line macros may require manual verification. |
| **Partial config** | Uses default configuration. Project-specific defines must be inferred or passed via `include_dirs`. |

### Cross-File Analysis

| Limitation | Detail |
|-----------|--------|
| **No linker-level analysis** | Symbol table built from AST, not object files. Weak symbols invisible. |
| **Include path resolution** | Only `"..."` (relative) and workspace-root includes resolved. System headers (`<stdio.h>`) skipped. |
| **Typedef depth** | Chains resolved iteratively; deeply nested/recursive typedefs through macros may not resolve. |
| **Call graph scope** | Syntactic call sites only. Indirect calls via function pointers not tracked. |

### Parser & Language

| Limitation | Detail |
|-----------|--------|
| **C only** | C89/C99/C11 via tree-sitter-c. No C++ support. |
| **tree-sitter edge cases** | K&R definitions, computed `goto`, GCC statement expressions may not parse identically to a compiler. |
| **Binary files** | Null bytes in first 8 KB → skipped. |
| **Large files** | Context provider caps at 100,000 lines. |

### Fix Engine

| Limitation | Detail |
|-----------|--------|
| **Auto-fix coverage** | Full edit generation for 2.1, 2.7, 8.x, 10.x, 11.9, 14.4, 15.6. Other rules: text guidance only. |
| **No build integration** | Cannot verify fixes compile cleanly — only tree-sitter syntax validation. |
| **No incremental re-indexing** | Workspace index rebuilt on every `load_report`. |

### Verification

| Limitation | Detail |
|-----------|--------|
| **AST-level only** | `verify_fix` checks AST conditions, not Axivion compliance. A verified fix is confirmed structurally, not by the official static analyzer. |
| **Rule coverage** | Verification supported for 2.x, 8.x, 10.x, 11.9, 14.4, 15.6. Other rules return a fallback ("re-run Axivion to confirm"). |

### Platform

| Limitation | Detail |
|-----------|--------|
| **Path normalisation** | POSIX forward slashes. UNC paths and >260-char Windows paths untested. |
| **Encoding** | UTF-8 with `errors="replace"`. Non-UTF-8 files get garbled characters but don't crash. |

---

## Running Tests

```bash
source venv/bin/activate

# Run all tests (73 pass)
python -m pytest tests/ -v

# Run specific test modules
python -m pytest tests/test_logic.py -v            # Fix engine, 10.x, 8.4, verify_fix
python -m pytest tests/test_cross_file.py -v        # 60 cross-file analysis tests
python -m pytest tests/test_preprocessor.py -v      # Macro expansion & line mapping
python -m pytest tests/test_integration_preprocessor.py -v  # Preprocessor + analyzer

# Legacy test runner
python tests/test_logic.py
```

The test suite validates:
- Axivion parser loads 55 violations across 29 rules
- Knowledge base has complete entries for all core rules
- Fix engine produces suggestions for every violation
- Same-category narrowing auto-fix (e.g. `uint32_t → uint8_t`)
- Rule 8.4 forward declaration insertion
- **Violation status tracking** — `pending → fixed → verified / failed` lifecycle
- **Verify fix logic** — detects persisting violations (10.x narrowing, 2.7 unused params) and confirms resolution after fixes (cast insertion, `(void)x` suppression)
- **Cross-file analysis** (60 tests): workspace indexing, include graph, symbol table, call graph, type registry, and rule-specific checks (8.2, 8.3, 8.4, 8.5, 8.6, 8.8, 8.11, 8.13)
- Preprocessor macro expansion, line mapping, active region detection

---

## Project Structure

```
MISRA-MCP/
├── fastmcp_server.py              # MCP server entry point (10 tools, 980 lines)
├── requirements.txt               # Python dependencies
├── README.md
├── LICENSE                        # MIT
├── .gitignore
├── core/
│   ├── __init__.py
│   ├── axivion_parser.py          # Multi-format JSON parser (277 lines)
│   ├── context_provider.py        # Code context + function extraction (154 lines)
│   ├── preprocessor.py            # pcpp-based macro expansion (256 lines)
│   ├── c_analyzer.py              # tree-sitter AST analysis (1,644 lines)
│   ├── workspace_index.py         # Cross-file index engine (1,261 lines)
│   │   ├── IncludeGraph           #   #include DAG + transitive closure
│   │   ├── SymbolTable            #   declarations / definitions / linkage
│   │   ├── CallGraph              #   caller → callee mapping
│   │   └── TypeRegistry           #   typedef chain resolution
│   ├── misra_knowledge_base.py    # 29 core MISRA rules (959 lines)
│   ├── misra_rules_extended.py    # 72 extended rules (873 lines)
│   ├── fix_engine.py              # AST-informed fix generation (1,811 lines)
│   └── batch_fixer.py             # Multi-file edit helper (92 lines)
└── tests/
    ├── __init__.py
    ├── test_logic.py              # Fix engine + verify_fix tests (720 lines)
    ├── test_cross_file.py         # Cross-file analysis tests (576 lines)
    ├── test_preprocessor.py       # Preprocessor unit tests (149 lines)
    ├── test_integration_preprocessor.py  # Preprocessor + analyzer (73 lines)
    ├── test_hardening.py          # Edge cases + error recovery (225 lines)
    ├── mock_report.json           # 55-violation sample report
    ├── mock_code.c                # Basic C mock
    ├── mock_code_rule2x.c         # Rule 2.x edge cases
    ├── mock_code_rule8x.c         # Rule 8.x edge cases
    ├── mock_code_rule10x.c        # Rule 10.x edge cases
    └── mock_project/              # Multi-file mock for cross-file tests
        ├── config.h
        ├── utils.h
        ├── utils.c
        ├── main.c
        └── other.c
```

**Total**: ~10,000 lines across 13 Python modules + 73 automated tests.

---

## License

MIT — see [LICENSE](LICENSE).

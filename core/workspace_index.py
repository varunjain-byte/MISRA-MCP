"""
Workspace Index — Cross-file analysis for MISRA compliance.

Scans all .c and .h files in a workspace to build:
  • IncludeGraph  — #include resolution and transitive closure
  • SymbolTable   — global declarations, definitions, and their linkage
  • CallGraph     — function call relationships across files
  • TypeRegistry  — typedef chain resolution

This enables 15 MISRA rules that require cross-translation-unit analysis,
such as declaration/definition consistency (8.3), linkage correctness
(8.4–8.8), and API impact analysis (8.13, 8.14).
"""

import os
import re
import logging
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field

import tree_sitter_c as tsc
from tree_sitter import Language, Parser, Node

logger = logging.getLogger(__name__)

C_LANGUAGE = Language(tsc.language())
_parser = Parser(C_LANGUAGE)

# File extensions we index
_C_EXTENSIONS = {".c", ".h", ".cc", ".cpp", ".hh", ".hpp"}


def _norm_path(p: str) -> str:
    """Normalise a path to forward slashes for cross-platform consistency.

    On Windows, os.path.relpath returns backslash-separated paths
    (e.g. 'src\\main.c').  We normalise everything to POSIX forward
    slashes so that stored paths and query paths can be compared
    without platform-specific workarounds.
    """
    return p.replace("\\", "/")


# ═══════════════════════════════════════════════════════════════════════
#  Data types
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class SymbolEntry:
    """A declaration or definition of a symbol."""
    name: str
    file: str             # relative to workspace root
    line: int             # 1-indexed
    kind: str             # "function_def", "function_decl", "variable_def",
                          # "variable_decl", "typedef", "macro", "enum_const",
                          # "struct_tag", "union_tag", "enum_tag"
    linkage: str          # "external", "internal", "none"
    signature: str        # full text of the declaration/definition line
    params: List[str] = field(default_factory=list)  # param type strings for functions


@dataclass
class CallSite:
    """A function call found in source code."""
    caller_file: str      # relative path
    caller_function: str  # enclosing function name (or "<file_scope>")
    caller_line: int
    callee_name: str
    arg_count: int


@dataclass
class TypeAlias:
    """A typedef alias."""
    alias: str
    resolved: str
    file: str
    line: int


# ═══════════════════════════════════════════════════════════════════════
#  Include Graph
# ═══════════════════════════════════════════════════════════════════════

class IncludeGraph:
    """Resolves #include directives and builds a file dependency DAG."""

    def __init__(self, workspace_root: str, include_dirs: Optional[List[str]] = None):
        self.workspace_root = workspace_root
        self.include_dirs = include_dirs or []
        # file -> list of directly included files (all relative to workspace)
        self._direct: Dict[str, List[str]] = {}
        # file -> transitive closure (cached)
        self._transitive_cache: Dict[str, Set[str]] = {}
        # reverse map: header -> set of files that include it
        self._reverse: Dict[str, Set[str]] = {}

    def build(self, files: List[str]):
        """Parse all files and resolve their #include directives."""
        for fpath in files:
            self._direct[fpath] = self._parse_includes(fpath)

        # Build reverse map
        for fpath, includes in self._direct.items():
            for inc in includes:
                self._reverse.setdefault(inc, set()).add(fpath)

    def get_includes(self, file_path: str) -> List[str]:
        """Direct includes of a file."""
        return self._direct.get(file_path, [])

    def get_transitive_includes(self, file_path: str) -> Set[str]:
        """All files transitively included (BFS)."""
        if file_path in self._transitive_cache:
            return self._transitive_cache[file_path]

        visited: Set[str] = set()
        queue = list(self._direct.get(file_path, []))
        while queue:
            inc = queue.pop(0)
            if inc in visited:
                continue
            visited.add(inc)
            queue.extend(self._direct.get(inc, []))

        self._transitive_cache[file_path] = visited
        return visited

    def get_includers(self, header_path: str) -> Set[str]:
        """Files that directly include this header."""
        return self._reverse.get(header_path, set())

    def get_all_includers(self, header_path: str) -> Set[str]:
        """Files that transitively include this header."""
        visited: Set[str] = set()
        queue = list(self._reverse.get(header_path, set()))
        while queue:
            f = queue.pop(0)
            if f in visited:
                continue
            visited.add(f)
            queue.extend(self._reverse.get(f, set()))
        return visited

    def _parse_includes(self, file_path: str) -> List[str]:
        """Extract and resolve #include directives from a file."""
        full_path = os.path.join(self.workspace_root, file_path)
        if not os.path.isfile(full_path):
            return []

        includes = []
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped.startswith("#include"):
                        continue

                    # Match #include "file.h" or #include <file.h>
                    m = re.match(r'#include\s*"([^"]+)"', stripped)
                    if m:
                        resolved = self._resolve_quoted(m.group(1), file_path)
                        if resolved:
                            includes.append(resolved)
                        continue

                    m = re.match(r'#include\s*<([^>]+)>', stripped)
                    if m:
                        resolved = self._resolve_angled(m.group(1))
                        if resolved:
                            includes.append(resolved)
        except Exception as e:
            logger.error("Error reading includes from %s: %s", file_path, e)

        return includes

    def _resolve_quoted(self, include_name: str, current_file: str) -> Optional[str]:
        """Resolve #include "file.h" — relative to current file, then include dirs."""
        # Relative to current file's directory
        current_dir = os.path.dirname(os.path.join(self.workspace_root, current_file))
        candidate = os.path.join(current_dir, include_name)
        if os.path.isfile(candidate):
            return _norm_path(os.path.relpath(candidate, self.workspace_root))

        # Search include directories
        for inc_dir in self.include_dirs:
            full_dir = inc_dir if os.path.isabs(inc_dir) else os.path.join(
                self.workspace_root, inc_dir
            )
            candidate = os.path.join(full_dir, include_name)
            if os.path.isfile(candidate):
                return _norm_path(os.path.relpath(candidate, self.workspace_root))

        # Search workspace root
        candidate = os.path.join(self.workspace_root, include_name)
        if os.path.isfile(candidate):
            return _norm_path(os.path.relpath(candidate, self.workspace_root))

        return None

    def _resolve_angled(self, include_name: str) -> Optional[str]:
        """Resolve #include <file.h> — search include dirs and workspace."""
        for inc_dir in self.include_dirs:
            full_dir = inc_dir if os.path.isabs(inc_dir) else os.path.join(
                self.workspace_root, inc_dir
            )
            candidate = os.path.join(full_dir, include_name)
            if os.path.isfile(candidate):
                return os.path.relpath(candidate, self.workspace_root)

        # Fallback: check workspace root
        candidate = os.path.join(self.workspace_root, include_name)
        if os.path.isfile(candidate):
            return os.path.relpath(candidate, self.workspace_root)

        return None  # system header — not in workspace


# ═══════════════════════════════════════════════════════════════════════
#  Symbol Table
# ═══════════════════════════════════════════════════════════════════════

class SymbolTable:
    """Global symbol registry across all workspace files."""

    def __init__(self):
        # symbol_name -> list of entries (may have decl + def across files)
        self._symbols: Dict[str, List[SymbolEntry]] = {}

    def add(self, entry: SymbolEntry):
        self._symbols.setdefault(entry.name, []).append(entry)

    def find(self, name: str) -> List[SymbolEntry]:
        """All entries for a symbol name."""
        return self._symbols.get(name, [])

    def find_definitions(self, name: str) -> List[SymbolEntry]:
        """Only definitions (not declarations)."""
        return [e for e in self.find(name) if e.kind.endswith("_def")]

    def find_declarations(self, name: str) -> List[SymbolEntry]:
        """Only declarations (not definitions)."""
        return [e for e in self.find(name) if e.kind.endswith("_decl")]

    def find_in_file(self, name: str, file_path: str) -> List[SymbolEntry]:
        """Entries for a symbol in a specific file."""
        nfp = _norm_path(file_path)
        return [e for e in self.find(name) if e.file == nfp]

    def find_header_declaration(self, name: str) -> Optional[SymbolEntry]:
        """Find a declaration in a .h file (for 8.3, 8.4)."""
        for e in self.find(name):
            if e.file.endswith(".h") and e.kind.endswith("_decl"):
                return e
        return None

    def find_duplicate_definitions(self, name: str) -> List[SymbolEntry]:
        """Find symbol with definitions in multiple files (Rule 8.6)."""
        defs = self.find_definitions(name)
        files = set(e.file for e in defs)
        if len(files) > 1:
            return defs
        return []

    def find_duplicate_extern(self, name: str) -> List[SymbolEntry]:
        """Find extern declarations in multiple .c files (Rule 8.5)."""
        externs = [
            e for e in self.find(name)
            if e.linkage == "external" and e.kind.endswith("_decl")
            and e.file.endswith(".c")
        ]
        if len(externs) > 1:
            return externs
        return []

    def is_used_outside_file(self, name: str, source_file: str) -> bool:
        """Check if symbol appears in any file other than source_file (Rule 8.8, 8.9)."""
        nsf = _norm_path(source_file)
        for e in self.find(name):
            if e.file != nsf:
                return True
        return False

    def all_symbols(self) -> Dict[str, List[SymbolEntry]]:
        return dict(self._symbols)

    @property
    def total_entries(self) -> int:
        return sum(len(v) for v in self._symbols.values())


# ═══════════════════════════════════════════════════════════════════════
#  Call Graph
# ═══════════════════════════════════════════════════════════════════════

class CallGraph:
    """Cross-file function call relationships."""

    def __init__(self):
        # callee_name -> list of CallSite
        self._callers: Dict[str, List[CallSite]] = {}
        # caller_function -> list of callee names
        self._callees: Dict[str, List[str]] = {}

    def add(self, site: CallSite):
        self._callers.setdefault(site.callee_name, []).append(site)
        self._callees.setdefault(site.caller_function, []).append(site.callee_name)

    def get_callers(self, function_name: str) -> List[CallSite]:
        """All call sites that invoke this function."""
        return self._callers.get(function_name, [])

    def get_external_callers(self, function_name: str, definition_file: str) -> List[CallSite]:
        """Callers from files other than the definition file (Rule 8.8)."""
        return [
            c for c in self.get_callers(function_name)
            if c.caller_file != definition_file
        ]

    def get_callees(self, function_name: str) -> List[str]:
        """Functions called by this function."""
        return self._callees.get(function_name, [])

    def is_called_externally(self, function_name: str, definition_file: str) -> bool:
        """True if any file besides definition_file calls this function."""
        return len(self.get_external_callers(function_name, definition_file)) > 0

    @property
    def total_call_sites(self) -> int:
        return sum(len(v) for v in self._callers.values())


# ═══════════════════════════════════════════════════════════════════════
#  Type Registry
# ═══════════════════════════════════════════════════════════════════════

class TypeRegistry:
    """Tracks typedefs across the workspace."""

    def __init__(self):
        self._aliases: Dict[str, TypeAlias] = {}

    def add(self, alias: TypeAlias):
        self._aliases[alias.alias] = alias

    def resolve(self, type_name: str) -> str:
        """Follow typedef chains to get the underlying type."""
        visited: Set[str] = set()
        current = type_name
        while current in self._aliases and current not in visited:
            visited.add(current)
            current = self._aliases[current].resolved
        return current

    def get(self, alias: str) -> Optional[TypeAlias]:
        return self._aliases.get(alias)

    @property
    def total_aliases(self) -> int:
        return len(self._aliases)


# ═══════════════════════════════════════════════════════════════════════
#  AST Symbol Extraction Helpers
# ═══════════════════════════════════════════════════════════════════════

def _node_text(node: Node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _find_child(node: Node, type_name: str) -> Optional[Node]:
    """Find first child or grandchild of given type."""
    for child in node.children:
        if child.type == type_name:
            return child
    for child in node.children:
        for gc in child.children:
            if gc.type == type_name:
                return gc
    return None


def _walk_type(node: Node, type_name: str):
    """Yield all descendant nodes of a given type."""
    cursor = node.walk()
    visited = False
    while True:
        if not visited and cursor.node.type == type_name:
            yield cursor.node
        if not visited and cursor.goto_first_child():
            visited = False
            continue
        if cursor.goto_next_sibling():
            visited = False
            continue
        if cursor.goto_parent():
            visited = True
            continue
        break


def _extract_linkage(node: Node, source: bytes) -> str:
    """Determine linkage from storage class specifiers."""
    for child in node.children:
        if child.type == "storage_class_specifier":
            text = _node_text(child, source)
            if text == "static":
                return "internal"
            if text == "extern":
                return "external"
    return "external"  # default for file-scope in C


def _extract_param_types(declarator: Node, source: bytes) -> List[str]:
    """Extract parameter type strings from a function declarator."""
    param_list = _find_child(declarator, "parameter_list")
    if param_list is None:
        return []
    params = []
    for child in param_list.children:
        if child.type == "parameter_declaration":
            text = _node_text(child, source).strip()
            params.append(text)
    return params


def _get_enclosing_function(node: Node, source: bytes) -> str:
    """Get the name of the function containing this node."""
    current = node.parent
    while current:
        if current.type == "function_definition":
            decl = _find_child(current, "function_declarator")
            if decl:
                ident = _find_child(decl, "identifier")
                if ident:
                    return _node_text(ident, source)
            return "<unknown>"
        current = current.parent
    return "<file_scope>"


# ═══════════════════════════════════════════════════════════════════════
#  WorkspaceIndex — Main class
# ═══════════════════════════════════════════════════════════════════════

class WorkspaceIndex:
    """
    Scans an entire workspace to build cross-file analysis structures.

    Usage:
        index = WorkspaceIndex("/path/to/project")
        index.build()
        decl = index.symbols.find_header_declaration("myFunction")
        callers = index.call_graph.get_callers("myFunction")
    """

    def __init__(self, workspace_root: str, include_dirs: Optional[List[str]] = None, preprocessor=None):
        self.workspace_root = workspace_root
        self.preprocessor = preprocessor
        self.include_graph = IncludeGraph(workspace_root, include_dirs)
        self.symbols = SymbolTable()
        self.call_graph = CallGraph()
        self.types = TypeRegistry()
        self._files: List[str] = []
        self._built = False

    @property
    def is_built(self) -> bool:
        return self._built

    def build(self):
        """Scan workspace and build all indexes."""
        self._files = self._discover_files()
        logger.info("WorkspaceIndex: found %d files to index", len(self._files))

        # 1. Build include graph
        self.include_graph.build(self._files)

        # 2. Parse each file for symbols, calls, and types
        for fpath in self._files:
            self._index_file(fpath)

        self._built = True
        logger.info(
            "WorkspaceIndex built: %d symbols, %d call sites, %d type aliases, %d files",
            self.symbols.total_entries,
            self.call_graph.total_call_sites,
            self.types.total_aliases,
            len(self._files),
        )

    def get_summary(self) -> Dict:
        return {
            "files_indexed": len(self._files),
            "symbols": self.symbols.total_entries,
            "call_sites": self.call_graph.total_call_sites,
            "type_aliases": self.types.total_aliases,
            "c_files": len([f for f in self._files if f.endswith(".c")]),
            "h_files": len([f for f in self._files if f.endswith(".h")]),
        }

    # ────────────────────────────────────────────────────────────────
    #  Cross-file queries (used by CAnalyzer and FixEngine)
    # ────────────────────────────────────────────────────────────────

    def check_rule_8_3(self, function_name: str) -> Dict:
        """Rule 8.3: Compare header declaration with definition."""
        header_decl = self.symbols.find_header_declaration(function_name)
        defs = self.symbols.find_definitions(function_name)
        definition = defs[0] if defs else None

        result = {
            "function": function_name,
            "declaration": None,
            "definition": None,
            "consistent": True,
            "mismatches": [],
        }

        if header_decl:
            result["declaration"] = {
                "file": header_decl.file,
                "line": header_decl.line,
                "signature": header_decl.signature,
                "params": header_decl.params,
            }

        if definition:
            result["definition"] = {
                "file": definition.file,
                "line": definition.line,
                "signature": definition.signature,
                "params": definition.params,
            }

        if header_decl and definition:
            mismatches = self._diff_signatures(header_decl, definition)
            result["mismatches"] = mismatches
            result["consistent"] = len(mismatches) == 0

        return result

    def check_rule_8_4(self, function_name: str, definition_file: str) -> Dict:
        """Rule 8.4: Is there a compatible prior declaration visible?"""
        # Check all headers included by the definition file
        headers = self.include_graph.get_transitive_includes(definition_file)
        declarations = []

        for h in headers:
            for e in self.symbols.find_in_file(function_name, h):
                if e.kind == "function_decl":
                    declarations.append({
                        "file": e.file,
                        "line": e.line,
                        "signature": e.signature,
                    })

        # Also check the same file for forward declarations
        for e in self.symbols.find_in_file(function_name, definition_file):
            if e.kind == "function_decl":
                declarations.append({
                    "file": e.file,
                    "line": e.line,
                    "signature": e.signature,
                })

        return {
            "function": function_name,
            "has_prior_declaration": len(declarations) > 0,
            "declarations": declarations,
            "included_headers": list(headers),
        }

    def check_rule_8_5(self, symbol_name: str) -> Dict:
        """Rule 8.5: Is there a duplicate extern in .c files?"""
        duplicates = self.symbols.find_duplicate_extern(symbol_name)
        return {
            "symbol": symbol_name,
            "has_duplicates": len(duplicates) > 1,
            "extern_locations": [
                {"file": e.file, "line": e.line, "signature": e.signature}
                for e in duplicates
            ],
        }

    def check_rule_8_6(self, symbol_name: str) -> Dict:
        """Rule 8.6: Multiple definitions across TUs?"""
        duplicates = self.symbols.find_duplicate_definitions(symbol_name)
        return {
            "symbol": symbol_name,
            "has_multiple_definitions": len(duplicates) > 1,
            "definitions": [
                {"file": e.file, "line": e.line, "signature": e.signature}
                for e in duplicates
            ],
        }

    def check_rule_8_8(self, function_name: str, definition_file: str) -> Dict:
        """Rule 8.8: Is function used only internally? Safe to add static?"""
        ext_callers = self.call_graph.get_external_callers(
            function_name, definition_file
        )
        header_decl = self.symbols.find_header_declaration(function_name)

        return {
            "function": function_name,
            "definition_file": definition_file,
            "has_external_callers": len(ext_callers) > 0,
            "external_callers": [
                {"file": c.caller_file, "line": c.caller_line,
                 "calling_function": c.caller_function}
                for c in ext_callers
            ],
            "declared_in_header": header_decl.file if header_decl else None,
            "safe_to_add_static": len(ext_callers) == 0 and header_decl is None,
        }

    def check_rule_8_13(self, function_name: str) -> Dict:
        """Rule 8.13: Impact analysis for adding const to pointer param."""
        callers = self.call_graph.get_callers(function_name)
        header_decl = self.symbols.find_header_declaration(function_name)

        return {
            "function": function_name,
            "total_callers": len(callers),
            "callers": [
                {"file": c.caller_file, "line": c.caller_line,
                 "calling_function": c.caller_function}
                for c in callers[:20]  # cap to avoid huge output
            ],
            "header_to_update": header_decl.file if header_decl else None,
            "files_affected": list(set(
                [c.caller_file for c in callers] +
                ([header_decl.file] if header_decl else [])
            )),
        }

    # ────────────────────────────────────────────────────────────────
    #  Internal: file discovery
    # ────────────────────────────────────────────────────────────────

    def _discover_files(self) -> List[str]:
        """Find all C/H files in the workspace."""
        files = []
        for root, dirs, filenames in os.walk(self.workspace_root):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in {
                ".git", "build", "cmake-build-debug", "cmake-build-release",
                "__pycache__", "node_modules", ".vscode", ".idea", "venv",
            }]
            for fname in filenames:
                ext = os.path.splitext(fname)[1].lower()
                if ext in _C_EXTENSIONS:
                    rel = _norm_path(os.path.relpath(os.path.join(root, fname), self.workspace_root))
                    files.append(rel)
        return sorted(files)

    # ────────────────────────────────────────────────────────────────
    #  Internal: per-file indexing
    # ────────────────────────────────────────────────────────────────

    # Node types that are preprocessor containers we need to recurse into
    _PREPROC_CONTAINERS = {
        "preproc_ifdef", "preproc_if", "preproc_elif",
        "preproc_else", "preproc_ifndef",
    }

    def _index_file(self, rel_path: str):
        """Parse a single file and extract symbols, calls, types."""
        full_path = os.path.join(self.workspace_root, rel_path)
        try:
            with open(full_path, "rb") as f:
                original_source = f.read()
        except Exception as e:
            logger.error("Cannot read %s: %s", rel_path, e)
            return

        # Skip binary
        if b"\x00" in original_source[:8192]:
            return

        # 1. Parse ORIGINAL source for macros and basic structure
        #    (We always need original source for macros, as pcpp consumes them)
        try:
            tree = _parser.parse(original_source)
            root = tree.root_node
            
            # Extract macros (preprocessor lines — tree-sitter gives us preproc_def)
            for macro_node in _walk_type(root, "preproc_def"):
                self._index_macro(macro_node, original_source, rel_path)
        except Exception as e:
            logger.error("Failed to parse original %s: %s", rel_path, e)

        # 2. Parse source for Symbols and Calls
        #    If preprocessor is available, use expanded source for accuracy
        #    Otherwise fall back to original source
        
        target_source = original_source
        use_mapping = False
        
        if self.preprocessor and rel_path.endswith(".c"):
            try:
                # Use workspace root as include dir, plus explicit include dirs if we knew them.
                # WorkspaceIndex doesn't strictly track include dirs configuration per file.
                # We assume relative paths from workspace root work or are standard.
                expanded, _ = self.preprocessor.preprocess(rel_path, include_dirs=["."])
                if expanded and len(expanded.strip()) > 0:
                    target_source = expanded
                    use_mapping = True
            except Exception as e:
                logger.warning("Preprocessing failed for %s, falling back to raw: %s", rel_path, e)

        try:
            tree = _parser.parse(target_source)
            root = tree.root_node
            
            # Extract symbols and calls
            # We must be careful: if using expanded source, it contains content from included files!
            # We must only index nodes that map back to THIS file.
            
            self._walk_and_index_symbols_calls(root, target_source, rel_path, use_mapping)

        except Exception as e:
            logger.error("Failed to parse target source for %s: %s", rel_path, e)

    def _walk_and_index_symbols_calls(self, node: Node, source: bytes, rel_path: str, use_mapping: bool):
        """Walk AST and index symbols/calls, filtering by file origin if mapped."""
        # Simplified walker that iterates over children
        for child in node.children:
             self._process_node(child, source, rel_path, use_mapping)

    def _process_node(self, node: Node, source: bytes, rel_path: str, use_mapping: bool):
        
        # Check if node belongs to this file
        effective_line = node.start_point[0] + 1
        
        if use_mapping:
            # We check the start line
            orig_file, orig_line = self.preprocessor.get_original_location(rel_path, effective_line)
            
            # If the node comes from another file (include), SKIP IT
            # We only index what is defined IN THIS FILE
            if orig_file != rel_path:
                return
            effective_line = orig_line

        # ── Function Definitions ──
        if node.type == "function_definition":
            self._index_function_def(node, source, rel_path, effective_line, use_mapping)
            return

        # ── Type Definitions ──
        if node.type == "type_definition":
            self._index_typedef(node, source, rel_path, line_override=effective_line)
            return

        # ── Declarations ──
        if node.type == "declaration":
            self._index_declaration(node, source, rel_path, effective_line)
            return
            
        # ── Struct/Union/Enum tags ──
        if node.type in ("struct_specifier", "union_specifier", "enum_specifier"):
            self._index_struct_union_enum(node, source, rel_path, effective_line)
            return

        # Recursive walk for other containers if necessary?
        if node.type in self._PREPROC_CONTAINERS or node.type == "translation_unit":
             for child in node.children:
                 self._process_node(child, source, rel_path, use_mapping)

    def _index_function_def(self, node: Node, source: bytes, rel_path: str, line: int, use_mapping: bool):
        decl = _find_child(node, "function_declarator")
        if decl is None: return
        ident = _find_child(decl, "identifier")
        if ident is None: return

        name = _node_text(ident, source)
        sig = _node_text(node, source).split("{")[0].strip()
        linkage = _extract_linkage(node, source)
        params = _extract_param_types(decl, source)

        self.symbols.add(SymbolEntry(
            name=name, file=rel_path,
            line=line,
            kind="function_def", linkage=linkage,
            signature=sig, params=params,
        ))
        
        # Index call sites in body
        body = _find_child(node, "compound_statement")
        if body:
            self._index_function_body(body, source, rel_path, name, use_mapping)

    def _index_function_body(self, body_node: Node, source: bytes, rel_path: str, caller_name: str, use_mapping: bool):
        # Walk for call_expressions efficiently
        to_visit = [body_node]
        while to_visit:
            curr = to_visit.pop()
            if curr.type == "call_expression":
                # Index call
                func_node = curr.child_by_field_name("function")
                if func_node:
                    callee = _node_text(func_node, source)
                    c_line = curr.start_point[0] + 1
                    
                    # Count arguments
                    arg_list = curr.child_by_field_name("arguments")
                    arg_count = 0
                    if arg_list:
                        # Count explicit arguments (comma separated usually, but tree-sitter structure)
                        # Simply counting named children or specific types might be better
                        # argument_list children are usually ( ) and expressions and commas
                        for child in arg_list.children:
                            if child.type not in ("(", ")", ","):
                                arg_count += 1

                    final_line = c_line
                    should_index = True
                    
                    if use_mapping:
                        orig_file, orig_line = self.preprocessor.get_original_location(rel_path, c_line)
                        if orig_file != rel_path:
                            should_index = False
                        final_line = orig_line
                    
                    if should_index:
                        self.call_graph.add(CallSite(
                            caller_file=rel_path,
                            caller_function=caller_name,
                            caller_line=final_line,
                            callee_name=callee,
                            arg_count=arg_count
                        ))
            
            # Recurse
            to_visit.extend(curr.children)

    def _index_declaration(self, node: Node, source: bytes, rel_path: str, line: int):
        text = _node_text(node, source).strip()
        linkage = _extract_linkage(node, source)

        func_decl = _find_child(node, "function_declarator")
        if func_decl:
             ident = _find_child(func_decl, "identifier")
             if ident:
                 name = _node_text(ident, source)
                 params = _extract_param_types(func_decl, source)
                 self.symbols.add(SymbolEntry(
                    name=name, file=rel_path, line=line,
                    kind="function_decl", linkage=linkage,
                    signature=text, params=params
                 ))
        else:
             # Variable declaration (with or without initializer)
             # Case 1: init_declarator (int x = 1; or int x;) - wait, int x; is usually just identifier sibling to type
             
             init = _find_child(node, "init_declarator")
             if init:
                 ident = _find_child(init, "identifier")
                 if ident:
                     name = _node_text(ident, source)
                     # Determine if definition or declaration
                     has_initializer = any(c.type == "=" for c in init.children)
                     kind = "variable_decl" if (linkage == "external" and not has_initializer) else "variable_def"
                     
                     self.symbols.add(SymbolEntry(
                        name=name, file=rel_path, line=line,
                        kind=kind, linkage=linkage,
                        signature=text
                     ))
             else:
                 # Case 2: Simple declaration: int x; extern int y;
                 # We look for an identifier that NOT a type_identifier
                 for child in node.children:
                     if child.type == "identifier":
                         name = _node_text(child, source)
                         kind = "variable_decl" if linkage == "external" else "variable_def"
                         self.symbols.add(SymbolEntry(
                            name=name, file=rel_path, line=line,
                            kind=kind, linkage=linkage,
                            signature=text
                         ))
                         break

    def _index_struct_union_enum(self, node: Node, source: bytes, rel_path: str, line: int):
        tag = _find_child(node, "type_identifier")
        if tag is None:
            tag = _find_child(node, "identifier")
        if tag:
            tag_name = _node_text(tag, source)
            kind_map = {
                "struct_specifier": "struct_tag",
                "union_specifier": "union_tag",
                "enum_specifier": "enum_tag",
            }
            self.symbols.add(SymbolEntry(
                name=tag_name, file=rel_path,
                line=line,
                kind=kind_map.get(node.type, "struct_tag"),
                linkage="none",
                signature=_node_text(node, source).split("{")[0].strip(),
            ))

        # Enum constants
        if node.type == "enum_specifier":
            body = _find_child(node, "enumerator_list")
            if body:
                for child in body.children:
                    if child.type == "enumerator":
                        ident = _find_child(child, "identifier")
                        if ident:
                            self.symbols.add(SymbolEntry(
                                name=_node_text(ident, source),
                                file=rel_path,
                                line=child.start_point[0] + 1,
                                kind="enum_const", linkage="none",
                                signature=_node_text(child, source),
                            ))

    def _walk_and_index(self, node: Node, source: bytes, rel_path: str):
        """Walk AST and index symbols, recursing into preprocessor blocks."""
        for child in node.children:
            if child.type in self._PREPROC_CONTAINERS:
                # Recurse into #ifdef / #ifndef / #if / #else blocks
                self._walk_and_index(child, source, rel_path)
            else:
                self._index_top_level(child, source, rel_path)

    def _index_top_level(self, node: Node, source: bytes, rel_path: str):
        """Index a top-level AST node."""

        # ── Function definitions ──
        if node.type == "function_definition":
            decl = _find_child(node, "function_declarator")
            if decl is None:
                return
            ident = _find_child(decl, "identifier")
            if ident is None:
                return

            name = _node_text(ident, source)
            sig = _node_text(node, source).split("{")[0].strip()
            linkage = _extract_linkage(node, source)
            params = _extract_param_types(decl, source)

            self.symbols.add(SymbolEntry(
                name=name, file=rel_path,
                line=node.start_point[0] + 1,
                kind="function_def", linkage=linkage,
                signature=sig, params=params,
            ))
            return

        # ── Type definitions (tree-sitter uses 'type_definition' not 'declaration') ──
        if node.type == "type_definition":
            self._index_typedef(node, source, rel_path)
            return

        # ── Declarations (variables, function prototypes) ──
        if node.type == "declaration":
            text = _node_text(node, source).strip()
            linkage = _extract_linkage(node, source)

            # Typedef (fallback — older tree-sitter may use declaration)
            if text.startswith("typedef"):
                self._index_typedef(node, source, rel_path)
                return

            # Check for function declarations (prototypes)
            for child in node.children:
                if child.type == "function_declarator":
                    ident = _find_child(child, "identifier")
                    if ident:
                        name = _node_text(ident, source)
                        params = _extract_param_types(child, source)
                        self.symbols.add(SymbolEntry(
                            name=name, file=rel_path,
                            line=node.start_point[0] + 1,
                            kind="function_decl", linkage=linkage,
                            signature=text.rstrip(";").strip(),
                            params=params,
                        ))
                    return

                # Check inside init_declarator for function declarators
                if child.type == "init_declarator":
                    fn_decl = _find_child(child, "function_declarator")
                    if fn_decl:
                        ident = _find_child(fn_decl, "identifier")
                        if ident:
                            name = _node_text(ident, source)
                            params = _extract_param_types(fn_decl, source)
                            self.symbols.add(SymbolEntry(
                                name=name, file=rel_path,
                                line=node.start_point[0] + 1,
                                kind="function_decl", linkage=linkage,
                                signature=text.rstrip(";").strip(),
                                params=params,
                            ))
                        return

            # Variable declarations
            has_extern = any(
                c.type == "storage_class_specifier" and _node_text(c, source) == "extern"
                for c in node.children
            )

            for child in node.children:
                if child.type == "init_declarator":
                    ident = _find_child(child, "identifier")
                    if ident:
                        name = _node_text(ident, source)
                        has_initializer = any(c.type == "=" for c in child.children)
                        # extern without initializer = declaration, not definition
                        if has_extern and not has_initializer:
                            kind = "variable_decl"
                        elif has_initializer:
                            kind = "variable_def"
                        else:
                            kind = "variable_def"  # tentative definition
                        self.symbols.add(SymbolEntry(
                            name=name, file=rel_path,
                            line=node.start_point[0] + 1,
                            kind=kind, linkage=linkage,
                            signature=text.rstrip(";").strip(),
                        ))

                elif child.type == "identifier":
                    # Simple declaration without initializer: extern int x;
                    parent_types = [c.type for c in node.children]
                    if "init_declarator" not in parent_types:
                        name = _node_text(child, source)
                        # Skip type identifiers
                        prev = None
                        for c in node.children:
                            if c == child and prev and prev.type in (
                                "primitive_type", "sized_type_specifier",
                                "type_qualifier", "storage_class_specifier"
                            ):
                                # extern without initializer = declaration
                                kind = "variable_decl" if has_extern else "variable_def"
                                self.symbols.add(SymbolEntry(
                                    name=name, file=rel_path,
                                    line=node.start_point[0] + 1,
                                    kind=kind, linkage=linkage,
                                    signature=text.rstrip(";").strip(),
                                ))
                                break
                            prev = c

        # ── Struct/Union/Enum tags ──
        if node.type in ("struct_specifier", "union_specifier", "enum_specifier"):
            tag = _find_child(node, "type_identifier")
            if tag is None:
                tag = _find_child(node, "identifier")
            if tag:
                tag_name = _node_text(tag, source)
                kind_map = {
                    "struct_specifier": "struct_tag",
                    "union_specifier": "union_tag",
                    "enum_specifier": "enum_tag",
                }
                self.symbols.add(SymbolEntry(
                    name=tag_name, file=rel_path,
                    line=node.start_point[0] + 1,
                    kind=kind_map.get(node.type, "struct_tag"),
                    linkage="none",
                    signature=_node_text(node, source).split("{")[0].strip(),
                ))

            # Enum constants
            if node.type == "enum_specifier":
                body = _find_child(node, "enumerator_list")
                if body:
                    for child in body.children:
                        if child.type == "enumerator":
                            ident = _find_child(child, "identifier")
                            if ident:
                                self.symbols.add(SymbolEntry(
                                    name=_node_text(ident, source),
                                    file=rel_path,
                                    line=child.start_point[0] + 1,
                                    kind="enum_const", linkage="none",
                                    signature=_node_text(child, source),
                                ))

    def _index_typedef(self, node: Node, source: bytes, rel_path: str, line_override: Optional[int] = None):
        """Extract typedef alias → resolved type."""
        text = _node_text(node, source).strip().rstrip(";")
        line = line_override if line_override is not None else (node.start_point[0] + 1)

        # Find the typedef name (last identifier in the declaration)
        identifiers = []
        for child in _walk_type(node, "type_identifier"):
            identifiers.append(_node_text(child, source))
        for child in _walk_type(node, "identifier"):
            identifiers.append(_node_text(child, source))

        if not identifiers:
            return

        alias_name = identifiers[-1]
        resolved = text.replace("typedef", "").replace(alias_name, "").strip()

        self.symbols.add(SymbolEntry(
            name=alias_name, file=rel_path,
            line=line,
            kind="typedef", linkage="none",
            signature=text,
        ))
        self.types.add(TypeAlias(
            alias=alias_name, resolved=resolved,
            file=rel_path, line=line,
        ))

    def _index_call(self, call_node: Node, source: bytes,
                    rel_path: str, caller_fn: str):
        """Index a function call expression."""
        # Get callee name
        fn_expr = call_node.children[0] if call_node.children else None
        if fn_expr is None:
            return

        callee = None
        if fn_expr.type == "identifier":
            callee = _node_text(fn_expr, source)
        elif fn_expr.type == "field_expression":
            # method-like call (struct->fn(...)), index the field name
            field = _find_child(fn_expr, "field_identifier")
            if field:
                callee = _node_text(field, source)

        if callee is None:
            return

        # Count arguments
        arg_list = _find_child(call_node, "argument_list")
        arg_count = 0
        if arg_list:
            arg_count = sum(1 for c in arg_list.children if c.type not in (",", "(", ")"))

        self.call_graph.add(CallSite(
            caller_file=rel_path,
            caller_function=caller_fn,
            caller_line=call_node.start_point[0] + 1,
            callee_name=callee,
            arg_count=arg_count,
        ))

    def _index_macro(self, node: Node, source: bytes, rel_path: str):
        """Index a #define macro."""
        # preproc_def children: ["#define", identifier, ...]
        ident = _find_child(node, "identifier")
        if ident is None:
            return

        name = _node_text(ident, source)
        self.symbols.add(SymbolEntry(
            name=name, file=rel_path,
            line=node.start_point[0] + 1,
            kind="macro", linkage="none",
            signature=_node_text(node, source).strip(),
        ))

    # ────────────────────────────────────────────────────────────────
    #  Signature diffing for Rule 8.3
    # ────────────────────────────────────────────────────────────────

    @staticmethod
    def _diff_signatures(decl: SymbolEntry, defn: SymbolEntry) -> List[str]:
        """Compare declaration and definition signatures for mismatches."""
        mismatches = []

        decl_params = decl.params
        defn_params = defn.params

        if len(decl_params) != len(defn_params):
            mismatches.append(
                f"Parameter count: declaration has {len(decl_params)}, "
                f"definition has {len(defn_params)}"
            )
            return mismatches

        for i, (dp, fp) in enumerate(zip(decl_params, defn_params)):
            # Normalize whitespace for comparison
            dp_norm = re.sub(r'\s+', ' ', dp.strip())
            fp_norm = re.sub(r'\s+', ' ', fp.strip())

            if dp_norm != fp_norm:
                mismatches.append(
                    f"Parameter {i + 1}: declaration=`{dp_norm}`, "
                    f"definition=`{fp_norm}`"
                )

        return mismatches

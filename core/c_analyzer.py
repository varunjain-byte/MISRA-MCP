"""
C Analyzer — AST-based code analysis using tree-sitter.

Provides deep structural understanding of C source files:
  • Function body extraction (full text, params, return type)
  • Parameter usage analysis (read/write counts)
  • Pointer write-through detection
  • Symbol scope classification (file/block/external)
  • Reachability analysis (code after return/break/continue)
  • Declaration and reference finding
  • Enum constant value computation
  • Cross-file analysis via WorkspaceIndex (optional)
"""

import os
import re
import logging
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, field

import tree_sitter_c as tsc
from tree_sitter import Language, Parser, Node

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════
#  Tree-sitter setup
# ═══════════════════════════════════════════════════════════════════════

C_LANGUAGE = Language(tsc.language())
_parser = Parser(C_LANGUAGE)


# ═══════════════════════════════════════════════════════════════════════
#  Data types
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class ParamInfo:
    """Information about a function parameter."""
    name: str
    type_str: str
    is_pointer: bool = False
    read_count: int = 0
    write_count: int = 0
    read_lines: List[int] = field(default_factory=list)
    write_lines: List[int] = field(default_factory=list)


@dataclass
class FunctionInfo:
    """Structural information about a C function."""
    name: str
    return_type: str
    signature: str          # full signature text
    body_text: str          # full function body including braces
    start_line: int         # 1-indexed
    end_line: int           # 1-indexed
    params: List[ParamInfo] = field(default_factory=list)
    is_static: bool = False
    is_inline: bool = False
    has_prototype: bool = False  # whether a prior declaration exists


@dataclass
class SymbolRef:
    """A reference to a symbol in the source."""
    name: str
    line: int               # 1-indexed
    column: int
    context: str            # surrounding line text
    is_definition: bool = False
    is_declaration: bool = False
    is_write: bool = False


@dataclass
class EnumConstant:
    """An enumeration constant with its computed value."""
    name: str
    value: int
    is_implicit: bool       # value was not explicitly assigned
    line: int


# ═══════════════════════════════════════════════════════════════════════
#  Analyzer
# ═══════════════════════════════════════════════════════════════════════

class CAnalyzer:
    """AST-based C source file analyzer with optional cross-file support."""

    def __init__(self, workspace_root: str, workspace_index=None, preprocessor=None):
        self.workspace_root = workspace_root
        self.index = workspace_index  # Optional WorkspaceIndex for cross-file queries
        self.preprocessor = preprocessor # Optional PreprocessorEngine
        self._cache: Dict[str, Tuple[bytes, object]] = {}  # path -> (source, tree)

    def _resolve(self, file_path: str) -> str:
        """Resolve a (possibly POSIX-style) relative path to an absolute path."""
        # Normalise separators so 'src/main.c' works on Windows too
        native = file_path.replace("/", os.sep).replace("\\", os.sep)
        if os.path.isabs(native):
            return native
        return os.path.join(self.workspace_root, native)

    def _get_tree(self, file_path: str) -> Tuple[Optional[bytes], Optional[object]]:
        """Parse file and cache the result."""
        full = self._resolve(file_path)
        if full in self._cache:
            return self._cache[full]

        if not os.path.isfile(full):
            logger.warning("File not found: %s", full)
            return None, None

        try:
            with open(full, "rb") as f:
                source = f.read()
            # Skip binary files
            if b"\x00" in source[:8192]:
                logger.warning("Skipping binary file: %s", full)
                return None, None
            tree = _parser.parse(source)
            self._cache[full] = (source, tree)
            return source, tree
        except Exception as e:
            logger.error("Failed to parse %s: %s", full, e)
            return None, None

    def _source_lines(self, file_path: str) -> List[str]:
        source, _ = self._get_tree(file_path)
        if source is None:
            return []
        return source.decode("utf-8", errors="replace").splitlines(keepends=True)

    def _node_text(self, node: Node, source: bytes) -> str:
        return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    # ────────────────────────────────────────────────────────────────
    #  Function extraction
    # ────────────────────────────────────────────────────────────────

    def get_functions(self, file_path: str) -> List[FunctionInfo]:
        """Extract all function definitions from the file."""
        source, tree = self._get_tree(file_path)
        if tree is None:
            return []

        functions = []
        for node in self._walk_type(tree.root_node, "function_definition"):
            fn = self._extract_function(node, source, file_path)
            if fn:
                functions.append(fn)
        return functions

    def get_function_at_line(self, file_path: str, line: int) -> Optional[FunctionInfo]:
        """Get the function containing a specific line (1-indexed)."""
        for fn in self.get_functions(file_path):
            if fn.start_line <= line <= fn.end_line:
                return fn
        return None

    def _extract_function(self, node: Node, source: bytes, file_path: str) -> Optional[FunctionInfo]:
        """Build a FunctionInfo from a function_definition node."""
        # Get declarator (contains function name and params)
        declarator = self._find_child(node, "function_declarator")
        if declarator is None:
            # Try direct_declarator inside a pointer_declarator
            ptr_decl = self._find_child(node, "pointer_declarator")
            if ptr_decl:
                declarator = self._find_child(ptr_decl, "function_declarator")
            if declarator is None:
                return None

        # Function name
        name_node = self._find_child(declarator, "identifier")
        if name_node is None:
            return None
        name = self._node_text(name_node, source)

        # Return type — everything before the declarator
        ret_type = self._extract_return_type(node, source)

        # Storage class specifiers
        is_static = "static" in ret_type
        is_inline = "inline" in ret_type

        # Parameters
        param_list = self._find_child(declarator, "parameter_list")
        params = self._extract_params(param_list, source) if param_list else []

        # Signature
        sig = self._node_text(node, source).split("{")[0].strip()

        # Body
        body_node = self._find_child(node, "compound_statement")
        body_text = self._node_text(body_node, source) if body_node else ""

        # Analyze parameter usage within the body
        if body_node and params:
            self._analyze_param_usage(params, body_node, source)

        # Check for prior declaration
        has_prototype = self._has_prior_declaration(name, node, source)

        fn = FunctionInfo(
            name=name,
            return_type=ret_type,
            signature=sig,
            body_text=body_text,
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            params=params,
            is_static=is_static,
            is_inline=is_inline,
            has_prototype=has_prototype,
        )
        return fn

    def _extract_return_type(self, fn_node: Node, source: bytes) -> str:
        """Extract the return type from a function definition."""
        parts = []
        for child in fn_node.children:
            if child.type in ("storage_class_specifier", "type_qualifier",
                              "primitive_type", "sized_type_specifier",
                              "type_identifier", "struct_specifier",
                              "enum_specifier", "union_specifier"):
                parts.append(self._node_text(child, source))
            elif child.type in ("function_declarator", "pointer_declarator",
                                "identifier", "parenthesized_declarator"):
                break
        return " ".join(parts) if parts else "int"  # implicit int

    def _extract_params(self, param_list: Node, source: bytes) -> List[ParamInfo]:
        """Extract parameter info from a parameter_list node."""
        params = []
        for child in param_list.children:
            if child.type == "parameter_declaration":
                name, type_str, is_ptr = self._parse_param_decl(child, source)
                if name:
                    params.append(ParamInfo(
                        name=name, type_str=type_str, is_pointer=is_ptr
                    ))
        return params

    def _parse_param_decl(self, node: Node, source: bytes) -> Tuple[str, str, bool]:
        """Parse a single parameter declaration."""
        full_text = self._node_text(node, source).strip()
        # Find the identifier (parameter name)
        ident = None
        is_ptr = False
        for child in self._walk_all(node):
            if child.type == "identifier" and child.parent and child.parent.type != "type_identifier":
                ident = self._node_text(child, source)
            if child.type == "pointer_declarator" or child.type == "abstract_pointer_declarator":
                is_ptr = True
            if child.type == "*":
                is_ptr = True
        # Type is everything except the name
        type_str = full_text.replace(ident, "").strip() if ident else full_text
        type_str = re.sub(r'\s+', ' ', type_str).strip()
        return ident or "", type_str, is_ptr

    # ────────────────────────────────────────────────────────────────
    #  Parameter usage analysis
    # ────────────────────────────────────────────────────────────────

    def _analyze_param_usage(self, params: List[ParamInfo], body: Node, source: bytes):
        """Count read/write references to each parameter within the function body."""
        param_names = {p.name for p in params}
        param_map = {p.name: p for p in params}

        for node in self._walk_all(body):
            if node.type != "identifier":
                continue
            name = self._node_text(node, source)
            if name not in param_names:
                continue

            line = node.start_point[0] + 1
            p = param_map[name]

            if self._is_write_context(node):
                p.write_count += 1
                p.write_lines.append(line)
            else:
                p.read_count += 1
                p.read_lines.append(line)

    def _is_write_context(self, node: Node) -> bool:
        """Check if an identifier is being written to (LHS of assignment, &, etc.)."""
        parent = node.parent
        if parent is None:
            return False

        # Direct assignment: x = ...
        if parent.type == "assignment_expression":
            if parent.children and parent.children[0] == node:
                return True

        # Compound assignment: x += ...
        if parent.type == "update_expression":
            return True

        # Pointer dereference write: *x = ... or x[i] = ...
        if parent.type == "pointer_expression":
            grandparent = parent.parent
            if grandparent and grandparent.type == "assignment_expression":
                if grandparent.children and grandparent.children[0] == parent:
                    return True

        # Subscript write: x[i] = ...
        if parent.type == "subscript_expression":
            grandparent = parent.parent
            if grandparent and grandparent.type == "assignment_expression":
                if grandparent.children and grandparent.children[0] == parent:
                    return True

        # Address-of (could be write): &x
        if parent.type == "pointer_expression":
            op = self._find_child(parent, "&")
            if op:
                return True  # conservative: treat &x as potential write

        # Unary increment/decrement
        if parent.type in ("update_expression",):
            return True

        return False

    # ────────────────────────────────────────────────────────────────
    #  Reachability analysis
    # ────────────────────────────────────────────────────────────────

    def is_unreachable(self, file_path: str, line: int) -> Optional[str]:
        """
        Check if a line is unreachable (after return/break/continue/goto).
        Returns a reason string if unreachable, None otherwise.
        """
        fn = self.get_function_at_line(file_path, line)
        if fn is None:
            return None

        source, tree = self._get_tree(file_path)
        if tree is None:
            return None

        # Find the compound_statement containing this line
        fn_node = self._find_function_node(tree.root_node, fn.name, source)
        if fn_node is None:
            return None

        body = self._find_child(fn_node, "compound_statement")
        if body is None:
            return None

        return self._check_reachability(body, line, source)

    def _check_reachability(self, block: Node, target_line: int, source: bytes) -> Optional[str]:
        """Check if target_line comes after a terminal statement in the same block."""
        terminal_types = {"return_statement", "break_statement",
                          "continue_statement", "goto_statement"}

        for i, child in enumerate(block.children):
            child_end_line = child.end_point[0] + 1

            if child.type in terminal_types and child_end_line < target_line:
                # Check if the target is a sibling that comes after this terminal
                remaining = block.children[i + 1:]
                for sibling in remaining:
                    sib_start = sibling.start_point[0] + 1
                    sib_end = sibling.end_point[0] + 1
                    if sib_start <= target_line <= sib_end:
                        kind = child.type.replace("_statement", "")
                        return f"Code after '{kind}' statement on line {child_end_line}"

            # Recurse into compound statements but not into sub-scopes like if/for
            if child.type == "compound_statement":
                result = self._check_reachability(child, target_line, source)
                if result:
                    return result

        return None

    # ────────────────────────────────────────────────────────────────
    #  Symbol scope analysis
    # ────────────────────────────────────────────────────────────────

    def get_symbol_scope(self, file_path: str, symbol: str) -> str:
        """
        Classify a symbol's scope: 'external', 'file' (static), 'block', or 'unknown'.
        """
        source, tree = self._get_tree(file_path)
        if tree is None:
            return "unknown"

        for node in self._walk_all(tree.root_node):
            if node.type != "identifier":
                continue
            if self._node_text(node, source) != symbol:
                continue

            decl = self._find_enclosing(node, {
                "declaration", "function_definition", "parameter_declaration"
            })
            if decl is None:
                continue

            decl_text = self._node_text(decl, source)

            # Check if inside a function body
            fn = self._find_enclosing(node, {"function_definition"})
            if fn:
                body = self._find_child(fn, "compound_statement")
                if body and body.start_byte <= node.start_byte <= body.end_byte:
                    if "extern" in decl_text:
                        return "block-extern"
                    return "block"

            # File scope
            if "static" in decl_text:
                return "file"
            if "extern" in decl_text:
                return "external"
            return "external"  # default linkage for file-scope

        return "unknown"

    # ────────────────────────────────────────────────────────────────
    #  Declaration finding
    # ────────────────────────────────────────────────────────────────

    def find_declarations(self, file_path: str, symbol: str) -> List[SymbolRef]:
        """Find all declarations (not definitions) of a symbol."""
        source, tree = self._get_tree(file_path)
        if tree is None:
            return []

        refs = []
        lines = self._source_lines(file_path)

        for node in self._walk_all(tree.root_node):
            if node.type != "identifier":
                continue
            if self._node_text(node, source) != symbol:
                continue

            line = node.start_point[0] + 1
            parent = node.parent

            is_decl = False
            is_def = False

            if parent and parent.type == "function_declarator":
                fn_def = self._find_enclosing(node, {"function_definition"})
                fn_decl = self._find_enclosing(node, {"declaration"})
                if fn_def:
                    is_def = True
                elif fn_decl:
                    is_decl = True

            if parent and parent.type in ("init_declarator", "declaration"):
                is_decl = True
                # Check if it's a definition (has initializer or is a function definition)
                if parent.type == "init_declarator":
                    for c in parent.children:
                        if c.type == "=":
                            is_def = True

            line_text = lines[line - 1].rstrip() if line <= len(lines) else ""
            refs.append(SymbolRef(
                name=symbol, line=line, column=node.start_point[1],
                context=line_text, is_definition=is_def, is_declaration=is_decl,
            ))

        return refs

    def find_all_references(self, file_path: str, symbol: str) -> List[SymbolRef]:
        """Find all references to a symbol (uses + declarations)."""
        source, tree = self._get_tree(file_path)
        if tree is None:
            return []

        refs = []
        lines = self._source_lines(file_path)

        for node in self._walk_all(tree.root_node):
            if node.type != "identifier":
                continue
            if self._node_text(node, source) != symbol:
                continue

            line = node.start_point[0] + 1
            line_text = lines[line - 1].rstrip() if line <= len(lines) else ""

            refs.append(SymbolRef(
                name=symbol, line=line, column=node.start_point[1],
                context=line_text,
                is_write=self._is_write_context(node),
            ))

        return refs

    # ────────────────────────────────────────────────────────────────
    #  Enum analysis
    # ────────────────────────────────────────────────────────────────

    def get_enum_values(self, file_path: str) -> List[EnumConstant]:
        """Extract all enum constants with computed values."""
        source, tree = self._get_tree(file_path)
        if tree is None:
            return []

        constants = []
        for node in self._walk_type(tree.root_node, "enum_specifier"):
            body = self._find_child(node, "enumerator_list")
            if body is None:
                continue

            next_val = 0
            for child in body.children:
                if child.type != "enumerator":
                    continue

                name_node = self._find_child(child, "identifier")
                if name_node is None:
                    continue
                name = self._node_text(name_node, source)

                # Check for explicit value
                val_node = None
                for c in child.children:
                    if c.type == "number_literal":
                        val_node = c
                    elif c.type == "expression" or c.type == "parenthesized_expression":
                        val_node = c

                is_implicit = True
                if val_node:
                    try:
                        val_text = self._node_text(val_node, source)
                        next_val = int(val_text, 0)
                        is_implicit = False
                    except ValueError:
                        pass  # complex expression, keep incrementing

                constants.append(EnumConstant(
                    name=name, value=next_val,
                    is_implicit=is_implicit,
                    line=child.start_point[0] + 1,
                ))
                next_val += 1

        return constants

    def analyze_for_rule(self, file_path: str, line: int, rule_id: str) -> Dict:
        """
        Run rule-specific AST analysis and return structured findings.
        This is the main entry point used by the FixEngine.

        When a WorkspaceIndex is available (self.index), cross-file evidence
        is added for rules 8.3, 8.4, 8.5, 8.6, 8.8, and 8.13.
        """
        analysis = {"rule_id": rule_id, "line": line}
        analysis["has_cross_file"] = self.index is not None and self.index.is_built

        fn = self.get_function_at_line(file_path, line)
        if fn:
            analysis["function"] = {
                "name": fn.name,
                "signature": fn.signature,
                "return_type": fn.return_type,
                "start_line": fn.start_line,
                "end_line": fn.end_line,
                "is_static": fn.is_static,
                "is_inline": fn.is_inline,
                "body_lines": fn.end_line - fn.start_line + 1,
            }
            analysis["params"] = [
                {
                    "name": p.name,
                    "type": p.type_str,
                    "is_pointer": p.is_pointer,
                    "read_count": p.read_count,
                    "write_count": p.write_count,
                    "read_lines": p.read_lines,
                    "write_lines": p.write_lines,
                    "unused": p.read_count == 0 and p.write_count == 0,
                }
                for p in fn.params
            ]
        else:
            analysis["function"] = None
            analysis["params"] = []

        # ── Rule-specific enrichments ──

        if rule_id == "MisraC2012-2.1":
            reason = self.is_unreachable(file_path, line)
            
            # Additional preprocessor check: is the line inside an inactive block?
            # e.g. #if 0 ... #endif
            if self.preprocessor:
                active_regions = self.preprocessor.get_active_regions(file_path)
                # active_regions is list of (start, end) inclusive
                is_active = False
                for start, end in active_regions:
                    if start <= line <= end:
                        is_active = True
                        break
                if not is_active:
                    reason = "Code is inside an inactive preprocessor block (e.g. #if 0)"
            
            analysis["unreachable_reason"] = reason

        elif rule_id == "MisraC2012-2.7" and fn:
            analysis["unused_params"] = [
                p.name for p in fn.params
                if p.read_count == 0 and p.write_count == 0
            ]

        elif rule_id == "MisraC2012-8.3" and fn:
            # ── Cross-file: compare header declaration with definition ──
            if self.index and self.index.is_built:
                analysis["cross_file"] = self.index.check_rule_8_3(fn.name)

        elif rule_id == "MisraC2012-8.4" and fn:
            # ── Cross-file: check for prior declaration in headers ──
            if self.index and self.index.is_built:
                analysis["cross_file"] = self.index.check_rule_8_4(
                    fn.name, file_path
                )

        elif rule_id == "MisraC2012-8.5":
            sym = self._extract_symbol_name(file_path, line)
            if sym:
                analysis["symbol_scope"] = self.get_symbol_scope(file_path, sym)
                if self.index and self.index.is_built:
                    analysis["cross_file"] = self.index.check_rule_8_5(sym)

        elif rule_id == "MisraC2012-8.6":
            sym = self._extract_symbol_name(file_path, line)
            if sym:
                if self.index and self.index.is_built:
                    analysis["cross_file"] = self.index.check_rule_8_6(sym)

        elif rule_id == "MisraC2012-8.8" and fn:
            analysis["needs_static"] = not fn.is_static
            if self.index and self.index.is_built:
                analysis["cross_file"] = self.index.check_rule_8_8(
                    fn.name, file_path
                )
                # Override simple heuristic with cross-file evidence
                cf = analysis["cross_file"]
                analysis["safe_to_add_static"] = cf.get("safe_to_add_static", False)

        elif rule_id == "MisraC2012-8.10" and fn:
            analysis["needs_static"] = fn.is_inline and not fn.is_static

        elif rule_id == "MisraC2012-8.12":
            enums = self.get_enum_values(file_path)
            val_map: Dict[int, List[str]] = {}
            for ec in enums:
                val_map.setdefault(ec.value, []).append(ec.name)
            analysis["enum_collisions"] = {
                v: names for v, names in val_map.items() if len(names) > 1
            }

        elif rule_id == "MisraC2012-8.13" and fn:
            # Single-file: which pointer params are never written through?
            analysis["const_candidates"] = [
                {
                    "name": p.name,
                    "type": p.type_str,
                    "reads": p.read_count,
                    "writes": p.write_count,
                    "safe_to_add_const": p.is_pointer and p.write_count == 0,
                }
                for p in fn.params
                if p.is_pointer
            ]
            # ── Cross-file: caller impact analysis ──
            if self.index and self.index.is_built:
                analysis["cross_file"] = self.index.check_rule_8_13(fn.name)

        elif rule_id.startswith("MisraC2012-8."):
            # Generic linkage analysis for remaining 8.x rules
            sym = self._extract_symbol_name(file_path, line)
            if sym:
                analysis["symbol_scope"] = self.get_symbol_scope(file_path, sym)
                analysis["declarations"] = [
                    {"line": r.line, "context": r.context,
                     "is_definition": r.is_definition}
                    for r in self.find_declarations(file_path, sym)
                ]

        return analysis

    def _extract_symbol_name(self, file_path: str, line: int) -> Optional[str]:
        """Extract the primary identifier from a line of code."""
        lines = self._source_lines(file_path)
        if line > len(lines):
            return None
        line_text = lines[line - 1]
        m = re.search(r'\b(\w+)\s*[(\[;]', line_text)
        return m.group(1) if m else None

    # ────────────────────────────────────────────────────────────────
    #  Tree traversal helpers
    # ────────────────────────────────────────────────────────────────

    @staticmethod
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

    @staticmethod
    def _walk_all(node: Node):
        """Yield all descendant nodes."""
        cursor = node.walk()
        visited = False
        while True:
            if not visited:
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

    @staticmethod
    def _find_child(node: Node, type_name: str) -> Optional[Node]:
        """Find first direct or indirect child of a given type."""
        for child in node.children:
            if child.type == type_name:
                return child
        # Try one level deeper
        for child in node.children:
            for grandchild in child.children:
                if grandchild.type == type_name:
                    return grandchild
        return None

    @staticmethod
    def _find_enclosing(node: Node, types: Set[str]) -> Optional[Node]:
        """Walk up the tree to find the nearest enclosing node of given types."""
        current = node.parent
        while current:
            if current.type in types:
                return current
            current = current.parent
        return None

    def _find_function_node(self, root: Node, name: str, source: bytes) -> Optional[Node]:
        """Find the function_definition node for a named function."""
        for node in self._walk_type(root, "function_definition"):
            decl = self._find_child(node, "function_declarator")
            if decl is None:
                continue
            ident = self._find_child(decl, "identifier")
            if ident and self._node_text(ident, source) == name:
                return node
        return None

    def _has_prior_declaration(self, name: str, fn_node: Node, source: bytes) -> bool:
        """Check if there's a declaration of this function before its definition."""
        root = fn_node.parent
        if root is None:
            return False
        for child in root.children:
            if child == fn_node:
                break
            if child.type == "declaration":
                decl_text = self._node_text(child, source)
                if name in decl_text and "(" in decl_text:
                    return True
        return False

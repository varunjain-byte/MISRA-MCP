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
#  Type System
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class CType:
    """Represents a C type with properties relevant for MISRA analysis."""
    name: str
    width: int              # heuristic width in bits (e.g. 8, 16, 32, 64)
    is_signed: bool
    is_float: bool = False
    is_pointer: bool = False
    
    def __repr__(self):
        s = "signed" if self.is_signed else "unsigned"
        if self.is_float: return f"{self.name} (float{self.width})"
        if self.is_pointer: return f"{self.name} (ptr)"
        return f"{self.name} ({s} {self.width}-bit)"

class TypeSystem:
    """
    Manages C types, standard MISRA essential type models, and arithmetic conversions.

    When a WorkspaceIndex is available, its TypeRegistry is used as a
    fallback to resolve project-specific typedefs (e.g. AUTOSAR ``uint8``,
    ``ErrorStatusType``) by chasing the typedef chain back to a known
    primitive type.
    """

    def __init__(self):
        # Standard primitives (assuming 32-bit int, 64-bit long for analysis)
        self.types: Dict[str, CType] = {
            "void":   CType("void", 0, False),
            "char":   CType("char", 8, True),   # Implementation defined, assume signed for now
            "signed char": CType("signed char", 8, True),
            "unsigned char": CType("unsigned char", 8, False),
            "short":  CType("short", 16, True),
            "unsigned short": CType("unsigned short", 16, False),
            "int":    CType("int", 32, True),
            "unsigned int": CType("unsigned int", 32, False),
            "unsigned": CType("unsigned int", 32, False),
            "long":   CType("long", 64, True),
            "unsigned long": CType("unsigned long", 64, False),
            "float":  CType("float", 32, True, is_float=True),
            "double": CType("double", 64, True, is_float=True),
            "bool":   CType("bool", 1, False),
            "_Bool":  CType("_Bool", 1, False),
        }

        # stdint.h types
        for w in (8, 16, 32, 64):
            self.types[f"int{w}_t"] = CType(f"int{w}_t", w, True)
            self.types[f"uint{w}_t"] = CType(f"uint{w}_t", w, False)

        # Optional typedef resolver (set via set_type_registry)
        self._type_registry = None

    def set_type_registry(self, type_registry) -> None:
        """Attach a WorkspaceIndex TypeRegistry for typedef resolution.

        When ``get_type()`` can't find a name among known primitives, it
        will follow the typedef chain in the registry (e.g.
        ``uint8 → unsigned char → CType``).
        """
        self._type_registry = type_registry

    def register_typedef(self, alias: str, resolved_type: "CType") -> None:
        """Directly register a typedef alias as a known type."""
        self.types[alias] = resolved_type

    def get_type(self, type_name: str) -> Optional[CType]:
        """Resolve a type definition string to a CType.

        Resolution order:
          1. Direct lookup in known types (primitives + stdint)
          2. If a TypeRegistry is attached, follow the typedef chain
             until a known primitive is found
        """
        name = type_name.strip()

        # Handle pointers roughly
        if "*" in name:
            return CType(name, 64, False, is_pointer=True) # Pointers are 64-bit unsigned-ish

        # Strip common qualifiers
        cleaned = re.sub(r'\b(const|volatile|static|register|extern)\b', '', name).strip()
        cleaned = re.sub(r'\s+', ' ', cleaned)

        # 1. Direct lookup
        result = self.types.get(cleaned)
        if result is not None:
            return result

        # 2. Follow typedef chain via workspace TypeRegistry
        if self._type_registry is not None:
            resolved_name = self._type_registry.resolve(cleaned)
            if resolved_name != cleaned:
                # Strip qualifiers from resolved name too
                resolved_clean = re.sub(r'\b(const|volatile|static|register|extern)\b', '', resolved_name).strip()
                resolved_clean = re.sub(r'\s+', ' ', resolved_clean)
                base_type = self.types.get(resolved_clean)
                if base_type is not None:
                    # Cache so future lookups are instant
                    self.types[cleaned] = CType(
                        cleaned, base_type.width, base_type.is_signed,
                        is_float=base_type.is_float,
                        is_pointer=base_type.is_pointer,
                    )
                    return self.types[cleaned]

        return None

    def get_essential_type(self, type_obj: CType) -> str:
        """
        Map to MISRA essential type categories:
        Boolean, Signed, Unsigned, Floating, Character
        """
        if type_obj.name in ("bool", "_Bool"): return "Boolean"
        if type_obj.is_float: return "Floating"
        if type_obj.name in ("char", "signed char", "unsigned char"): return "Character"
        if type_obj.is_signed: return "Signed"
        return "Unsigned"

    def promote(self, left: CType, right: CType) -> CType:
        """
        Determine the result type of a binary operation (Usual Arithmetic Conversions).
        Simplified for essential type analysis.
        """
        if left.is_float or right.is_float:
            return left if left.width >= right.width else right
            
        # Integer promotion rules (simplified)
        # If one is unsigned and wider or equal, result is unsigned
        # If both are signed, larger wins
        
        l_width, r_width = left.width, right.width
        
        if l_width > r_width:
            return left
        elif r_width > l_width:
            return right
        else:
            # Equal width: if either is unsigned, result is unsigned
            if not left.is_signed or not right.is_signed:
                return CType(f"uint{l_width}_t", l_width, False)
            return left

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
        self.type_system = TypeSystem()

        # Wire workspace typedef information into the type system so that
        # project-specific types (uint8, ErrorStatusType, etc.) resolve to
        # their underlying primitive types during analysis.
        if workspace_index is not None and hasattr(workspace_index, 'types'):
            self.type_system.set_type_registry(workspace_index.types)
            logger.info(
                "TypeSystem: attached TypeRegistry with %d aliases",
                workspace_index.types.total_aliases,
            )

    def _resolve(self, file_path: str) -> str:
        """Resolve a (possibly POSIX-style) relative path to an absolute path."""
        # Normalise separators so 'src/main.c' works on Windows too
        native = file_path.replace("/", os.sep).replace("\\", os.sep)
        if os.path.isabs(native):
            return native
        return os.path.join(self.workspace_root, native)

    def _get_tree(self, file_path: str) -> Tuple[Optional[bytes], Optional[object]]:
        """Parse file and cache the result (raw source, no preprocessing)."""
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

    def _get_preprocessed_tree(self, file_path: str) -> Tuple[Optional[bytes], Optional[object]]:
        """Lazily preprocess a single file and return (expanded_source, tree).

        This is the on-demand counterpart to _get_tree().  It runs pcpp
        on *one* file (not the whole workspace) so that macro expansions
        and included typedefs become visible to tree-sitter.  The result
        is cached under a separate key so it doesn't interfere with the
        raw-source cache used for byte-accurate edits.

        Falls back to _get_tree() if no preprocessor is available or
        preprocessing fails.
        """
        full = self._resolve(file_path)
        cache_key = full + "::pp"
        if cache_key in self._cache:
            return self._cache[cache_key]

        if self.preprocessor is None or self.index is None:
            return self._get_tree(file_path)

        # Compute the relative path pcpp expects
        rel_path = file_path.replace(os.sep, "/")
        if os.path.isabs(rel_path):
            rel_path = os.path.relpath(rel_path, self.workspace_root).replace(os.sep, "/")

        try:
            include_dirs = getattr(self.index, 'include_dirs', ["."])
            expanded, _ = self.preprocessor.preprocess(rel_path, include_dirs=include_dirs)
            if expanded and len(expanded.strip()) > 0:
                if isinstance(expanded, str):
                    expanded = expanded.encode("utf-8")
                tree = _parser.parse(expanded)
                self._cache[cache_key] = (expanded, tree)
                logger.info("On-demand preprocessed %s (%d bytes)", rel_path, len(expanded))
                return expanded, tree
        except Exception as e:
            logger.warning("On-demand preprocessing failed for %s, using raw: %s", rel_path, e)

        # Fallback to raw source
        return self._get_tree(file_path)

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
        """Count read/write references to each parameter within the function body.

        Also detects when a pointer parameter is passed as a non-const argument
        to another function (indirect write potential).
        """
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
            elif p.is_pointer and self._is_passed_as_nonconst_arg(node, source):
                # Pointer passed to a function that takes non-const param —
                # treat as potential write (conservative)
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

    def _is_passed_as_nonconst_arg(self, node: Node, source: bytes) -> bool:
        """Check if a pointer identifier is passed as an argument to a function call.

        If the callee's corresponding parameter is not const-qualified, the
        pointer may be written through — so we conservatively treat it as a
        write.  If we cannot determine the callee's parameter types, we
        assume the worst (non-const).
        """
        # Walk up to find if this identifier is inside a call_expression's
        # argument_list
        arg_list = None
        current = node.parent
        depth = 0
        while current and depth < 8:
            if current.type == "argument_list":
                arg_list = current
                break
            # Stop if we've left the immediate expression context
            if current.type in ("compound_statement", "function_definition",
                                "declaration"):
                return False
            current = current.parent
            depth += 1

        if arg_list is None:
            return False

        # The call_expression is arg_list's parent
        call_expr = arg_list.parent
        if call_expr is None or call_expr.type != "call_expression":
            return False

        # Determine which argument position this identifier is in
        arg_index = -1
        for i, child in enumerate(arg_list.children):
            if child.type in (",", "(", ")"):
                continue
            if self._node_contains(child, node):
                arg_index = i // 1  # approximate
                break

        # Try to find the callee's declaration to check if the param is const
        callee_node = call_expr.children[0] if call_expr.children else None
        if callee_node is None:
            return True  # Cannot determine callee — assume non-const

        callee_name = self._node_text(callee_node, source)

        # Well-known safe (const) functions — common C standard library
        _CONST_SAFE_FUNCS = {
            "printf", "fprintf", "sprintf", "snprintf", "puts", "fputs",
            "strlen", "strcmp", "strncmp", "memcmp", "strchr", "strstr",
            "fwrite", "fread", "sizeof", "assert", "free",
        }
        if callee_name in _CONST_SAFE_FUNCS:
            return False

        # Look up the callee in the current TU to check param types
        root = node
        while root.parent:
            root = root.parent
        callee_fn = self._find_function_node(root, callee_name, source)
        if callee_fn:
            decl = self._find_child(callee_fn, "function_declarator")
            if decl:
                param_list = self._find_child(decl, "parameter_list")
                if param_list:
                    params = [c for c in param_list.children
                              if c.type == "parameter_declaration"]
                    # Find the arg_index-th parameter, check for const
                    actual_idx = 0
                    for child in arg_list.children:
                        if child.type in (",", "(", ")"):
                            continue
                        if self._node_contains(child, node):
                            break
                        actual_idx += 1
                    if actual_idx < len(params):
                        param_text = self._node_text(params[actual_idx], source)
                        if "const" in param_text:
                            return False  # Callee takes const — safe

        # Default conservative: treat as potential write
        return True

    @staticmethod
    def _node_contains(ancestor: Node, descendant: Node) -> bool:
        """Check if ancestor contains descendant by byte range."""
        return (ancestor.start_byte <= descendant.start_byte and
                ancestor.end_byte >= descendant.end_byte)

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

    def _get_unreachable_range(self, file_path: str, flagged_line: int,
                               fn: 'FunctionInfo') -> Optional[Dict]:
        """Find all unreachable siblings after the terminal statement.

        Returns {"start_line": int, "end_line": int} covering the full
        unreachable block, so the fixer can remove it in one pass.
        """
        source, tree = self._get_tree(file_path)
        if tree is None:
            return None

        fn_node = self._find_function_node(tree.root_node, fn.name, source)
        if fn_node is None:
            return None

        body = self._find_child(fn_node, "compound_statement")
        if body is None:
            return None

        return self._find_unreachable_range(body, flagged_line, source)

    def _find_unreachable_range(self, block: Node, flagged_line: int,
                                source: bytes) -> Optional[Dict]:
        """Recursively find the range of unreachable siblings in a block."""
        terminal_types = {"return_statement", "break_statement",
                          "continue_statement", "goto_statement"}

        for i, child in enumerate(block.children):
            child_end_line = child.end_point[0] + 1

            if child.type in terminal_types and child_end_line < flagged_line:
                remaining = block.children[i + 1:]
                # Check if flagged_line falls within remaining siblings
                for sibling in remaining:
                    sib_start = sibling.start_point[0] + 1
                    sib_end = sibling.end_point[0] + 1
                    if sib_start <= flagged_line <= sib_end:
                        # Found: collect ALL unreachable siblings after terminal
                        first_unreachable = remaining[0].start_point[0] + 1
                        last_unreachable = remaining[-1].end_point[0] + 1
                        # Don't include the closing brace of the block
                        for r in reversed(remaining):
                            if r.type == "}":
                                continue
                            last_unreachable = r.end_point[0] + 1
                            break
                        return {
                            "start_line": first_unreachable,
                            "end_line": last_unreachable,
                        }

            if child.type == "compound_statement":
                result = self._find_unreachable_range(child, flagged_line, source)
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

            # Compute the full unreachable range so the fixer can remove
            # the entire block, not just the single flagged line
            if reason and fn:
                unreachable_range = self._get_unreachable_range(file_path, line, fn)
                if unreachable_range:
                    analysis["unreachable_range"] = unreachable_range

        elif rule_id == "MisraC2012-2.7" and fn:
            analysis["unused_params"] = [
                p.name for p in fn.params
                if p.read_count == 0 and p.write_count == 0
            ]

        elif rule_id == "MisraC2012-8.2":
            # ── Cross-file: find definition param names for unnamed decl ──
            sym = self._extract_symbol_name(file_path, line) if not fn else fn.name
            if sym and self.index and self.index.is_built:
                analysis["cross_file"] = self.index.check_rule_8_2(sym)

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

        elif rule_id == "MisraC2012-8.11":
            # ── Cross-file: find array definition and extract size ──
            sym = self._extract_symbol_name(file_path, line)
            if sym and self.index and self.index.is_built:
                analysis["cross_file"] = self.index.check_rule_8_11(sym)

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
            # Also checks:
            #   - Already const → skip (not a candidate)
            #   - Passed as non-const arg to another function → counted as write
            analysis["const_candidates"] = [
                {
                    "name": p.name,
                    "type": p.type_str,
                    "reads": p.read_count,
                    "writes": p.write_count,
                    "already_const": "const" in p.type_str,
                    "safe_to_add_const": (p.is_pointer
                                          and p.write_count == 0
                                          and "const" not in p.type_str),
                }
                for p in fn.params
                if p.is_pointer
            ]
            # ── Cross-file: caller impact analysis ──
            if self.index and self.index.is_built:
                analysis["cross_file"] = self.index.check_rule_8_13(fn.name)

        elif rule_id.startswith("MisraC2012-10."):
            # Expression/Type rules
            # First, check if this line is a macro definition
            macro_analysis = self._analyze_macro_definition(file_path, line)
            if macro_analysis:
                analysis["macro_analysis"] = macro_analysis
            else:
                 # Fallback: try to find expressions at this line in the main tree
                 expr_list = self._analyze_expression_at_line(file_path, line)
                 if expr_list:
                     analysis["expressions"] = expr_list

        elif rule_id == "MisraC2012-11.9":
            # Detect usage of '0' as null pointer constant
            # Logic: Find assignments where LHS is pointer and RHS is literal 0
            # Weak heuristic without full type propagation, but catch obvious cases
            # like: int *p = 0; or p = 0;
            assigns = []
            source, tree = self._get_tree(file_path)
            if tree and fn:
                # Limit to function scope for now
                fn_node = self._find_function_node(tree.root_node, fn.name, source)
                if fn_node:
                    for node in self._walk_all(fn_node):
                        # check init_declarator: int *p = 0;
                        if node.type == "init_declarator":
                            val = self._find_child(node, "number_literal")
                            if val and self._node_text(val, source) == "0":
                                # check if decl is pointer
                                decl = self._find_child(node, "pointer_declarator")
                                if decl:
                                    assigns.append({
                                        "line": val.start_point[0] + 1,
                                        "start_byte": val.start_byte,
                                        "end_byte": val.end_byte,
                                        "context": "init"
                                    })
                        # check assignment: p = 0;
                        elif node.type == "assignment_expression":
                            rhs = node.children[-1]
                            if rhs.type == "number_literal" and self._node_text(rhs, source) == "0":
                                lhs = node.children[0]
                                # Heuristic: if LHS is known pointer param check
                                lhs_name = self._node_text(lhs, source)
                                p_info = next((p for p in fn.params if p.name == lhs_name), None)
                                if p_info and p_info.is_pointer:
                                    assigns.append({
                                        "line": rhs.start_point[0] + 1,
                                        "start_byte": rhs.start_byte,
                                        "end_byte": rhs.end_byte,
                                        "context": "assign"
                                    })
            if assigns:
                analysis["null_pointer_violations"] = assigns



        elif rule_id == "MisraC2012-14.4":
            # Controlling expression not essentially boolean
            # if (p), while (x), ternary ? ...
            non_bools = []
            source, tree = self._get_tree(file_path)
            if tree and fn:
                fn_node = self._find_function_node(tree.root_node, fn.name, source)
                if fn_node:
                    for node in self._walk_all(fn_node):
                        cond = None
                        if node.type in ("if_statement", "while_statement", "do_statement"):
                            cond = self._find_child(node, "parenthesized_expression")
                        elif node.type == "for_statement":
                           # for (init; cond; update) - cond is 2nd child usually, but verify
                           for c in node.children:
                               # Condition is an expression between semicolons, usually
                               pass # simplistic for now, focused on if/while
                        
                        if cond:
                            # Strip parens
                            inner = cond.children[1] if len(cond.children) > 2 else cond
                            # Check if inner is comparison or logical
                            # Safe: binary_expression (depends on op), true/false
                            is_safe = False
                            if inner.type == "binary_expression":
                                op = inner.children[1].type
                                if op in ("==", "!=", "<", ">", "<=", ">=", "&&", "||"):
                                    is_safe = True
                            elif inner.type in ("true", "false", "parenthesized_expression"):
                                is_safe = True # simplify
                            
                            if not is_safe:
                                # Determine if the expression is a pointer
                                # (helps the fixer choose != NULL vs != 0)
                                expr_type = self.get_expression_type(inner, source)
                                is_ptr = (expr_type.is_pointer
                                          if expr_type else False)
                                non_bools.append({
                                    "line": inner.start_point[0] + 1,
                                    "start_byte": inner.start_byte,
                                    "end_byte": inner.end_byte,
                                    "text": self._node_text(inner, source),
                                    "is_pointer": is_ptr,
                                })
            if non_bools:
                analysis["non_boolean_conditions"] = non_bools

        elif rule_id == "MisraC2012-15.6":
            # Body not compound statement
            missing_braces = []
            source, tree = self._get_tree(file_path)
            if tree and fn:
                fn_node = self._find_function_node(tree.root_node, fn.name, source)
                if fn_node:
                    for node in self._walk_all(fn_node):
                        check_nodes = []
                        if node.type in ("if_statement", "while_statement", "for_statement"):
                            # Last child is usually the body, unless it's if-else
                            if node.type == "if_statement":
                                # consequence is after condition
                                # alternative is after 'else'
                                children = node.children
                                for i, c in enumerate(children):
                                    if c.type == "parenthesized_expression" and i+1 < len(children):
                                        check_nodes.append(children[i+1])
                                    if c.type == "else" and i+1 < len(children):
                                        check_nodes.append(children[i+1])
                            else:
                                check_nodes.append(node.children[-1])
                        
                        for body in check_nodes:
                            if body.type != "compound_statement" and body.type != "if_statement": # else if is ok structurally if chained
                                 missing_braces.append({
                                    "line": body.start_point[0] + 1,
                                    "start_byte": body.start_byte,
                                    "end_byte": body.end_byte,
                                    "text": self._node_text(body, source)
                                })
            if missing_braces:
                analysis["missing_braces"] = missing_braces

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
        """Extract the primary symbol name declared/defined at a given line.

        Walks the AST looking for a declaration or function definition at the
        specified line and returns the identifier name.  Falls back to a simple
        regex extraction from the source line if the AST walk finds nothing.
        """
        source, tree = self._get_tree(file_path)
        if tree is None:
            return None

        target_row = line - 1  # tree-sitter uses 0-indexed rows

        # Strategy 1: walk top-level declarations for a match at this line
        decl_types = {
            "function_definition", "declaration", "function_declarator",
        }
        for node in self._walk_all(tree.root_node):
            if node.start_point[0] != target_row:
                continue
            if node.type == "function_definition":
                # Find the function_declarator → identifier
                for child in self._walk_type(node, "function_declarator"):
                    for gc in child.children:
                        if gc.type == "identifier":
                            return self._node_text(gc, source)
            if node.type in ("declaration", "init_declarator"):
                for child in node.children:
                    if child.type == "identifier":
                        return self._node_text(child, source)
                    if child.type in ("function_declarator", "init_declarator",
                                      "array_declarator", "pointer_declarator"):
                        for gc in self._walk_all(child):
                            if gc.type == "identifier":
                                return self._node_text(gc, source)

        # Strategy 2: regex fallback on the source line
        lines = self._source_lines(file_path)
        if 0 < line <= len(lines):
            text = lines[line - 1]
            # Match common patterns: type name; / type name( / extern type name
            m = re.search(r'\b(\w+)\s*[(\[;=]', text)
            if m:
                # Skip C keywords
                kw = {"if", "else", "for", "while", "do", "switch", "case",
                       "return", "sizeof", "typedef", "struct", "union",
                       "enum", "extern", "static", "inline", "const",
                       "volatile", "void", "int", "char", "short", "long",
                       "float", "double", "unsigned", "signed", "_Bool"}
                candidates = re.findall(r'\b(\w+)\s*[(\[;=]', text)
                for c in candidates:
                    if c not in kw:
                        return c

        return None

    def _analyze_macro_definition(self, file_path: str, line: int) -> Optional[Dict]:
        """
        If the line is a #define, try to parse its body as an expression.
        Returns AST analysis of the macro body if successful.
        """
        source, tree = self._get_tree(file_path)
        if tree is None:
            return None

        # Find the preproc_def node at this line
        macro_node = None
        for node in self._walk_all(tree.root_node):
             if node.start_point[0] + 1 == line and node.type == "preproc_def":
                 macro_node = node
                 break
        
        if not macro_node:
             return None

        # Extract macro body: usually the last child is the 'value'
        # e.g. #define FOO (a + b) -> value is (a + b)
        # Tree-sitter structure for preproc_def: name, value (preproc_arg)
        
        # We need the raw text after the identifier
        ident = self._find_child(macro_node, "identifier")
        if not ident:
             return None
        
        # Get everything after the identifier from source
        macro_text = self._node_text(macro_node, source)
        ident_text = self._node_text(ident, source)
        
        # Basic split to get body
        parts = macro_text.split(ident_text, 1)
        if len(parts) < 2:
            return None
        
        body_text = parts[1].strip()
        if not body_text:
             return None

        # Calculate absolute start byte of the body in the source file
        # ident.end_byte gives us the end of the identifier.
        # We need to skip whitespace after identifier.
        current_byte = ident.end_byte
        while current_byte < len(source) and chr(source[current_byte]).isspace():
            current_byte += 1
        body_start_byte = current_byte

        # Wrap in a dummy function to parse as expression
        # void _dummy() { __MACRO_BODY__; }
        prefix = "void _dummy() { "
        dummy_source = f"{prefix}{body_text}; }}"
        
        try:
            dummy_tree = _parser.parse(dummy_source.encode("utf-8"))
            # Find the expression statement in the dummy tree
            fn_node = self._find_child(dummy_tree.root_node, "function_definition")
            if fn_node:
                body = self._find_child(fn_node, "compound_statement")
                if body:
                    # The first child should be our expression statement
                    stmt = self._find_child(body, "expression_statement")
                    if stmt:
                         expr = stmt.children[0] if stmt.children else None
                         if expr:
                             # Unwrap parenthesized_expression if present
                             while expr.type == "parenthesized_expression" and len(expr.children) >= 3:
                                 # child 1 is the inner expression ( ( expr ) )
                                 expr = expr.children[1]
                             
                             analysis = self._analyze_expression_node(expr, dummy_source.encode("utf-8"))
                             analysis["body_start_byte"] = body_start_byte
                             analysis["prefix_len"] = len(prefix)
                             return analysis
        except Exception as e:
            logger.warning("Failed to parse macro body for analysis: %s", e)

        return {"raw_body": body_text}

    def _analyze_expression_at_line(self, file_path: str, line: int) -> List[Dict]:
        """Find all relevant expressions at the given line."""
        source, tree = self._get_tree(file_path)
        if not tree:
            return []
            
        # Find all binary or assignment expressions strictly contained in the line
        # or covering the line if they are single-line
        results = []
        seen = set()
        
        for node in self._walk_all(tree.root_node):
            # Check if node is on the target line
            # node.start_point is (row, col)
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            
            # We care about nodes that "contain" the violation on this line.
            # Usually simple expressions are single-line.
            # If multi-line, we might include them if they start or end on this line?
            # Let's restrict to nodes identified as expressions on this line.
            if start_line <= line <= end_line:
                if node.type in ("binary_expression", "assignment_expression", "cast_expression", "init_declarator"):
                    logger.debug("Found %s at %d-%d", node.type, start_line, end_line)
                    # Avoid duplicates (tree walk visits same node once, but avoid logic errors)
                    if node.id in seen:
                        continue
                        
                    # We want 'significant' expressions.
                    # _analyze_expression_node handles these types.
                    seen.add(node.id)
                    results.append(self._analyze_expression_node(node, source))
        
        return results

    def _analyze_expression_node(self, node: Node, source: bytes) -> Dict:
        """Analyze an expression node for operators and operands."""
        info = {
            "type": node.type,
            "text": self._node_text(node, source),
            "start_byte": node.start_byte,
            "end_byte": node.end_byte,
            "operator": None,
            "operands": []
        }
        
        # Binary expression: left OP right
        if node.type == "binary_expression":
            # Operator is the child that is not an expression usually
            # Tree-sitter: left, operator, right
             if len(node.children) >= 3:
                 left = node.children[0]
                 op = node.children[1]
                 right = node.children[2]
                 
                 info["left"] = self._node_text(left, source)
                 info["operator"] = self._node_text(op, source)
                 info["right"] = self._node_text(right, source)
                 
                 t_left = self.get_expression_type(left, source)
                 t_right = self.get_expression_type(right, source)
                 
                 info["operands"] = [
                     {
                         "text": info["left"], 
                         "start_byte": left.start_byte, 
                         "end_byte": left.end_byte,
                         "type": t_left.__dict__ if t_left else None
                     },
                     {
                         "text": info["right"], 
                         "start_byte": right.start_byte, 
                         "end_byte": right.end_byte,
                         "type": t_right.__dict__ if t_right else None
                     }
                 ]

        # Cast expression: (type)value
        elif node.type == "cast_expression":
             type_node = self._find_child(node, "type_descriptor")
             val_node = node.children[-1]
             info["cast_to"] = self._node_text(type_node, source) if type_node else "?"
             info["operand"] = self._node_text(val_node, source)
             
             t_op = self.get_expression_type(val_node, source)
             info["operands"] = [
                 {
                     "text": info["operand"],
                     "start_byte": val_node.start_byte,
                     "end_byte": val_node.end_byte,
                     "type": t_op.__dict__ if t_op else None
                 }
             ]

        # Assignment expression: lhs = rhs
        elif node.type == "assignment_expression":
            operator = None
            for child in node.children:
                if child.type in ("=", "+=", "-=", "*=", "/=", "%=",
                                  "<<=", ">>=", "&=", "^=", "|="):
                    operator = child.text.decode() if hasattr(child.text, 'decode') else str(child.text)
                    break
            # Skip compound assignments — too complex to cast safely
            if operator and operator != "=":
                return info
            lhs = node.child_by_field_name("left")
            rhs = node.child_by_field_name("right")
            if lhs and rhs:
                info["operator"] = "="
                lhs_type = self._resolve_identifier_type(lhs, source)
                rhs_type = self.get_expression_type(rhs, source)
                info["operands"] = [
                    {
                        "text": self._node_text(rhs, source),
                        "start_byte": rhs.start_byte,
                        "end_byte": rhs.end_byte,
                        "type": rhs_type.__dict__ if rhs_type else None,
                        "target_type": lhs_type.__dict__ if lhs_type else None,
                    }
                ]

        # Init declarator: type x = expr;
        elif node.type == "init_declarator":
            value = node.child_by_field_name("value")
            if value:
                decl_type = self._extract_init_declarator_type(node, source)
                val_type = self.get_expression_type(value, source)
                info["operator"] = "="
                info["operands"] = [
                    {
                        "text": self._node_text(value, source),
                        "start_byte": value.start_byte,
                        "end_byte": value.end_byte,
                        "type": val_type.__dict__ if val_type else None,
                        "target_type": decl_type.__dict__ if decl_type else None,
                    }
                ]

        return info

    def _extract_init_declarator_type(self, init_decl_node: Node, source: bytes) -> Optional["CType"]:
        """Walk up to parent 'declaration' node and extract the type specifier.

        For ``uint8_t x = expr;`` the tree-sitter AST looks like:
            declaration
              type_identifier "uint8_t"
              init_declarator
                identifier "x"
                = "="
                <value>
        We collect all type-related children before the first init_declarator.
        """
        parent = init_decl_node.parent
        if parent and parent.type == "declaration":
            type_parts: list[str] = []
            for child in parent.children:
                if child.type in ("type_identifier", "primitive_type",
                                  "sized_type_specifier", "type_qualifier"):
                    type_parts.append(self._node_text(child, source))
                elif child.type == "init_declarator":
                    break  # stop before declarator
            if type_parts:
                type_name = " ".join(type_parts)
                return self.type_system.get_type(type_name)
        return None

    # ────────────────────────────────────────────────────────────────
    #  Type Inference
    # ────────────────────────────────────────────────────────────────

    def get_expression_type(self, node: Node, source: bytes) -> Optional[CType]:
        """Infer the type of an expression node."""
        if node.type == "number_literal":
            text = self._node_text(node, source)
            if "f" in text.lower():
                return self.type_system.get_type("float")
            if "u" in text.lower():
                # Heuristic: verify width based on value?
                # For now assume minimal fitting unsigned or int
                return self.type_system.get_type("unsigned int")
            return self.type_system.get_type("int")
            
        if node.type == "string_literal":
            return CType("char *", 64, False, is_pointer=True)
            
        if node.type == "identifier":
            return self._resolve_identifier_type(node, source)
            
        if node.type == "binary_expression":
            left = node.children[0]
            right = node.children[2]
            t_left = self.get_expression_type(left, source)
            t_right = self.get_expression_type(right, source)
            
            if t_left and t_right:
                return self.type_system.promote(t_left, t_right)
            return t_left or t_right
            
        if node.type == "cast_expression":
            type_node = self._find_child(node, "type_descriptor")
            if type_node:
                type_name = self._node_text(type_node, source)
                return self.type_system.get_type(type_name)

        if node.type == "parenthesized_expression":
             # ( expr ) -> type of expr
             for child in node.children:
                 if child.type not in ("(", ")"):
                      return self.get_expression_type(child, source)

        return None

    def _resolve_identifier_type(self, node: Node, source: bytes) -> Optional[CType]:
        """Find declaration of identifier and return its type."""
        name = self._node_text(node, source)
        
        # 1. Local scope (declaration inside function)
        # Walk up to find Decl
        current = node
        while current:
            if current.type == "compound_statement":
                # Scan declarations in this block BEFORE the usage
                for child in current.children:
                    if child.end_byte > node.start_byte:
                        break # passed the usage point
                    if child.type == "declaration":
                        # int x;
                         t = self._extract_type_from_decl(child, name, source)
                         if t: return t
            
            if current.type == "function_definition":
                # Check parameters
                declarator = self._find_child(current, "function_declarator")
                if declarator:
                    params = self._find_child(declarator, "parameter_list")
                    if params:
                        for p in params.children:
                            if p.type == "parameter_declaration":
                                t = self._extract_type_from_decl(p, name, source)
                                if t: return t
            
            current = current.parent
            
        # 2. File scope (global variables)
        root = node
        while root.parent:
            root = root.parent
            
        for child in root.children:
            if child.type == "declaration":
                t = self._extract_type_from_decl(child, name, source)
                if t: return t
                
        return None

    def _extract_type_from_decl(self, decl_node: Node, name: str, source: bytes) -> Optional[CType]:
        """Extract type for 'name' from a declaration node."""
        # This is a bit complex as C declarations are nested.
        # Simplified: look for type_identifier and matches of declarator
        
        decl_text = self._node_text(decl_node, source)
        if name not in decl_text:
            return None
            
        # Parse type specifier (int, uint16_t, etc)
        type_str = "int" # default
        
        # Collect type parts
        parts = []
        for child in decl_node.children:
            if child.type in ("primitive_type", "type_identifier", "sized_type_specifier", 
                              "storage_class_specifier", "type_qualifier"):
                parts.append(self._node_text(child, source))
                
        if parts:
            type_str = " ".join(parts)
            
        # Check if the specific identifier is declared here
        # (int a, b;)
        # We need to find the declarator that matches 'name'
        # to check for pointers/arrays
        
        is_ptr = False
        
        def find_decl(n):
            nonlocal is_ptr
            if n.type == "identifier" and self._node_text(n, source) == name:
                return True
            if n.type == "pointer_declarator":
                if find_decl(n.children[1]):
                    is_ptr = True
                    return True
            if n.type in ("init_declarator", "declaration", "parameter_declaration"):
                for c in n.children:
                    if find_decl(c): return True
            return False

        if find_decl(decl_node):
             if is_ptr:
                 type_str += "*"
             return self.type_system.get_type(type_str)
             
        return None

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


import os
import io
import re
import logging
from typing import List, Dict, Optional, Tuple, Set
from pcpp import Preprocessor, OutputDirective, Action

logger = logging.getLogger(__name__)


class _QuietPreprocessor(Preprocessor):
    """A pcpp Preprocessor that silences 'Include file not found' stderr noise.

    By default pcpp prints every missing-include error to stderr via
    ``on_error()``, which floods the VS Code output panel.  This subclass
    redirects those messages to Python's ``logging`` at DEBUG level and
    silently passes through unfound includes so preprocessing can continue.
    """

    def on_include_not_found(self, is_malformed, is_system_include, curdir, includepath):
        logger.debug("pcpp: include not found: %s (system=%s)", includepath, is_system_include)
        raise OutputDirective(Action.IgnoreAndPassThrough)

    def on_error(self, file, line, msg):
        # Redirect all pcpp errors to debug logging instead of stderr
        logger.debug("pcpp: %s:%s: %s", file, line, msg)

class PreprocessorEngine:
    """
    A C preprocessor wrapper using 'pcpp'.
    
    It expands macros and handles conditional compilation (#ifdef, etc.),
    returning the expanded source code. Crucially, it parses the #line
    directives emitted by pcpp to map line numbers in the expanded source
    back to the original source file, ensuring that analysis results
    point to the correct user-facing lines.
    """

    def __init__(self, workspace_root: str):
        self.workspace_root = workspace_root
        # Cache: file_path -> (expanded_source_bytes, line_map, defined_macros)
        self._cache: Dict[str, Tuple[bytes, List[Tuple[int, int]], Dict[str, str]]] = {}
        # Pre-defined macros (e.g. from compiler or user config)
        self.defines: Dict[str, str] = {}

    def add_define(self, name: str, value: str = "1"):
        """Add a global macro definition (e.g. -DDEBUG=1)."""
        self.defines[name] = value

    def preprocess(self, file_path: str, include_dirs: Optional[List[str]] = None) -> Tuple[bytes, List[Tuple[int, int]]]:
        """
        Preprocess a file and return (expanded_source, line_map).
        
        Args:
            file_path: Relative path to the source file in workspace.
            include_dirs: List of include directories (relative to workspace).
            
        Returns:
            expanded_source: UTF-8 encoded bytes of the expanded code.
            line_map: A list of (expanded_line, original_line) tuples.
                      Since pcpp emits #line directives, we use this to track
                      where each block of code came from.
        """
        if file_path in self._cache:
            return self._cache[file_path][0], self._cache[file_path][1]

        full_path = os.path.join(self.workspace_root, file_path)
        if not os.path.isfile(full_path):
            logger.error("Preprocessor: file not found %s", full_path)
            return b"", []

        # Setup pcpp (using quiet subclass to suppress stderr noise)
        pp = _QuietPreprocessor()
        
        # Add includes
        if include_dirs:
            for d in include_dirs:
                abs_dir = os.path.join(self.workspace_root, d)
                pp.add_path(abs_dir)
        
        # Add global defines
        for k, v in self.defines.items():
            pp.define(f"{k} {v}")

        # Capture output
        output_buffer = io.StringIO()
        
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                pp.parse(f.read(), source=file_path)
            pp.write(output_buffer)
        except Exception as e:
            logger.error("Preprocessing failed for %s: %s", file_path, e)
            return b"", []

        expanded_text = output_buffer.getvalue()
        
        # Parse #line directives to build line map
        # Format: #line 123 "filename"
        # We only care about lines mapping back to THE CURRENT FILE.
        # Lines from included files should ideally be mapped too, or ignored if we only analyze the TU.
        # For now, we'll map everything, but we need to track the filename to know if it's the main file.
        
        lines = expanded_text.splitlines()
        line_map = [] # List where index i corresponds to line i+1 of expanded source
                      # Value is (original_line, filename)
        
        current_orig_line = 1
        current_file = file_path
        
        cleaned_lines = []
        
        line_directive_re = re.compile(r'^#line\s+(\d+)\s+"([^"]+)"')
        
        for line in lines:
            m = line_directive_re.match(line)
            if m:
                # Update state, don't include this line in output
                current_orig_line = int(m.group(1))
                current_file = m.group(2)
                # We intentionally don't add #line directives to the output sent to tree-sitter
                # because tree-sitter C parser might not like them or they might mess up the AST structure
                # if not standard C.
                # Actually, standard C supports #line. But pcpp output often strips comments and whitespace.
                # Let's keep them as empty lines to preserve relative spacing if possible, 
                # OR just track mapping.
                # Constructing a clean source without #line directives is better for tree-sitter-c 
                # if tree-sitter-c doesn't handle them well (it usually handles them as preproc nodes).
                # However, for the MAP to work, we need to know which line in 'clean_source' corresponds to what.
                
                # Strategy: Keep #line directives in the source passed to tree-sitter?
                # tree-sitter-c parses #line directives as `preproc_line`. 
                # If we keep them, tree-sitter handles them. 
                # But for our *analysis*, we want to map AST node rows back to original.
                
                # Better strategy: 
                # The expanded output FROM pcpp already contains #line directives.
                # We can just return that text.
                # BUT, we also want a precise look-up table for our own usage if needed.
                pass
            else:
                current_orig_line += 1
            
            # For simplicity in this v1, we will return the text AS IS from pcpp.
            # tree-sitter-c parses #line directives fine.
            # But we need a helper to map a node's start_point (row) in expanded source
            # back to (row) in original source.
        
        # Re-scan to build the map
        final_map: List[Tuple[int, str]] = []
        current_line = 1
        current_file = file_path
        
        for line in lines:
            m = line_directive_re.match(line)
            if m:
                # Directive: #line N "file" -> The *next* line is N
                next_line_num = int(m.group(1))
                new_file = m.group(2)
                
                # Map the directive line itself loosely to N-1
                final_map.append((next_line_num - 1, new_file))
                
                # Update state for subsequent lines
                current_line = next_line_num
                current_file = new_file
            else:
                final_map.append((current_line, current_file))
                current_line += 1
                
        # Cache macros
        defined_macros = {}
        for k, v in pp.macros.items():
            if hasattr(v, 'value'):
                # v.value is a list of LexToken objects. Join their values.
                try:
                    # Handle both list of tokens and single token/string scenarios if they exist
                    if isinstance(v.value, list):
                        defined_macros[k] = "".join(tok.value for tok in v.value)
                    else:
                        defined_macros[k] = str(v.value)
                except Exception:
                    defined_macros[k] = str(v.value)
            else:
                defined_macros[k] = ""
        
        self._cache[file_path] = (expanded_text.encode("utf-8"), final_map, defined_macros)
        
        return self._cache[file_path][0], self._cache[file_path][1]

    def get_active_regions(self, file_path: str) -> List[Tuple[int, int]]:
        """
        Get list of (start_line, end_line) ranges in the original file 
        that end up in the preprocessed output (i.e. are active).
        """
        if file_path not in self._cache:
            return []
            
        _, line_map, _ = self._cache[file_path]
        
        # Extract all original lines belonging to this file
        active_lines = set()
        # Normalise file_path for comparison
        target_file = _norm_path(file_path)
        
        for orig_line, orig_file in line_map:
            # Check if this line came from our file
            # pcpp might use absolute paths
            if _norm_path(orig_file).endswith(target_file):
                active_lines.add(orig_line)
                
        if not active_lines:
            return []
            
        # Coalesce into ranges
        sorted_lines = sorted(list(active_lines))
        ranges = []
        if not sorted_lines:
            return []
            
        start = sorted_lines[0]
        end = start
        
        for line in sorted_lines[1:]:
            if line == end + 1:
                end = line
            else:
                ranges.append((start, end))
                start = line
                end = line
        ranges.append((start, end))
        
        return ranges

    def get_original_location(self, file_path: str, expanded_line: int) -> Tuple[str, int]:
        """
        Convert a line number in the preprocessed source to (file, line) in original source.
        
        Args:
            file_path: The file that was preprocessed
            expanded_line: 1-indexed line number in preprocessed output
            
        Returns:
            (original_file_path, original_line_number)
        """
        if file_path not in self._cache:
            return file_path, expanded_line
            
        _, line_map, _ = self._cache[file_path]
        
        if expanded_line < 1 or expanded_line > len(line_map):
            return file_path, expanded_line
            
        # map is 0-indexed for list access (line 1 -> index 0)
        orig_line, orig_file = line_map[expanded_line - 1]
        
        # pcpp might output absolute paths or relative. We try to be consistent.
        # If orig_file looks like it's in our workspace, normalize it.
        if orig_file.startswith(self.workspace_root):
             orig_file = os.path.relpath(orig_file, self.workspace_root)
             
        return orig_file, orig_line

    def get_defined_macros(self, file_path: str) -> Dict[str, str]:
        """Get all macros defined after preprocessing the file."""
        if file_path not in self._cache:
            return {}
        return self._cache[file_path][2]

def _norm_path(p: str) -> str:
    """Normalize for comparison."""
    if not p: return ""
    return p.replace("\\", "/").strip("/")

"""
Context Provider — Enhanced

Retrieves code context around violation lines, extracts function signatures,
and provides symbol cross-reference search within a file.

Guards:
  • Skips binary files (null-byte check)
  • Caps reads at MAX_LINES to prevent memory issues
  • Handles encoding errors gracefully
"""

import os
import re
import logging
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

MAX_LINES = 100_000  # safety cap for very large files


class ContextProvider:
    def __init__(self, workspace_root: str):
        self.workspace_root = workspace_root

    # ────────────────────────────────────────────────────────────────
    #  Internal helpers
    # ────────────────────────────────────────────────────────────────

    def _resolve(self, file_path: str) -> str:
        # Normalise separators so 'src/main.c' works on Windows too
        native = file_path.replace("/", os.sep).replace("\\", os.sep)
        return os.path.join(self.workspace_root, native)

    @staticmethod
    def _read_lines(full_path: str) -> Optional[List[str]]:
        """Read file lines with binary-file guard and size cap."""
        if not os.path.isfile(full_path):
            return None
        try:
            with open(full_path, "rb") as fb:
                head = fb.read(8192)
                if b"\x00" in head:
                    logger.warning("Skipping binary file: %s", full_path)
                    return None
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                lines = []
                for i, line in enumerate(f):
                    if i >= MAX_LINES:
                        logger.warning(
                            "File %s exceeds %d lines — truncated", full_path, MAX_LINES
                        )
                        break
                    lines.append(line)
                return lines
        except Exception as e:
            logger.error("Error reading %s: %s", full_path, e)
            return None

    # ────────────────────────────────────────────────────────────────
    #  Core: Code context around a line
    # ────────────────────────────────────────────────────────────────

    def get_code_context(
        self, file_path: str, line_number: int, context_lines: int = 15
    ) -> str:
        """Retrieve code surrounding a specific line number."""
        lines = self._read_lines(self._resolve(file_path))
        if lines is None:
            return f"Error: Cannot read {file_path}"

        start = max(0, line_number - 1 - context_lines)
        end = min(len(lines), line_number + context_lines)
        return "".join(lines[start:end])

    def get_line(self, file_path: str, line_number: int) -> str:
        """Return a single line from a file (1-indexed)."""
        lines = self._read_lines(self._resolve(file_path))
        if lines is None:
            return ""
        if 1 <= line_number <= len(lines):
            return lines[line_number - 1]
        return ""

    # ────────────────────────────────────────────────────────────────
    #  Dependency analysis (includes / imports)
    # ────────────────────────────────────────────────────────────────

    def analyze_dependencies(self, file_path: str) -> List[str]:
        """Return all #include and import directives in a file."""
        lines = self._read_lines(self._resolve(file_path))
        if lines is None:
            return []
        deps: List[str] = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#include") or stripped.startswith("import"):
                deps.append(stripped)
        return deps

    # ────────────────────────────────────────────────────────────────
    #  Function signature extraction
    # ────────────────────────────────────────────────────────────────

    def get_enclosing_function(
        self, file_path: str, line_number: int
    ) -> Optional[str]:
        """
        Return the signature of the function enclosing 'line_number',
        or None if the line is at file scope.
        """
        lines = self._read_lines(self._resolve(file_path))
        if lines is None:
            return None

        # Walk backwards from the violation line to find the function header
        brace_depth = 0
        for i in range(min(line_number - 1, len(lines) - 1), -1, -1):
            line = lines[i]
            brace_depth -= line.count("}")
            brace_depth += line.count("{")
            if brace_depth >= 1:
                # Found the opening brace — grab the signature above
                sig_lines = []
                for j in range(max(0, i - 3), i + 1):
                    sig_lines.append(lines[j].strip())
                sig = " ".join(sig_lines)
                m = re.search(r"[\w\s\*]+\b(\w+)\s*\([^)]*\)", sig)
                if m:
                    return m.group(0).strip()
                break
        return None

    # ────────────────────────────────────────────────────────────────
    #  Symbol cross-reference (same file)
    # ────────────────────────────────────────────────────────────────

    def find_symbol_uses(
        self, file_path: str, symbol: str
    ) -> List[Tuple[int, str]]:
        """
        Find all lines in file_path that reference 'symbol'.
        Returns list of (line_number, line_text).
        """
        lines = self._read_lines(self._resolve(file_path))
        if lines is None:
            return []
        results: List[Tuple[int, str]] = []
        pattern = re.compile(rf"\b{re.escape(symbol)}\b")
        for i, line in enumerate(lines, start=1):
            if pattern.search(line):
                results.append((i, line.rstrip()))
        return results

"""
Axivion Report Parser

Parses JSON reports from Axivion Bauhaus Suite / Dashboard.  Supports
multiple JSON key conventions:

  • {"issues": [...]}      (default / simplified)
  • {"findings": [...]}    (Axivion Dashboard export)
  • {"warnings": [...]}    (legacy Axivion format)
  • {"results": [...]}     (custom CI pipeline wrapper)
  • [...]                  (bare array at top level)

Each issue is normalised into an AxivionViolation dataclass.
"""

import json
import logging
import os
from typing import List, Dict, Optional
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Keys we scan for when auto-detecting the report structure
_CANDIDATE_KEYS = ("issues", "findings", "warnings", "results", "violations")


class AxivionViolation(BaseModel):
    rule_id: str
    message: str
    file_path: str
    line_number: int
    end_line: int = 0
    severity: str = "medium"
    description: Optional[str] = None


class AxivionParser:
    """Load and query an Axivion JSON report."""

    def __init__(self, report_path: str):
        self.report_path = report_path
        self.violations: List[AxivionViolation] = []
        self._detected_key: Optional[str] = None
        self._load_report()

    # ────────────────────────────────────────────────────────────────
    #  Loading
    # ────────────────────────────────────────────────────────────────

    def _load_report(self):
        try:
            with open(self.report_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            logger.error("Report file not found: %s", self.report_path)
            return
        except json.JSONDecodeError as e:
            logger.error("Invalid JSON in %s: %s", self.report_path, e)
            return
        except UnicodeDecodeError:
            logger.error("Cannot read %s — file may be binary", self.report_path)
            return

        raw_issues = self._extract_issues(data)
        if raw_issues is None:
            logger.error(
                "Unrecognised report format in %s. "
                "Expected a JSON object with one of the keys: %s, "
                "or a top-level JSON array.",
                self.report_path,
                ", ".join(_CANDIDATE_KEYS),
            )
            return

        for item in raw_issues:
            try:
                violation = self._normalise(item)
                if violation:
                    self.violations.append(violation)
            except Exception as e:
                logger.warning("Skipping malformed issue: %s — %s", item, e)

    def _extract_issues(self, data) -> Optional[list]:
        """Auto-detect the array of issues inside the JSON structure."""
        # Top-level array
        if isinstance(data, list):
            self._detected_key = "<root array>"
            return data

        if not isinstance(data, dict):
            return None

        # Try each candidate key
        for key in _CANDIDATE_KEYS:
            if key in data and isinstance(data[key], list):
                self._detected_key = key
                return data[key]

        # Last resort: look for the first key whose value is a list
        for key, val in data.items():
            if isinstance(val, list) and len(val) > 0 and isinstance(val[0], dict):
                self._detected_key = key
                logger.info("Auto-detected issues under key '%s'", key)
                return val

        return None

    @staticmethod
    def _normalise(item: dict) -> Optional[AxivionViolation]:
        """Normalise a single issue dict to AxivionViolation."""
        if not isinstance(item, dict):
            return None

        # ── Rule ID ──
        rule_id = (
            item.get("ruleId")
            or item.get("rule_id")
            or item.get("rule")
            or item.get("checkId")
            or item.get("errorNumber")
            or "UNKNOWN"
        )

        # ── Message ──
        message = (
            item.get("message")
            or item.get("msg")
            or item.get("text")
            or ""
        )

        # ── Location ──
        loc = item.get("location")
        if isinstance(loc, dict) and loc:
            file_path = loc.get("path") or loc.get("file") or ""
            line_number = loc.get("startLine") or loc.get("line") or 0
            end_line = loc.get("endLine") or line_number
        else:
            # Fallback: path/line at top level
            file_path = item.get("file") or item.get("path") or ""
            line_number = item.get("line") or item.get("startLine") or 0
            end_line = item.get("endLine") or line_number

        # Last-resort fallback: if file_path still empty, try top-level
        if not file_path:
            file_path = item.get("file") or item.get("path") or ""
        if not line_number:
            line_number = item.get("line") or item.get("startLine") or 0

        # ── Severity ──
        severity = (
            item.get("severity")
            or item.get("priority")
            or item.get("level")
            or "medium"
        )

        # ── Description ──
        description = (
            item.get("description")
            or item.get("detail")
            or item.get("longMessage")
            or ""
        )

        return AxivionViolation(
            rule_id=str(rule_id),
            message=str(message),
            file_path=str(file_path),
            line_number=int(line_number),
            end_line=int(end_line),
            severity=str(severity).lower(),
            description=str(description) if description else None,
        )

    # ────────────────────────────────────────────────────────────────
    #  Path normalisation
    # ────────────────────────────────────────────────────────────────

    def normalize_paths(self, workspace_root: str) -> None:
        """
        Normalise violation file paths to be relative to workspace_root.

        Axivion reports may contain absolute paths from the analysis server
        (e.g. /opt/axivion/checkout/src/main.c or C:\\build\\src\\main.c) that
        don't match the user's workspace.  This method strips any prefix so
        that paths become workspace-relative with forward slashes
        (e.g. src/main.c).

        When files don't exist on disk (e.g. report loaded without full
        source tree), the method still produces best-guess relative paths
        by stripping common build-system prefixes.

        On Windows, comparisons are case-insensitive.
        """
        ws = os.path.abspath(workspace_root)
        ws_nc = os.path.normcase(ws)   # lowercase on Windows, unchanged on POSIX

        # Build a set of relative paths that actually exist in the workspace
        # for fast lookup during suffix matching.
        _existing_files: Dict[str, str] = {}  # basename → relative posix path
        _existing_paths: set = set()           # full relative posix paths
        for dirpath, _dirnames, filenames in os.walk(ws):
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, ws).replace("\\", "/")
                _existing_paths.add(rel)
                # Store basename → rel; last-one-wins is fine, used only as hint
                _existing_files[fn] = rel

        matched = 0
        guessed = 0

        for v in self.violations:
            fp = v.file_path

            # Normalise separators for consistent matching
            fp_norm = fp.replace("\\", "/")

            # ── Strategy 1: Already relative and exists in workspace ──
            if not os.path.isabs(fp):
                if fp_norm in _existing_paths:
                    v.file_path = fp_norm
                    matched += 1
                    continue

            # ── Strategy 2: Absolute path under workspace root ──
            abs_fp = os.path.abspath(fp) if os.path.isabs(fp) else fp
            abs_nc = os.path.normcase(abs_fp)
            if abs_nc.startswith(ws_nc + os.sep) or abs_nc.startswith(ws_nc + "/"):
                v.file_path = os.path.relpath(abs_fp, ws).replace("\\", "/")
                matched += 1
                continue

            # ── Strategy 3: Suffix match against real workspace files ──
            parts = fp_norm.split("/")
            found_on_disk = False
            for i in range(len(parts)):
                candidate_posix = "/".join(parts[i:])
                if candidate_posix in _existing_paths:
                    v.file_path = candidate_posix
                    matched += 1
                    found_on_disk = True
                    break
            if found_on_disk:
                continue

            # ── Strategy 4: Best-guess relative path (files not on disk) ──
            # Strip well-known build-server / CI prefixes so the path
            # becomes something the user can recognise and match against.
            v.file_path = self._best_guess_relative(fp_norm)
            guessed += 1

        logger.info(
            "Normalised %d violation paths against workspace %s "
            "(%d matched on disk, %d best-guess)",
            len(self.violations), workspace_root, matched, guessed,
        )

    @staticmethod
    def _best_guess_relative(fp_norm: str) -> str:
        """Heuristically strip build-server prefixes to produce a relative path.

        Given a path like ``/opt/axivion/checkout/source/App/main.c``, try
        to find a recognisable source-tree root marker (``source/``,
        ``src/``, ``include/``) and return everything from that marker
        onward.  If no marker is found, return the filename only.
        """
        # Common directory names that typically sit at or near the project root
        _SOURCE_MARKERS = (
            "/source/", "/sources/", "/src/", "/include/",
            "/app/", "/application/", "/lib/", "/core/",
            "/modules/", "/components/", "/drivers/",
        )

        fp_lower = fp_norm.lower()
        best_idx = len(fp_norm)  # worst case: full path

        for marker in _SOURCE_MARKERS:
            idx = fp_lower.find(marker)
            if idx != -1:
                # Keep from the marker directory onward (strip leading '/')
                candidate_start = idx + 1  # skip the leading '/'
                if candidate_start < best_idx:
                    best_idx = candidate_start

        if best_idx < len(fp_norm):
            return fp_norm[best_idx:]

        # No marker found — just return the filename portion
        return fp_norm.rsplit("/", 1)[-1]

    # ────────────────────────────────────────────────────────────────
    #  Queries
    # ────────────────────────────────────────────────────────────────

    def get_violations_by_file(self, file_path: str) -> List[AxivionViolation]:
        """Get violations for a file, using multi-tier matching for robustness.

        Matching tiers (returns on first tier that produces results):
          1. Exact match (case-sensitive)
          2. Case-insensitive exact match
          3. Suffix match (either direction)
          4. Case-insensitive suffix match
          5. Basename match (case-insensitive)
        """
        query = file_path.replace("\\", "/").rstrip("/")
        query_lower = query.lower()
        query_base = query.rsplit("/", 1)[-1].lower()

        exact = []
        exact_ci = []
        suffix = []
        suffix_ci = []
        basename = []

        for v in self.violations:
            vp = v.file_path.replace("\\", "/").rstrip("/")
            vp_lower = vp.lower()

            # Tier 1: Exact
            if vp == query:
                exact.append(v)
                continue

            # Tier 2: Case-insensitive exact
            if vp_lower == query_lower:
                exact_ci.append(v)
                continue

            # Tier 3: Suffix match (case-sensitive)
            if vp.endswith("/" + query) or query.endswith("/" + vp):
                suffix.append(v)
                continue

            # Tier 4: Suffix match (case-insensitive)
            if vp_lower.endswith("/" + query_lower) or query_lower.endswith("/" + vp_lower):
                suffix_ci.append(v)
                continue

            # Tier 5: Basename match (case-insensitive, works with or without dir in query)
            vp_base = vp.rsplit("/", 1)[-1].lower()
            if vp_base == query_base:
                basename.append(v)

        # Return the most specific tier that has results
        return exact or exact_ci or suffix or suffix_ci or basename

    def get_violation_by_id(self, rule_id: str) -> List[AxivionViolation]:
        return [v for v in self.violations if v.rule_id == rule_id]

    def get_all_violations(self) -> List[AxivionViolation]:
        return self.violations

    def get_summary(self) -> Dict:
        """Return a summary of the report for quick overview."""
        files = {}
        severities = {}
        rules = {}
        for v in self.violations:
            files[v.file_path] = files.get(v.file_path, 0) + 1
            severities[v.severity] = severities.get(v.severity, 0) + 1
            rules[v.rule_id] = rules.get(v.rule_id, 0) + 1
        return {
            "total_violations": len(self.violations),
            "files_affected": len(files),
            "by_file": files,
            "by_severity": severities,
            "by_rule": rules,
            "detected_format": self._detected_key,
        }

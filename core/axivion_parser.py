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

        On Windows, comparisons are case-insensitive.
        """
        ws = os.path.abspath(workspace_root)
        ws_nc = os.path.normcase(ws)   # lowercase on Windows, unchanged on POSIX

        for v in self.violations:
            fp = v.file_path

            # Normalise separators for consistent matching
            fp_norm = fp.replace("\\", "/")

            # Already relative and exists in workspace — normalise and keep
            if not os.path.isabs(fp):
                native = fp.replace("/", os.sep).replace("\\", os.sep)
                if os.path.isfile(os.path.join(ws, native)):
                    v.file_path = fp_norm
                    continue

            # Absolute path that starts with workspace root (case-insensitive on Win)
            abs_fp = os.path.abspath(fp) if os.path.isabs(fp) else fp
            abs_nc = os.path.normcase(abs_fp)
            if abs_nc.startswith(ws_nc + os.sep) or abs_nc.startswith(ws_nc + "/"):
                v.file_path = os.path.relpath(abs_fp, ws).replace("\\", "/")
                continue

            # Try to match by finding the longest suffix that exists in workspace
            parts = fp_norm.split("/")
            for i in range(len(parts)):
                candidate_posix = "/".join(parts[i:])
                candidate_native = candidate_posix.replace("/", os.sep)
                if os.path.isfile(os.path.join(ws, candidate_native)):
                    v.file_path = candidate_posix
                    break
            else:
                # No match found — at least normalise separators
                v.file_path = fp_norm

        logger.info(
            "Normalised %d violation paths against workspace %s",
            len(self.violations), workspace_root,
        )

    # ────────────────────────────────────────────────────────────────
    #  Queries
    # ────────────────────────────────────────────────────────────────

    def get_violations_by_file(self, file_path: str) -> List[AxivionViolation]:
        """Get violations for a file, using suffix matching for robustness."""
        # Normalise separators
        query = file_path.replace("\\", "/").rstrip("/")
        results = []
        for v in self.violations:
            vp = v.file_path.replace("\\", "/").rstrip("/")
            # Exact match
            if vp == query:
                results.append(v)
            # Suffix match: query "src/main.c" matches "/opt/.../src/main.c"
            elif vp.endswith("/" + query) or query.endswith("/" + vp):
                results.append(v)
            # Basename match as last resort (only if unique enough: has dir)
            elif "/" not in query and os.path.basename(vp) == query:
                results.append(v)
        return results

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

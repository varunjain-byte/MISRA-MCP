import os
import logging
from typing import List, Dict, Tuple, Any

logger = logging.getLogger(__name__)

class BatchFixer:
    """
    Applies multiple text edits to files safely.
    Handles offset shifts by applying edits in reverse order (bottom-up).
    """

    def apply_fix_analyses(self, fix_analyses: List[Any], dry_run: bool = False) -> Dict[str, int]:
        """
        Apply edits from a list of FixAnalysis objects.
        Returns a summary of changes: {file_path: number_of_fixes_applied}.
        """
        # Group edits by file
        # FixAnalysis object structure:
        # has .edits list, but doesn't have file_path directly?
        # The user's FixAnalysis definition in fix_engine.py doesn't have file_path.
        # It's returned by FixEngine.propose_fix, which takes a violation.
        # We need to ensure we know which file each analysis belongs to.
        # Assuming for now either FixAnalysis has it or the caller passes tuples.
        
        # Let's assume the caller groups them or we change the API to take (file_path, edits).
        # But wait, looking at FixAnalysis definition... it definitely doesn't have file_path.
        # So I'll define this method to take a map: {file_path: [FixAnalysis, ...]}
        
        raise NotImplementedError("Use apply_fixes_by_file instead")

    def apply_fixes_by_file(self, file_map: Dict[str, List[Dict]], dry_run: bool = False) -> Dict[str, int]:
        """
        file_map: { file_path: [ {start_byte, end_byte, text}, ... ] }
        """
        summary = {}
        
        for file_path, edits in file_map.items():
            if not edits:
                continue
                
            try:
                msg = self._apply_to_file(file_path, edits, dry_run)
                summary[file_path] = len(edits)
                logger.info(msg)
            except Exception as e:
                logger.error(f"Failed to apply fixes to {file_path}: {e}")
                summary[file_path] = 0
                
        return summary

    def _apply_to_file(self, file_path: str, edits: List[Dict], dry_run: bool) -> str:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
            
        with open(file_path, "rb") as f:
            content = f.read()
            
        # 1. Sort edits descending by start_byte
        # If multiple edits start at same point, order is ambiguous unless specified.
        # Assuming non-overlapping for now.
        sorted_edits = sorted(edits, key=lambda e: e["start_byte"], reverse=True)
        
        # 2. Check for overlaps
        # Since we are going reverse, current_edit.end_byte must be <= previous_processed_edit.start_byte
        # (Where previous_processed_edit is actually one that appears LATER in the file)
        
        last_start = float('inf')
        
        new_content = bytearray(content)
        
        for edit in sorted_edits:
            start = edit["start_byte"]
            end = edit["end_byte"]
            text = edit["text"].encode("utf-8")
            
            if end > last_start:
                logger.warning(f"Overlap detected in {file_path} at offset {start}-{end}. Skipping edit.")
                continue
                
            # Apply edit
            # Replace [start:end] with text
            new_content[start:end] = text
            
            last_start = start
            
        if not dry_run:
            with open(file_path, "wb") as f:
                f.write(new_content)
            return f"Applied {len(sorted_edits)} fixes to {file_path}"
        else:
            return f"[Dry Run] Would apply {len(sorted_edits)} fixes to {file_path}"

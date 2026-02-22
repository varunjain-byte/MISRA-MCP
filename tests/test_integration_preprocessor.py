
import unittest
import os
import sys

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from core.workspace_index import WorkspaceIndex
from core.preprocessor import PreprocessorEngine

MOCK_PROJECT = os.path.join(PROJECT_ROOT, "tests", "mock_project")

class TestIntegrationPreprocessor(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Create an engine and index pointing to the mock project
        cls.preprocessor = PreprocessorEngine(MOCK_PROJECT)
        cls.index = WorkspaceIndex(MOCK_PROJECT, preprocessor=cls.preprocessor)
        cls.index.build()
        
    def test_dead_code_exclusion(self):
        """Symbols in #if 0 blocks ARE indexed (raw parse) but detected as
        inactive via preprocessor active-region analysis at analysis time.

        Indexing now uses raw tree-sitter parsing (no pcpp) for performance,
        so dead-code symbols appear in the symbol table.  The preprocessor
        is invoked lazily per-file to identify inactive regions.
        """
        # mock_macros.c has a function 'dead_code' inside #if 0
        symbols = self.index.symbols.find("dead_code")

        # Symbol IS present in the raw-parsed index
        self.assertGreater(len(symbols), 0,
                           "'dead_code' should be indexed from raw source")

        # But the preprocessor correctly identifies it as inactive
        active_regions = self.preprocessor.get_active_regions("mock_macros.c")
        is_active = any(start <= 22 <= end for start, end in active_regions)
        self.assertFalse(is_active,
                         "Line 22 (dead_code body) should be in an inactive region")
        
    def test_active_code_inclusion(self):
        """Active symbols should be indexed correctly."""
        # 'calculate_area' is active
        symbols = self.index.symbols.find("calculate_area")
        self.assertGreater(len(symbols), 0)
        
        entry = symbols[0]
        self.assertEqual(entry.name, "calculate_area")
        self.assertTrue(entry.file.endswith("mock_macros.c"))
        
        # Check line number - should be mapped back to original file
        # In mock_macros.c, calculate_area is around line 8
        self.assertEqual(entry.line, 8)
        
    def test_unreachable_code_detection(self):
        """
        Verify that we can detect unreachable code using the preprocessor's active regions.
        This conceptually tests the logic added to CAnalyzer, but via PreprocessorEngine directly here.
        """
        # mock_macros.c:
        # #if 0
        # void dead_code(void) { ... }
        # #endif
        
        active_regions = self.preprocessor.get_active_regions("mock_macros.c")
        
        # Line 22 is inside dead_code
        is_active = False
        for start, end in active_regions:
            if start <= 22 <= end:
                is_active = True
                break
                
        self.assertFalse(is_active, "Line 22 should be inactive")

if __name__ == "__main__":
    unittest.main()


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
        """Symbols in #if 0 blocks should not be indexed when preprocessor is used."""
        # mock_macros.c has a function 'dead_code' inside #if 0
        
        # Check if 'dead_code' is in symbols
        # The symbol entry is (name, file, line...)
        
        # We need to find if any symbol named 'dead_code' exists in 'mock_macros.c'
        symbols = self.index.symbols.find("dead_code")
        
        # Should be empty because pcpp removes the #if 0 block
        self.assertEqual(len(symbols), 0, "Current 'dead_code' should be removed by preprocessor")
        
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


import unittest
import os
import sys

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from core.preprocessor import PreprocessorEngine

MOCK_PROJECT = os.path.join(PROJECT_ROOT, "tests", "mock_project")

class TestPreprocessorEngine(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.engine = PreprocessorEngine(MOCK_PROJECT)
        
    def test_macro_expansion(self):
        """Standard macros should be expanded."""
        # mock_macros.c uses PI (3.14159) and SQUARE(x)
        expanded, _ = self.engine.preprocess("mock_macros.c", include_dirs=["."])
        code = expanded.decode("utf-8")
        
        self.assertNotIn("PI", code)
        self.assertIn("3.14159", code)
        
        # SQUARE(radius) -> ((radius) * (radius))
        self.assertNotIn("SQUARE(radius)", code)
        self.assertIn("((radius) * (radius))", code)

    def test_include_resolution(self):
        """Output should contain content from utils.h."""
        expanded, _ = self.engine.preprocess("mock_macros.c", include_dirs=["."])
        code = expanded.decode("utf-8")
        
        # utils.h defines add_numbers
        self.assertIn("int add_numbers(int a, int b);", code)

    def test_active_regions_if_0(self):
        """#if 0 block should NOT be in active regions."""
        self.engine.preprocess("mock_macros.c", include_dirs=["."])
        regions = self.engine.get_active_regions("mock_macros.c")
        
        # In mock_macros.c:
        # lines 21-26 are #if 0 block
        # void dead_code(void) is inside.
        
        # We need to verify that lines 22-25 are NOT in regions
        # Line 22: void dead_code(void) {
        
        is_active = False
        for start, end in regions:
            if start <= 22 <= end:
                is_active = True
                break
        
        self.assertFalse(is_active, "Line 22 (dead_code) should be inactive")

    def test_active_regions_production(self):
        """Without DEBUG_ENABLED, log_production should be active."""
        # By default DEBUG_ENABLED is not defined
        self.engine.preprocess("mock_macros.c", include_dirs=["."])
        regions = self.engine.get_active_regions("mock_macros.c")
        
        # log_production is around line 16
        is_active = False
        for start, end in regions:
            if start <= 16 <= end:
                is_active = True
                break
        
        self.assertTrue(is_active, "Line 16 (log_production) should be active")

    def test_define_injection(self):
        """Injecting DEBUG_ENABLED should switch active path."""
        # Create a new engine instance to avoid cache
        engine2 = PreprocessorEngine(MOCK_PROJECT)
        engine2.add_define("DEBUG_ENABLED")
        
        expanded, _ = engine2.preprocess("mock_macros.c", include_dirs=["."])
        regions = engine2.get_active_regions("mock_macros.c")
        code = expanded.decode("utf-8")
        
        # log_debug should be active (line 12)
        is_active_12 = False
        for start, end in regions:
            if start <= 12 <= end:
                is_active_12 = True
                break
        self.assertTrue(is_active_12, "Line 12 (log_debug) should be active with -DDEBUG_ENABLED")
        
        # log_production should be inactive (line 16)
        is_active_16 = False
        for start, end in regions:
            if start <= 16 <= end:
                is_active_16 = True
                break
        self.assertFalse(is_active_16, "Line 16 (log_production) should be inactive with -DDEBUG_ENABLED")
        
        # Also check code content
        self.assertIn("void log_debug", code)
        # Note: pcpp usually omits inactive blocks from output entirely, 
        # so check if log_production is GONE or just present as empty lines?
        # pcpp removes lines.
        self.assertNotIn("void log_production", code)

    def test_get_defined_macros(self):
        """Should return macros defined in the file."""
        self.engine.preprocess("mock_macros.c", include_dirs=["."])
        macros = self.engine.get_defined_macros("mock_macros.c")
        self.assertIn("PI", macros)
        self.assertIn("SQUARE", macros)
        self.assertIn("GREETING", macros)
        self.assertEqual(macros["PI"], "3.14159")

    def test_line_mapping(self):
        """Line map should exist and look reasonable."""
        _, line_map = self.engine.preprocess("mock_macros.c", include_dirs=["."])
        self.assertGreater(len(line_map), 0)
        
        # Check an entry
        # Line 8: int calculate_area...
        # In expanded source, this might be shifted due to includes
        # But we can check that there IS a map entry pointing to line 8 of mock_macros.c
        
        # Let's find where 'calculate_area' is in expanded text
        exp, _ = self.engine.preprocess("mock_macros.c", include_dirs=["."])
        exp_lines = exp.decode("utf-8").splitlines()
        
        calc_idx = -1
        for i, line in enumerate(exp_lines):
            if "int calculate_area" in line:
                calc_idx = i
                break
        
        self.assertNotEqual(calc_idx, -1)
        
        # Map back
        # line_map is 0-indexed corresponding to expanded lines
        orig_line, orig_file = line_map[calc_idx]
        
        self.assertEqual(orig_file, "mock_macros.c")
        # In original file it is line 8
        self.assertEqual(orig_line, 8)

if __name__ == "__main__":
    unittest.main()

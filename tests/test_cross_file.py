"""
Cross-File Analysis Tests — WorkspaceIndex, IncludeGraph, SymbolTable, CallGraph.

Validates that the cross-file analysis engine can:
  1. Discover and parse all C/H files
  2. Resolve #include directives (direct + transitive)
  3. Build a global symbol table with correct linkage
  4. Build a call graph across translation units
  5. Index typedefs, macros, and struct tags
  6. Perform rule-specific cross-file checks (8.3, 8.4, 8.5, 8.6, 8.8, 8.13)
  7. Integrate with CAnalyzer for enriched analysis
"""

import os
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

MOCK_PROJECT = os.path.join(PROJECT_ROOT, "tests", "mock_project")

from core.workspace_index import (
    WorkspaceIndex, IncludeGraph, SymbolTable, CallGraph, TypeRegistry,
    SymbolEntry, CallSite, TypeAlias,
)
from core.c_analyzer import CAnalyzer


class TestWorkspaceIndexBuild(unittest.TestCase):
    """Test that the index builds correctly on the mock project."""

    @classmethod
    def setUpClass(cls):
        cls.index = WorkspaceIndex(MOCK_PROJECT)
        cls.index.build()

    def test_index_is_built(self):
        self.assertTrue(self.index.is_built)

    def test_file_discovery(self):
        """All .c and .h files should be discovered."""
        summary = self.index.get_summary()
        self.assertEqual(summary["c_files"], 4, "Should find 4 .c files")
        self.assertEqual(summary["h_files"], 2, "Should find 2 .h files")
        self.assertEqual(summary["files_indexed"], 6, "Total 6 files")

    def test_symbols_indexed(self):
        """Should index a meaningful number of symbols."""
        summary = self.index.get_summary()
        self.assertGreater(summary["symbols"], 10, "Should have >10 symbols")

    def test_call_sites_indexed(self):
        """Should index call sites from function bodies."""
        summary = self.index.get_summary()
        self.assertGreater(summary["call_sites"], 3, "Should have >3 call sites")


class TestIncludeGraph(unittest.TestCase):
    """Tests for #include resolution."""

    @classmethod
    def setUpClass(cls):
        cls.index = WorkspaceIndex(MOCK_PROJECT)
        cls.index.build()

    def test_main_includes_utils_h(self):
        """main.c should include utils.h."""
        includes = self.index.include_graph.get_includes("main.c")
        self.assertIn("utils.h", includes)

    def test_utils_c_includes_utils_h(self):
        """utils.c should include utils.h."""
        includes = self.index.include_graph.get_includes("utils.c")
        self.assertIn("utils.h", includes)

    def test_other_c_includes_utils_h(self):
        """other.c should include utils.h."""
        includes = self.index.include_graph.get_includes("other.c")
        self.assertIn("utils.h", includes)

    def test_transitive_includes(self):
        """main.c transitively includes utils.h."""
        trans = self.index.include_graph.get_transitive_includes("main.c")
        self.assertIn("utils.h", trans)

    def test_reverse_includers(self):
        """utils.h should be included by main.c, utils.c, other.c."""
        includers = self.index.include_graph.get_includers("utils.h")
        self.assertIn("main.c", includers)
        self.assertIn("utils.c", includers)
        self.assertIn("other.c", includers)

    def test_config_h_not_included(self):
        """config.h is not included by any file (it's standalone)."""
        includers = self.index.include_graph.get_includers("config.h")
        self.assertEqual(len(includers), 0)


class TestSymbolTable(unittest.TestCase):
    """Tests for global symbol indexing."""

    @classmethod
    def setUpClass(cls):
        cls.index = WorkspaceIndex(MOCK_PROJECT)
        cls.index.build()

    def test_function_definition(self):
        """add_numbers should have a definition in utils.c."""
        defs = self.index.symbols.find_definitions("add_numbers")
        self.assertEqual(len(defs), 1)
        self.assertEqual(defs[0].file, "utils.c")
        self.assertEqual(defs[0].kind, "function_def")

    def test_function_declaration(self):
        """add_numbers should have a declaration in utils.h."""
        decls = self.index.symbols.find_declarations("add_numbers")
        self.assertTrue(any(d.file == "utils.h" for d in decls))

    def test_header_declaration_lookup(self):
        """find_header_declaration should return utils.h entry."""
        decl = self.index.symbols.find_header_declaration("add_numbers")
        self.assertIsNotNone(decl)
        self.assertEqual(decl.file, "utils.h")
        self.assertEqual(decl.kind, "function_decl")

    def test_variable_definition(self):
        """global_counter should be found as a variable definition."""
        defs = self.index.symbols.find_definitions("global_counter")
        self.assertGreaterEqual(len(defs), 1)

    def test_internal_helper_no_header_decl(self):
        """internal_helper has no declaration in any header."""
        decl = self.index.symbols.find_header_declaration("internal_helper")
        self.assertIsNone(decl)

    def test_macro_indexed(self):
        """MAX_BUFFER_SIZE macro should be indexed from utils.h."""
        entries = self.index.symbols.find("MAX_BUFFER_SIZE")
        self.assertTrue(any(e.kind == "macro" for e in entries))

    def test_typedef_indexed(self):
        """uint32_t_custom typedef should be indexed from utils.h."""
        entries = self.index.symbols.find("uint32_t_custom")
        self.assertTrue(any(e.kind == "typedef" for e in entries))

    def test_static_linkage(self):
        """internal_helper should have internal linkage (if defined static)."""
        # In our mock it's NOT static — that's the violation. It should be external.
        defs = self.index.symbols.find_definitions("internal_helper")
        if defs:
            self.assertEqual(defs[0].linkage, "external")


class TestCallGraph(unittest.TestCase):
    """Tests for cross-file call graph."""

    @classmethod
    def setUpClass(cls):
        cls.index = WorkspaceIndex(MOCK_PROJECT)
        cls.index.build()

    def test_add_numbers_called_from_main(self):
        """main.c should call add_numbers."""
        callers = self.index.call_graph.get_callers("add_numbers")
        main_callers = [c for c in callers if c.caller_file == "main.c"]
        self.assertGreater(len(main_callers), 0)

    def test_add_numbers_called_from_other(self):
        """other.c should also call add_numbers."""
        callers = self.index.call_graph.get_callers("add_numbers")
        other_callers = [c for c in callers if c.caller_file == "other.c"]
        self.assertGreater(len(other_callers), 0)

    def test_external_callers(self):
        """add_numbers defined in utils.c should have external callers."""
        ext = self.index.call_graph.get_external_callers("add_numbers", "utils.c")
        self.assertGreater(len(ext), 0)

    def test_internal_helper_no_external_callers(self):
        """internal_helper should have no external callers."""
        ext = self.index.call_graph.get_external_callers("internal_helper", "utils.c")
        self.assertEqual(len(ext), 0)

    def test_compute_sum_called_from_main(self):
        """compute_sum should be called from main.c."""
        callers = self.index.call_graph.get_callers("compute_sum")
        main_callers = [c for c in callers if c.caller_file == "main.c"]
        self.assertGreater(len(main_callers), 0)

    def test_public_function_called_externally(self):
        """public_function should be called from main.c (external caller)."""
        ext = self.index.call_graph.get_external_callers("public_function", "utils.c")
        self.assertGreater(len(ext), 0)


class TestTypeRegistry(unittest.TestCase):
    """Tests for typedef indexing."""

    @classmethod
    def setUpClass(cls):
        cls.index = WorkspaceIndex(MOCK_PROJECT)
        cls.index.build()

    def test_typedef_resolution(self):
        """uint32_t_custom should resolve to 'unsigned int'."""
        resolved = self.index.types.resolve("uint32_t_custom")
        self.assertIn("unsigned", resolved.lower())

    def test_error_code_from_config(self):
        """error_code_t from config.h should resolve to int."""
        resolved = self.index.types.resolve("error_code_t")
        self.assertIn("int", resolved.lower())

    def test_unknown_type_passthrough(self):
        """Unknown type should pass through unchanged."""
        resolved = self.index.types.resolve("unknown_type")
        self.assertEqual(resolved, "unknown_type")


# ═══════════════════════════════════════════════════════════════════════
#  Rule-Specific Cross-File Checks
# ═══════════════════════════════════════════════════════════════════════

class TestRule8_3CrossFile(unittest.TestCase):
    """Rule 8.3: Declaration vs definition consistency."""

    @classmethod
    def setUpClass(cls):
        cls.index = WorkspaceIndex(MOCK_PROJECT)
        cls.index.build()

    def test_add_numbers_consistent(self):
        """add_numbers should have consistent declaration and definition."""
        result = self.index.check_rule_8_3("add_numbers")
        self.assertIsNotNone(result["declaration"])
        self.assertIsNotNone(result["definition"])
        # Both use (int a, int b)
        self.assertTrue(result["consistent"])

    def test_multiply_values_mismatch(self):
        """multiply_values has (x,y) in header but (a,b) in definition."""
        result = self.index.check_rule_8_3("multiply_values")
        self.assertIsNotNone(result["declaration"])
        self.assertIsNotNone(result["definition"])
        # Param names differ: (int x, int y) vs (int a, int b)
        self.assertFalse(result["consistent"])
        self.assertGreater(len(result["mismatches"]), 0)


class TestRule8_4CrossFile(unittest.TestCase):
    """Rule 8.4: Prior declaration visible."""

    @classmethod
    def setUpClass(cls):
        cls.index = WorkspaceIndex(MOCK_PROJECT)
        cls.index.build()

    def test_process_data_has_declaration(self):
        """process_data is declared in utils.h, included by utils.c."""
        result = self.index.check_rule_8_4("process_data", "utils.c")
        self.assertTrue(result["has_prior_declaration"])

    def test_internal_helper_no_declaration(self):
        """internal_helper has no declaration in any header."""
        result = self.index.check_rule_8_4("internal_helper", "utils.c")
        self.assertFalse(result["has_prior_declaration"])


class TestRule8_5CrossFile(unittest.TestCase):
    """Rule 8.5: Duplicate extern in .c files."""

    @classmethod
    def setUpClass(cls):
        cls.index = WorkspaceIndex(MOCK_PROJECT)
        cls.index.build()

    def test_shared_var_duplicate_extern(self):
        """shared_var has extern in both main.c and other.c."""
        result = self.index.check_rule_8_5("shared_var")
        self.assertTrue(result["has_duplicates"])
        self.assertGreaterEqual(len(result["extern_locations"]), 2)


class TestRule8_6CrossFile(unittest.TestCase):
    """Rule 8.6: Multiple definitions across TUs."""

    @classmethod
    def setUpClass(cls):
        cls.index = WorkspaceIndex(MOCK_PROJECT)
        cls.index.build()

    def test_global_counter_multiple_definitions(self):
        """global_counter is defined in both utils.c and main.c."""
        result = self.index.check_rule_8_6("global_counter")
        self.assertTrue(result["has_multiple_definitions"])
        files = [d["file"] for d in result["definitions"]]
        self.assertIn("utils.c", files)
        self.assertIn("main.c", files)


class TestRule8_8CrossFile(unittest.TestCase):
    """Rule 8.8: Safe to add static?"""

    @classmethod
    def setUpClass(cls):
        cls.index = WorkspaceIndex(MOCK_PROJECT)
        cls.index.build()

    def test_public_function_not_safe(self):
        """public_function is called externally — NOT safe to add static."""
        result = self.index.check_rule_8_8("public_function", "utils.c")
        self.assertFalse(result["safe_to_add_static"])
        self.assertTrue(result["has_external_callers"])

    def test_internal_helper_safe(self):
        """internal_helper has no external callers and no header decl — safe."""
        result = self.index.check_rule_8_8("internal_helper", "utils.c")
        self.assertTrue(result["safe_to_add_static"])


class TestRule8_13CrossFile(unittest.TestCase):
    """Rule 8.13: Caller impact for adding const."""

    @classmethod
    def setUpClass(cls):
        cls.index = WorkspaceIndex(MOCK_PROJECT)
        cls.index.build()

    def test_compute_sum_callers(self):
        """compute_sum has callers that would be affected by const."""
        result = self.index.check_rule_8_13("compute_sum")
        self.assertGreater(result["total_callers"], 0)
        self.assertIsNotNone(result["header_to_update"])
        self.assertEqual(result["header_to_update"], "utils.h")

    def test_compute_sum_files_affected(self):
        """Files affected should include main.c and utils.h."""
        result = self.index.check_rule_8_13("compute_sum")
        self.assertIn("main.c", result["files_affected"])


# ═══════════════════════════════════════════════════════════════════════
#  CAnalyzer Integration with WorkspaceIndex
# ═══════════════════════════════════════════════════════════════════════

class TestCAnalyzerCrossFile(unittest.TestCase):
    """Test that CAnalyzer enriches rules with cross-file evidence."""

    @classmethod
    def setUpClass(cls):
        cls.index = WorkspaceIndex(MOCK_PROJECT)
        cls.index.build()
        cls.analyzer = CAnalyzer(MOCK_PROJECT, workspace_index=cls.index)

    def test_has_cross_file_flag(self):
        """analyze_for_rule should set has_cross_file=True."""
        result = self.analyzer.analyze_for_rule(
            "utils.c", 6, "MisraC2012-8.3"
        )
        self.assertTrue(result.get("has_cross_file"))

    def test_rule_8_3_cross_file_enrichment(self):
        """Rule 8.3 should include cross_file data."""
        result = self.analyzer.analyze_for_rule(
            "utils.c", 6, "MisraC2012-8.3"
        )
        self.assertIn("cross_file", result)
        self.assertIn("declaration", result["cross_file"])

    def test_rule_8_8_cross_file_enrichment(self):
        """Rule 8.8 for internal_helper should show safe_to_add_static."""
        # internal_helper is at line 33 in utils.c
        result = self.analyzer.analyze_for_rule(
            "utils.c", 33, "MisraC2012-8.8"
        )
        self.assertIn("cross_file", result)
        self.assertTrue(result.get("safe_to_add_static"))

    def test_rule_8_13_cross_file_enrichment(self):
        """Rule 8.13 for compute_sum should include callers."""
        # compute_sum is at line 20 in utils.c  
        result = self.analyzer.analyze_for_rule(
            "utils.c", 20, "MisraC2012-8.13"
        )
        if result.get("cross_file"):
            self.assertGreater(result["cross_file"]["total_callers"], 0)

    def test_without_index(self):
        """CAnalyzer without index should still work but no cross_file."""
        plain_analyzer = CAnalyzer(MOCK_PROJECT)
        result = plain_analyzer.analyze_for_rule(
            "utils.c", 6, "MisraC2012-8.3"
        )
        self.assertFalse(result.get("has_cross_file"))
        self.assertNotIn("cross_file", result)


# ═══════════════════════════════════════════════════════════════════════
#  Edge Cases
# ═══════════════════════════════════════════════════════════════════════

class TestEdgeCases(unittest.TestCase):
    """Edge cases for robustness."""

    def test_empty_workspace(self):
        """WorkspaceIndex should handle empty directory gracefully."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            index = WorkspaceIndex(tmpdir)
            index.build()
            self.assertTrue(index.is_built)
            summary = index.get_summary()
            self.assertEqual(summary["files_indexed"], 0)

    def test_nonexistent_workspace(self):
        """WorkspaceIndex should handle non-existent directory."""
        index = WorkspaceIndex("/nonexistent/path/foo")
        index.build()  # Should not crash
        self.assertTrue(index.is_built)

    def test_symbol_not_found(self):
        """Queries for non-existent symbols should return empty."""
        index = WorkspaceIndex(MOCK_PROJECT)
        index.build()
        entries = index.symbols.find("this_function_does_not_exist_123")
        self.assertEqual(len(entries), 0)

    def test_include_graph_missing_file(self):
        """Include graph should handle missing includes gracefully."""
        graph = IncludeGraph(MOCK_PROJECT)
        resolved = graph._resolve_quoted("nonexistent.h", "main.c")
        self.assertIsNone(resolved)

# ═══════════════════════════════════════════════════════════════════════
#  Header (.h) File Analysis
# ═══════════════════════════════════════════════════════════════════════

class TestHeaderFileAnalysis(unittest.TestCase):
    """Dedicated tests for .h file parsing, indexing, and analysis."""

    @classmethod
    def setUpClass(cls):
        cls.index = WorkspaceIndex(MOCK_PROJECT)
        cls.index.build()
        cls.analyzer = CAnalyzer(MOCK_PROJECT, workspace_index=cls.index)

    # ── File discovery ──

    def test_h_files_discovered(self):
        """Both .h files should be discovered by workspace index."""
        summary = self.index.get_summary()
        self.assertEqual(summary["h_files"], 2)

    def test_h_files_in_file_list(self):
        """utils.h and config.h should appear in the indexed file list."""
        files = self.index._files
        h_files = [f for f in files if f.endswith(".h")]
        self.assertEqual(len(h_files), 2)
        basenames = sorted(os.path.basename(f) for f in h_files)
        self.assertEqual(basenames, ["config.h", "utils.h"])

    # ── Declarations from headers ──

    def test_all_function_decls_from_utils_h(self):
        """All 5 function declarations in utils.h should be indexed."""
        expected = {"add_numbers", "multiply_values", "process_data",
                    "compute_sum", "public_function"}
        decls = self.index.symbols.find_declarations
        found = set()
        for name in expected:
            entries = [e for e in self.index.symbols.find(name)
                       if e.file.endswith("utils.h") and e.kind == "function_decl"]
            if entries:
                found.add(name)
        self.assertEqual(found, expected,
                         f"Missing declarations from utils.h: {expected - found}")

    def test_macro_from_config_h(self):
        """APP_VERSION and DEBUG_ENABLED macros from config.h should be indexed."""
        for macro_name in ("APP_VERSION", "DEBUG_ENABLED"):
            entries = self.index.symbols.find(macro_name)
            config_entries = [e for e in entries
                              if e.file.endswith("config.h") and e.kind == "macro"]
            self.assertGreater(len(config_entries), 0,
                               f"{macro_name} not found in config.h")

    def test_typedef_from_config_h(self):
        """error_code_t typedef from config.h should be indexed and resolvable."""
        entries = self.index.symbols.find("error_code_t")
        config_entries = [e for e in entries if e.file.endswith("config.h")]
        self.assertGreater(len(config_entries), 0)
        # Also check type resolution
        resolved = self.index.types.resolve("error_code_t")
        self.assertIn("int", resolved.lower())

    def test_struct_tag_from_utils_h(self):
        """DataPoint struct tag from utils.h should be indexed."""
        entries = self.index.symbols.find("DataPoint")
        h_entries = [e for e in entries if e.file.endswith("utils.h")]
        self.assertGreater(len(h_entries), 0, "DataPoint struct not found in utils.h")

    # ── CAnalyzer on .h files ──

    def test_analyzer_parses_header(self):
        """CAnalyzer.analyze_for_rule should work on .h files."""
        result = self.analyzer.analyze_for_rule("utils.h", 7, "MisraC2012-8.2")
        self.assertEqual(result["rule_id"], "MisraC2012-8.2")
        # Should not crash, and should have parsed the file

    def test_analyzer_find_declarations_in_header(self):
        """CAnalyzer.find_declarations should find declarations in utils.h."""
        decls = self.analyzer.find_declarations("utils.h", "add_numbers")
        self.assertGreaterEqual(len(decls), 1)


if __name__ == "__main__":
    unittest.main()

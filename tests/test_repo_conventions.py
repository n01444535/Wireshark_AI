import ast
from pathlib import Path
import unittest


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PYTHON_SOURCE_PATHS = [PROJECT_ROOT / "main.py", *sorted((PROJECT_ROOT / "src").glob("*.py"))]
BANNED_GENERIC_IDENTIFIERS = {
    "item",
    "row",
    "key",
    "value",
    "result",
    "proto",
    "parts",
    "lines",
    "matches",
    "arr",
    "temp",
    "tmp",
    "x",
    "v",
}


class StoredIdentifierCollector(ast.NodeVisitor):
    def __init__(self):
        self.occurrences = []

    def _record_identifier(self, identifier_name, line_number):
        if identifier_name in BANNED_GENERIC_IDENTIFIERS:
            self.occurrences.append((identifier_name, line_number))

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Store):
            self._record_identifier(node.id, node.lineno)
        self.generic_visit(node)

    def visit_arg(self, node):
        self._record_identifier(node.arg, node.lineno)
        self.generic_visit(node)


class RepoConventionTests(unittest.TestCase):
    def test_python_locals_and_parameters_do_not_use_banned_generic_identifiers(self):
        violating_identifier_messages = []

        for python_source_path in PYTHON_SOURCE_PATHS:
            module_tree = ast.parse(python_source_path.read_text(), filename=str(python_source_path))
            stored_identifier_collector = StoredIdentifierCollector()
            stored_identifier_collector.visit(module_tree)
            for identifier_name, line_number in stored_identifier_collector.occurrences:
                violating_identifier_messages.append(
                    f"{python_source_path.relative_to(PROJECT_ROOT)}:{line_number} -> {identifier_name}"
                )

        self.assertEqual(
            violating_identifier_messages,
            [],
            "Found banned generic identifiers:\n" + "\n".join(violating_identifier_messages),
        )

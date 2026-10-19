"""Limited privacy copy is not a completeness guarantee or stale source."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from windows_app import file_revision, make_safer_copy, summarize_review


class UploadGuardReviewTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "notes.txt"
        self.source.write_text("Email: alice@example.net\n", encoding="utf-8")

    def test_summary_distinguishes_limited_and_unchecked(self):
        results = [
            {"decision": "LIMITED", "unchecked": ["visible text"]},
            {"decision": "REVIEW", "unchecked": ["rest of file"]},
            {"decision": "BLOCK", "unchecked": []},
        ]
        self.assertEqual(summarize_review(results),
                         {"BLOCK": 1, "REVIEW": 1, "LIMITED": 1,
                          "not_fully_checked": 2})

    def test_limited_copy_not_original(self):
        original = file_revision(self.source)
        output = make_safer_copy(self.source, self.root / "output")
        self.assertEqual(original, file_revision(self.source))
        self.assertIn("[REDACTED_EMAIL]", output.read_text(encoding="utf-8"))

    def test_mid_conversion_change_discards_new_output(self):
        import windows_app
        actual = windows_app.verify_safer_copy
        def mutate_original(input_path, output_path):
            valid = actual(input_path, output_path)
            self.source.write_text("changed since start\n", encoding="utf-8")
            return valid
        with patch("windows_app.verify_safer_copy", side_effect=mutate_original):
            with self.assertRaisesRegex(ValueError, "Source file changed"):
                make_safer_copy(self.source, self.root / "output")
        self.assertEqual(list((self.root / "output").iterdir()), [])


if __name__ == "__main__":
    unittest.main()

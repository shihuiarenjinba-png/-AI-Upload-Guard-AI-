"""Regression checks for user-visible inspection scope and protected output."""
from pathlib import Path
import tempfile
import unittest

from windows_app import inspect_file, make_safer_copy


class UploadReviewGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_clean_text_is_limited_not_certified_safe(self):
        p = self.root / "日本語 連絡先.txt"
        p.write_text("This is a small, ordinary sample.", encoding="utf-8")
        result = inspect_file(p)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["decision"], "LIMITED")
        self.assertIn("Unrecognized secrets", " ".join(result["unchecked"]))
        self.assertTrue(result["checked"])

    def test_warning_and_block_have_distinct_decisions(self):
        p = self.root / "warning.txt"
        p.write_text("Contact: person@example.org", encoding="utf-8")
        reviewed = inspect_file(p)
        self.assertEqual(reviewed["decision"], "REVIEW")
        self.assertIn("email address candidate", reviewed["findings"])
        blocked = self.root / "tool.ps1"
        blocked.write_text("Write-Host hello", encoding="utf-8")
        self.assertEqual(inspect_file(blocked)["decision"], "BLOCK")
        with self.assertRaises(ValueError):
            make_safer_copy(blocked, self.root / "out")

    def test_large_text_shows_partial_scan_limit(self):
        p = self.root / "long.txt"
        p.write_bytes(b"x" * (2_000_000 + 5000) + b"\n")
        result = inspect_file(p)
        self.assertTrue(any("2 MB" in note for note in result["unchecked"]))

    def test_existing_copy_never_overwritten(self):
        p = self.root / "source.txt"
        p.write_text("Alice alice@example.com", encoding="utf-8")
        directory = self.root / "copies"
        directory.mkdir()
        existing = directory / "source_safe.txt"
        existing.write_text("valuable prior output", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            make_safer_copy(p, directory)
        self.assertEqual(existing.read_text(encoding="utf-8"), "valuable prior output")
        self.assertIn("alice@example.com", p.read_text(encoding="utf-8"))

    def test_text_output_reinspected(self):
        p = self.root / "message.txt"
        p.write_text("contact customer@example.com or 090-1234-5678", encoding="utf-8")
        out = make_safer_copy(p, self.root / "new")
        self.assertNotIn("customer@example.com", out.read_text(encoding="utf-8"))
        self.assertEqual(inspect_file(out)["decision"], "LIMITED")

    def test_pdf_scope_explicit_even_without_findings(self):
        from pypdf import PdfWriter
        p = self.root / "sample.pdf"
        w = PdfWriter()
        w.add_blank_page(width=100, height=100)
        with p.open("wb") as fh:
            w.write(fh)
        result = inspect_file(p)
        self.assertIn(result["decision"], ("LIMITED", "REVIEW"))
        self.assertIn("remaining pages", " ".join(result["unchecked"]))


if __name__ == "__main__":
    unittest.main()

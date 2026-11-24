from __future__ import annotations

import tempfile
import zipfile
from pathlib import Path
from unittest.mock import patch

from pypdf import PdfWriter
import windows_app
from windows_app import inspect_file


def make_pdf(path: Path, pages: int = 1, *, encrypted: bool = False, attachment: bool = False) -> None:
    writer = PdfWriter()
    for _ in range(pages):
        writer.add_blank_page(width=100, height=100)
    if attachment:
        writer.add_attachment("synthetic.txt", "synthetic attachment")
    if encrypted:
        writer.encrypt("synthetic-password")
    with path.open("wb") as stream:
        writer.write(stream)


with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)

    # Supported text is fully decoded up to and including the limit.
    exact_text = root / "limit.txt"
    exact_text.write_bytes(b"A" * windows_app.MAX_TEXT_BYTES)
    assert inspect_file(exact_text)["inspection_state"] == "COMPLETE"
    large_text = root / "large.txt"
    large_text.write_bytes(b"A" * (windows_app.MAX_TEXT_BYTES + 1))
    large_result = inspect_file(large_text)
    assert large_result["inspection_state"] == "PARTIAL" and not large_result["safe_copy_allowed"]

    office = root / "oversized.xml.xlsx"
    with zipfile.ZipFile(office, "w") as archive:
        archive.writestr("xl/workbook.xml", "<workbook/>")
        archive.writestr("xl/large.xml", "<root>" + ("x" * (windows_app.MAX_XML_BYTES + 1)) + "</root>")
    assert inspect_file(office)["inspection_state"] == "PARTIAL"

    too_many = root / "too-many.xlsx"
    with zipfile.ZipFile(too_many, "w") as archive:
        archive.writestr("xl/workbook.xml", "<workbook/>")
        for i in range(windows_app.MAX_ZIP_ENTRIES):
            archive.writestr(f"docProps/item{i}.xml", "x")
    assert inspect_file(too_many)["inspection_state"] == "BLOCKED"

    expanded = root / "expanded.xlsx"
    with zipfile.ZipFile(expanded, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("xl/workbook.xml", "<w/>")
        archive.writestr("xl/other.xml", "123456")
    with patch.object(windows_app, "MAX_ZIP_EXPANDED_BYTES", 8):
        assert inspect_file(expanded)["inspection_state"] == "BLOCKED"

    compressed = root / "ratio.docx"
    with zipfile.ZipFile(compressed, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("word/document.xml", "x" * 3_000_000)
    assert inspect_file(compressed)["inspection_state"] == "BLOCKED"

    pdf_limit = root / "pdf-limit.pdf"
    make_pdf(pdf_limit, windows_app.MAX_PDF_PAGES)
    with patch("pypdf._page.PageObject.extract_text", return_value="ordinary synthetic text"):
        assert inspect_file(pdf_limit)["inspection_state"] == "COMPLETE"
    pdf_over = root / "pdf-over.pdf"
    make_pdf(pdf_over, windows_app.MAX_PDF_PAGES + 1)
    with patch("pypdf._page.PageObject.extract_text", return_value="ordinary synthetic text"):
        assert inspect_file(pdf_over)["inspection_state"] == "PARTIAL"
    attached = root / "attachment.pdf"
    make_pdf(attached, attachment=True)
    attached_result = inspect_file(attached)
    assert attached_result["inspection_state"] == "UNSUPPORTED" and not attached_result["safe_copy_allowed"]
    encrypted = root / "encrypted.pdf"
    make_pdf(encrypted, encrypted=True)
    assert inspect_file(encrypted)["inspection_state"] == "BLOCKED"

    corrupt = root / "corrupt.pdf"
    corrupt.write_bytes(b"not a pdf")
    assert inspect_file(corrupt)["inspection_state"] == "ERROR"
    unknown = root / "unknown.bin"
    unknown.write_bytes(b"x")
    assert inspect_file(unknown)["inspection_state"] == "UNSUPPORTED"

    # Extraction failure, timeout, and memory exhaustion are explicit non-complete states.
    with patch.object(windows_app, "read_text_all", side_effect=MemoryError):
        assert inspect_file(exact_text)["inspection_state"] == "ERROR"
    with patch("pypdf._page.PageObject.extract_text", side_effect=ValueError("synthetic extraction failure")):
        assert inspect_file(pdf_limit)["inspection_state"] == "ERROR"
    with patch("pypdf._page.PageObject.extract_text", return_value="x" * (windows_app.MAX_PDF_TEXT_CHARS + 1)):
        assert inspect_file(pdf_limit)["inspection_state"] == "PARTIAL"
    ticks = iter([0.0, 0.0, float(windows_app.PDF_SCAN_SECONDS + 1)])
    with patch.object(windows_app.time, "monotonic", side_effect=lambda: next(ticks)), patch("pypdf._page.PageObject.extract_text", return_value="ordinary synthetic text"):
        timed = inspect_file(pdf_limit)
    assert timed["inspection_state"] == "PARTIAL", timed

    mixed = [inspect_file(exact_text), inspect_file(large_text)]
    assert all(item["safe_copy_allowed"] for item in mixed) is False

    class FakeControl:
        def __init__(self):
            self.state = None
            self.text = None
        def config(self, **kwargs):
            self.state = kwargs.get("state", self.state)
            self.text = kwargs.get("text", self.text)
    class FakeListbox:
        def delete(self, *_): pass
        def insert(self, *_): pass

    app = windows_app.App.__new__(windows_app.App)
    app.files = [exact_text, large_text]
    app.results = []
    app.listbox = FakeListbox()
    app.safe_copy_button = FakeControl()
    app.status = FakeControl()
    app.scan()
    assert app.safe_copy_button.state == "disabled"
    assert "incomplete" in app.status.text.lower()

print("AI Upload Guard classification regression: PASS")

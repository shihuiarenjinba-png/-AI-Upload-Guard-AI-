from pathlib import Path
import tempfile
from pypdf import PdfReader, PdfWriter

from windows_app import inspect_file, make_safer_copy

XMP = b'''<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">
<dc:title><rdf:Alt><rdf:li xml:lang="x-default">secret</rdf:li></rdf:Alt></dc:title>
</rdf:Description></rdf:RDF></x:xmpmeta>
<?xpacket end="w"?>'''

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)

    src = root / "sample.txt"
    src.write_text("Contact test@example.com or 090-1234-5678", encoding="utf-8")
    result = inspect_file(src)
    assert result["status"] == "warning"
    out = make_safer_copy(src, root / "out")
    text = out.read_text(encoding="utf-8")
    assert "test@example.com" not in text
    assert "090-1234-5678" not in text

    undecodable = root / "undecodable.txt"
    undecodable.write_bytes(b"\x81")
    bad = inspect_file(undecodable)
    assert bad["status"] == "rejected", bad
    assert any("text parser failure" in item for item in bad["findings"])
    try:
        make_safer_copy(undecodable, root / "bad-out")
    except ValueError:
        pass
    else:
        raise AssertionError("Undecodable text must not produce a safer copy")

    pdf = root / "sample.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    writer.add_metadata({"/Title": "secret", "/Author": "private"})
    writer.xmp_metadata = XMP
    with pdf.open("wb") as fh:
        writer.write(fh)
    inspected = inspect_file(pdf)
    assert inspected["status"] == "warning", inspected
    safe_pdf = make_safer_copy(pdf, root / "pdf-out")
    safe_reader = PdfReader(str(safe_pdf))
    assert safe_reader.metadata is None, safe_reader.metadata
    assert safe_reader.xmp_metadata is None, safe_reader.xmp_metadata

print("AI Upload Guard smoke test: OK")

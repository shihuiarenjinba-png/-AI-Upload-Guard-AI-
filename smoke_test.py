from pathlib import Path
import tempfile
from PIL import Image
from pypdf import PdfReader, PdfWriter

from windows_app import find_email_candidates, inspect_file, make_safer_copy

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
    src.write_text(
        "Contact test@example.com or 090-1234-5678, "
        "+81 90-1234-5678, +819012345678, 09012345678; ID 123456789012",
        encoding="utf-8",
    )
    result = inspect_file(src)
    assert result["status"] == "warning"
    out = make_safer_copy(src, root / "out")
    text = out.read_text(encoding="utf-8")
    assert "test@example.com" not in text
    assert "090-1234-5678" not in text
    assert "+81 90-1234-5678" not in text
    assert "+819012345678" not in text
    assert "09012345678" not in text
    assert "123456789012" in text
    assert text.count("[REDACTED_PHONE]") == 4, text
    assert "[REDACTED_ID]" not in text, text

    warning_only = root / "long-id-warning-only.txt"
    warning_only.write_text(
        "UUID tail 123e4567-e89b-12d3-a456-000000000000 / "
        "timestamp 1700000000123 / order 202600000012 / account 123456789012",
        encoding="utf-8",
    )
    warning_result = inspect_file(warning_only)
    assert "long numeric identifier candidate" in warning_result["findings"], warning_result
    warning_copy = make_safer_copy(warning_only, root / "warning-only-out")
    assert warning_copy.read_text(encoding="utf-8") == warning_only.read_text(encoding="utf-8")

    valid_emails = [
        "simple@example.com",
        "first.last+tag@sub.example.co.jp",
        "日本語周辺 user_123@example-domain.jp です",
        "CSV,value@example.org,末尾",
        '{"email":"json.user@example.net"}',
        "mailto:owner@example.com",
    ]
    for value in valid_emails:
        assert find_email_candidates(value), value

    hard_email_negatives = [
        "abc@",
        "@example.com",
        "a..b@example.com",
        "name@example",
        "https://user@example.com/private",
        "filename=report@0.txt",
        "report@5.txt",
        "const value = 'abc@';",
        "version=build@1.2.3",
        "user@-invalid.example",
        "user@invalid-.example",
        "全角＠example.com",
        "'not an address: abc@'",
    ]
    for value in hard_email_negatives:
        assert not find_email_candidates(value), value

    negative = root / "phone-negative.txt"
    negative.write_text(
        "2026-09-23 / 〒901-1234 / JPY 12,345 / ORDER-123456 / "
        "978-4-1234-5678-X / 192.0.2.10 / 090-123-456 / "
        "+81-090-1234-5678 / +81 090 1234 5678",
        encoding="utf-8",
    )
    negative_result = inspect_file(negative)
    assert "phone number candidate" not in negative_result["findings"], negative_result

    undecodable = root / "undecodable.txt"
    undecodable.write_bytes(b"\x81")
    bad = inspect_file(undecodable)
    assert bad["status"] == "rejected", bad
    assert any("text parser failure" in item for item in bad["findings"])

    binary_like = root / "binary-looking.txt"
    binary_like.write_bytes(b"\x00" * 64)
    binary_result = inspect_file(binary_like)
    assert binary_result["status"] == "rejected", binary_result
    try:
        make_safer_copy(binary_like, root / "bad-out")
    except ValueError:
        pass
    else:
        raise AssertionError("Binary-like text must not produce a safer copy")

    bmp = root / "日本語_image.bmp"
    Image.new("RGB", (32, 32), "white").save(bmp, format="BMP")
    bmp_result = inspect_file(bmp)
    assert bmp_result["status"] in {"accepted", "warning"}, bmp_result
    bmp_safe = make_safer_copy(bmp, root / "bmp-out")
    assert bmp_safe.exists()
    with Image.open(bmp_safe) as cleaned_bmp:
        cleaned_bmp.verify()

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

    spoofed_pdf = root / "not-really.pdf"
    spoofed_pdf.write_text("not a pdf", encoding="utf-8")
    spoofed_result = inspect_file(spoofed_pdf)
    assert spoofed_result["status"] == "rejected", spoofed_result

print("AI Upload Guard smoke test: OK")

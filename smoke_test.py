from pathlib import Path
import tempfile

from windows_app import inspect_file, make_safer_copy

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
print("AI Upload Guard smoke test: OK")

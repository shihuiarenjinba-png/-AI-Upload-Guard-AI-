from __future__ import annotations

import codecs
import re
import zipfile
from pathlib import Path
from tkinter import BOTH, END, LEFT, RIGHT, Button, Frame, Label, Listbox, Scrollbar, Tk, filedialog, messagebox

EMAIL_RE = re.compile(
    r"(?<![A-Z0-9._%+-])"
    r"[A-Z0-9_%+-]+(?:\.[A-Z0-9_%+-]+)*"
    r"@[A-Z0-9-]+(?:\.[A-Z0-9-]+)+"
    r"(?![A-Z0-9._-])",
    re.I,
)
PHONE_RE = re.compile(
    r"(?<![\d+])(?<!\+81-)(?<!\+81 )(?:"
    r"\+81(?:[- ]?(?:70|80|90)[- ]?\d{4}[- ]?\d{4}|[- ]?(?!0)\d{1,4}[- ]\d{1,4}[- ]\d{3,4})"
    r"|0(?:70|80|90)(?:[- ]?\d{4}){2}"
    r"|0(?![789]0[- ])\d{1,4}[- ]\d{1,4}[- ]\d{3,4}"
    r")(?!\d)"
)
LONG_ID_RE = re.compile(r"(?<!\d)\d{10,16}(?!\d)")
DANGEROUS = {".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".js", ".vbs", ".msi", ".jar"}
ALLOWED = {
    ".pdf", ".csv", ".tsv", ".xlsx", ".docx", ".txt", ".md", ".json", ".xml",
    ".yaml", ".yml", ".log", ".jpg", ".jpeg", ".png", ".webp", ".bmp", ".tif", ".tiff",
}
TEXTLIKE = {".csv", ".tsv", ".txt", ".md", ".json", ".xml", ".yaml", ".yml", ".log"}
IMAGELIKE = {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".tif", ".tiff"}
TEXT_ENCODINGS = ("utf-8-sig", "utf-8", "cp932", "utf-16")


def validate_decoded_text(text: str) -> str:
    if "\x00" in text:
        raise UnicodeError("Decoded text contains NUL bytes and appears binary.")
    if text:
        controls = sum(ord(ch) < 32 and ch not in "\t\n\r\f" for ch in text)
        if controls / len(text) > 0.01:
            raise UnicodeError("Decoded text contains too many control characters and appears binary.")
    return text


def decode_bytes(raw: bytes) -> str:
    last_error: UnicodeError | None = None
    for enc in TEXT_ENCODINGS:
        try:
            return validate_decoded_text(raw.decode(enc))
        except UnicodeError as exc:
            last_error = exc
    raise UnicodeError(f"Unsupported or undecodable text encoding; supported encodings: {', '.join(TEXT_ENCODINGS)}") from last_error


def decode_sample_bytes(raw: bytes, *, complete: bool = False) -> str:
    """Decode a byte-limited sample without misclassifying a valid multibyte tail."""
    last_error: UnicodeError | None = None
    for enc in TEXT_ENCODINGS:
        try:
            decoder = codecs.getincrementaldecoder(enc)(errors="strict")
            return validate_decoded_text(decoder.decode(raw, final=complete))
        except UnicodeError as exc:
            last_error = exc
    raise UnicodeError(f"Unsupported or undecodable text encoding; supported encodings: {', '.join(TEXT_ENCODINGS)}") from last_error


def read_text_sample(path: Path, limit: int = 2_000_000) -> str:
    with path.open("rb") as fh:
        raw = fh.read(limit + 4096)
    return decode_sample_bytes(raw, complete=path.stat().st_size <= len(raw))


def read_text_all(path: Path) -> str:
    return decode_bytes(path.read_bytes())


def _valid_email_match(text: str, match: re.Match[str]) -> bool:
    """Apply syntax and surrounding-context checks to an email-shaped match."""
    candidate = match.group(0)
    local, domain = candidate.rsplit("@", 1)
    if len(candidate) > 254 or len(local) > 64:
        return False
    labels = domain.split(".")
    if not (2 <= len(labels) and labels[-1].isalpha() and len(labels[-1]) >= 2):
        return False
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels):
        return False
    if not any(char.isalpha() for char in labels[0]):
        return False

    # A syntactically valid address used as URL user-info is not a contact email.
    token_start = max(text.rfind(" ", 0, match.start()), text.rfind("\t", 0, match.start()), text.rfind("\n", 0, match.start())) + 1
    prefix = text[token_start:match.start()].lower()
    if "://" in prefix and not prefix.endswith("mailto:"):
        return False

    # Explicit filename fields are a common hard negative (for example report@0.txt).
    context = text[max(0, token_start - 12):match.start()].lower()
    if context.rstrip().endswith(("filename=", "file=", "path=")):
        return False
    return True


def find_email_candidates(text: str) -> list[re.Match[str]]:
    return [match for match in EMAIL_RE.finditer(text) if _valid_email_match(text, match)]


def redact_email_candidates(text: str) -> str:
    return EMAIL_RE.sub(
        lambda match: "[REDACTED_EMAIL]" if _valid_email_match(text, match) else match.group(0),
        text,
    )


def scan_text(text: str) -> list[str]:
    findings: list[str] = []
    if find_email_candidates(text):
        findings.append("email address candidate")
    if PHONE_RE.search(text):
        findings.append("phone number candidate")
    if LONG_ID_RE.search(text):
        findings.append("long numeric identifier candidate")
    return findings


def inspect_office_container(path: Path) -> list[str]:
    findings: list[str] = []
    try:
        with zipfile.ZipFile(path) as zf:
            names = [n.lower() for n in zf.namelist()]
            if path.suffix.lower() == ".docx" and "word/document.xml" not in names:
                return ["invalid/corrupt DOCX container"]
            if path.suffix.lower() == ".xlsx" and "xl/workbook.xml" not in names:
                return ["invalid/corrupt XLSX container"]
            if any("vbaproject.bin" in n for n in names):
                findings.append("macro content detected")
            if any("externallinks/" in n for n in names):
                findings.append("external links detected")
            if any("comments" in n for n in names):
                findings.append("comments detected")
            text_parts: list[str] = []
            budget = 1_000_000
            for info in zf.infolist():
                if budget <= 0:
                    break
                if info.filename.lower().endswith(".xml") and info.file_size <= 300_000:
                    data = zf.read(info)[: min(info.file_size, budget)]
                    budget -= len(data)
                    text_parts.append(data.decode("utf-8", errors="strict"))
            findings.extend(scan_text("\n".join(text_parts)))
    except (zipfile.BadZipFile, OSError, UnicodeError) as exc:
        findings.append(f"invalid/corrupt Office container: {exc}")
    return findings


def inspect_image(path: Path) -> list[str]:
    findings: list[str] = []
    try:
        from PIL import Image
        with Image.open(path) as im:
            im.verify()
        with Image.open(path) as im:
            exif = im.getexif()
            if exif and len(exif):
                findings.append(f"EXIF metadata present ({len(exif)} tags)")
            if "icc_profile" in im.info:
                findings.append("ICC profile present")
    except Exception as exc:
        findings.append(f"image parser failure: {exc}")
    return findings


def inspect_pdf(path: Path) -> list[str]:
    findings: list[str] = []
    try:
        from pypdf import PdfReader
        reader = PdfReader(str(path), strict=True)
        if reader.is_encrypted:
            return ["encrypted PDF requires explicit handling"]
        if reader.metadata:
            findings.append("PDF document-info metadata present")
        if reader.xmp_metadata:
            findings.append("PDF XMP metadata present")
        text = "\n".join((p.extract_text() or "") for p in reader.pages[:20])
        findings.extend(scan_text(text[:2_000_000]))
    except Exception as exc:
        findings.append(f"PDF parser failure: {exc}")
    return findings


def is_hard_failure(findings: list[str]) -> bool:
    hard_prefixes = (
        "invalid/corrupt",
        "image parser failure",
        "PDF parser failure",
        "encrypted PDF",
        "macro content detected",
        "text parser failure",
    )
    return any(item.startswith(hard_prefixes) for item in findings)


def inspect_file(path: Path) -> dict:
    ext = path.suffix.lower()
    try:
        size = path.stat().st_size
    except OSError as exc:
        return {"file": str(path), "size": 0, "status": "rejected", "findings": [f"file access failure: {exc}"]}
    result = {"file": str(path), "size": size, "status": "accepted", "findings": []}
    if ext in DANGEROUS:
        result["status"] = "rejected"
        result["findings"].append("executable/active-content type")
        return result
    if ext not in ALLOWED:
        result["status"] = "rejected"
        result["findings"].append("unsupported/unknown extension")
        return result
    if size > 200 * 1024 * 1024:
        result["status"] = "rejected"
        result["findings"].append("file exceeds 200 MB limit")
        return result

    if ext in TEXTLIKE:
        try:
            result["findings"].extend(scan_text(read_text_sample(path)))
        except (OSError, UnicodeError) as exc:
            result["findings"].append(f"text parser failure: {exc}")
    elif ext in {".docx", ".xlsx"}:
        result["findings"].extend(inspect_office_container(path))
    elif ext == ".pdf":
        result["findings"].extend(inspect_pdf(path))
    elif ext in IMAGELIKE:
        result["findings"].extend(inspect_image(path))

    if is_hard_failure(result["findings"]):
        result["status"] = "rejected"
    elif result["findings"]:
        result["status"] = "warning"
    return result


def strip_pdf_metadata(writer) -> None:
    writer.metadata = None
    writer.xmp_metadata = None
    writer.compress_identical_objects(remove_duplicates=True, remove_unreferenced=True)


def make_safer_copy(path: Path, output_dir: Path) -> Path:
    inspection = inspect_file(path)
    if inspection["status"] == "rejected":
        raise ValueError("Rejected by intake gate: " + "; ".join(inspection["findings"]))
    ext = path.suffix.lower()
    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / f"{path.stem}_safe{ext}"

    if ext in IMAGELIKE:
        from PIL import Image, ImageOps
        with Image.open(path) as source:
            source.load()
            im = ImageOps.exif_transpose(source)
            im.info.clear()
            if ext in {".jpg", ".jpeg"}:
                im.convert("RGB").save(out, format="JPEG", quality=95, optimize=True)
            elif ext == ".png":
                im.save(out, format="PNG", optimize=True)
            elif ext == ".webp":
                im.save(out, format="WEBP", quality=95, method=6)
            elif ext == ".bmp":
                im.convert("RGB").save(out, format="BMP")
            else:
                im.save(out, format="TIFF", compression="tiff_deflate")
        return out

    if ext == ".pdf":
        from pypdf import PdfReader, PdfWriter
        reader = PdfReader(str(path), strict=True)
        if reader.is_encrypted:
            raise ValueError("Encrypted PDFs are scan/reject only in this MVP.")
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        strip_pdf_metadata(writer)
        with out.open("wb") as fh:
            writer.write(fh)
        return out

    if ext in TEXTLIKE:
        text = read_text_all(path)
        text = redact_email_candidates(text)
        text = PHONE_RE.sub("[REDACTED_PHONE]", text)
        out.write_text(text, encoding="utf-8", newline="")
        return out

    raise ValueError("This format is scan-only in the current Windows MVP; no safer copy was created.")


class App:
    def __init__(self, root: Tk):
        self.root = root
        self.root.title("AI Upload Guard — Windows")
        self.root.geometry("900x620")
        self.files: list[Path] = []
        self.results: list[dict] = []
        top = Frame(root, padx=12, pady=12)
        top.pack(fill="x")
        Label(top, text="AI Upload Guard", font=("Segoe UI", 20, "bold")).pack(anchor="w")
        Label(top, text="Local pre-flight inspection before sending files to AI/external services").pack(anchor="w")
        Button(top, text="Add files", command=self.add_files, width=18).pack(side=LEFT, pady=8)
        Button(top, text="Scan", command=self.scan, width=18).pack(side=LEFT, padx=8)
        Button(top, text="Create safer copies", command=self.safe_copies, width=20).pack(side=LEFT)
        mid = Frame(root, padx=12)
        mid.pack(fill=BOTH, expand=True)
        sb = Scrollbar(mid)
        sb.pack(side=RIGHT, fill="y")
        self.listbox = Listbox(mid, yscrollcommand=sb.set, font=("Consolas", 10))
        self.listbox.pack(side=LEFT, fill=BOTH, expand=True)
        sb.config(command=self.listbox.yview)

    def add_files(self):
        for p in filedialog.askopenfilenames(title="Select files"):
            path = Path(p)
            if path not in self.files:
                self.files.append(path)
        self.render_files()

    def render_files(self):
        self.listbox.delete(0, END)
        for p in self.files:
            self.listbox.insert(END, str(p))

    def scan(self):
        if not self.files:
            messagebox.showinfo("AI Upload Guard", "Select one or more files first.")
            return
        self.results = [inspect_file(p) for p in self.files]
        self.listbox.delete(0, END)
        for r in self.results:
            findings = "; ".join(r["findings"]) or "no flagged issue in supported checks"
            self.listbox.insert(END, f"[{r['status'].upper()}] {r['file']} — {findings}")

    def safe_copies(self):
        if not self.files:
            messagebox.showinfo("AI Upload Guard", "Select files first.")
            return
        folder = filedialog.askdirectory(title="Choose output folder")
        if not folder:
            return
        ok, errors = 0, []
        for p in self.files:
            try:
                make_safer_copy(p, Path(folder))
                ok += 1
            except Exception as exc:
                errors.append(f"{p.name}: {exc}")
        msg = f"Created {ok} safer copy/copies."
        if errors:
            msg += "\n\n" + "\n".join(errors[:10])
        messagebox.showinfo("AI Upload Guard", msg)


def main():
    from i18n import install_bilingual_ui

    root = Tk()
    App(root)
    install_bilingual_ui(root)
    root.mainloop()


if __name__ == "__main__":
    main()

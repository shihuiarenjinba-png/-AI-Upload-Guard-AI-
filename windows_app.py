from __future__ import annotations

import codecs
import hashlib
import re
import zipfile
from pathlib import Path
from i18n import translate
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
TIFF_STRUCTURAL_TAGS = {
    254, 256, 257, 258, 259, 262, 266, 273, 277, 278, 279,
    282, 283, 284, 286, 287, 292, 293, 296, 317, 320, 322,
    323, 324, 325, 338, 339,
}


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
            raw_tags = set(exif.keys()) if exif else set()
            structural_tags = raw_tags & TIFF_STRUCTURAL_TAGS if im.format == "TIFF" else set()
            separately_reported_tags = {34675} if "icc_profile" in im.info else set()
            privacy_tags = raw_tags - structural_tags - separately_reported_tags
            if privacy_tags:
                findings.append(f"EXIF metadata present ({len(privacy_tags)} privacy/content tags)")
            if 34853 in raw_tags:
                findings.append("GPS metadata present")
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


def _inspect_file_core(path: Path) -> dict:
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


def inspect_file(path: Path) -> dict:
    """Keep the legacy status for existing consumers and expose scan coverage."""
    result = _inspect_file_core(path)
    ext = path.suffix.lower()
    checked = []
    unchecked = []
    if result["status"] == "rejected":
        unchecked.append("Content was not fully inspected; upload is blocked.")
    elif ext in TEXTLIKE:
        checked.append("Text pattern candidates (email, phone, long number)")
        if result["size"] > 2_000_000 + 4096:
            unchecked.append("Text beyond the first 2 MB was not scanned.")
        unchecked.append("Unrecognized secrets and semantic context")
    elif ext in {".docx", ".xlsx"}:
        checked.append("Some Office XML text and container indicators")
        unchecked.append("All embedded content, hidden data and ZIP contents outside scan limits")
    elif ext == ".pdf":
        checked.append("Document metadata and extractable text on first 20 pages")
        unchecked.append("Scanned images/OCR, attachments, annotations, hidden objects and remaining pages")
    elif ext in IMAGELIKE:
        checked.append("EXIF/GPS/ICC indicators")
        unchecked.append("Visible personal data, text, faces, QR codes and embedded payloads")
    if not checked:
        checked.append("File type, size and basic parse gate")
    result["checked"] = checked
    result["unchecked"] = unchecked
    result["decision"] = (
        "BLOCK" if result["status"] == "rejected"
        else "REVIEW" if result["status"] == "warning"
        else "LIMITED"
    )
    return result


def verify_safer_copy(path: Path, output: Path) -> Path:
    """Verify only the explicitly supported transformations, not complete safety."""
    try:
        inspection = inspect_file(output)
        ext = path.suffix.lower()
        if inspection["status"] == "rejected":
            raise ValueError("Generated output could not be re-read.")
        if ext in IMAGELIKE:
            if any("GPS metadata present" in x or "ICC profile present" in x or "EXIF metadata present" in x
                   for x in inspection["findings"]):
                raise ValueError("Output metadata flags remain.")
        elif ext == ".pdf":
            from pypdf import PdfReader
            reader = PdfReader(str(output), strict=True)
            if reader.metadata or reader.xmp_metadata:
                raise ValueError("PDF metadata remains.")
            if any(x in inspection["findings"] for x in (
                "email address candidate", "phone number candidate", "long numeric identifier candidate"
            )):
                raise ValueError("Detected sensitive PDF text remains; metadata-only output is not approved.")
        elif ext in TEXTLIKE:
            if any(x in inspection["findings"] for x in ("email address candidate", "phone number candidate")):
                raise ValueError("Output text still contains detected email/phone candidates.")
        return output
    except BaseException:
        output.unlink(missing_ok=True)
        raise


def _save_new_image(image, out: Path, format_name: str, **options) -> None:
    created = False
    try:
        with out.open("xb") as handle:
            created = True
            image.save(handle, format=format_name, **options)
    except BaseException:
        if created:
            out.unlink(missing_ok=True)
        raise


def strip_pdf_metadata(writer) -> None:
    writer.metadata = None
    writer.xmp_metadata = None
    writer.compress_identical_objects(remove_duplicates=True, remove_unreferenced=True)


def file_revision(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Source must be a regular, existing file.")
    digest = hashlib.sha256()
    with path.open("rb") as reader:
        for block in iter(lambda: reader.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_source_copy(path: Path, output: Path, original_revision: str) -> Path:
    try:
        if file_revision(path) != original_revision:
            raise ValueError("Source file changed during conversion; new output discarded.")
        return output
    except BaseException:
        # Only an output created by this conversion reaches this function.
        output.unlink(missing_ok=True)
        raise


def summarize_review(results: list[dict]) -> dict[str, int]:
    counts = {"BLOCK": 0, "REVIEW": 0, "LIMITED": 0, "not_fully_checked": 0}
    for item in results:
        key = item.get("decision", "BLOCK")
        counts[key if key in counts else "BLOCK"] += 1
        if item.get("unchecked"):
            counts["not_fully_checked"] += 1
    return counts


def make_safer_copy(path: Path, output_dir: Path) -> Path:
    original_revision = file_revision(path)
    inspection = inspect_file(path)
    if inspection["status"] == "rejected":
        raise ValueError("Rejected by intake gate: " + "; ".join(inspection["findings"]))
    ext = path.suffix.lower()
    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / f"{path.stem}_safe{ext}"
    if out.exists() or out.is_symlink() or out.resolve() == path.resolve():
        raise FileExistsError("Output already exists or would overwrite an input; choose another folder.")

    if ext in IMAGELIKE:
        from PIL import Image, ImageOps
        with Image.open(path) as source:
            source.load()
            im = ImageOps.exif_transpose(source)
            im.info.clear()
            if ext in {".jpg", ".jpeg"}:
                _save_new_image(im.convert("RGB"), out, "JPEG", quality=95, optimize=True)
            elif ext == ".png":
                _save_new_image(im, out, "PNG", optimize=True)
            elif ext == ".webp":
                _save_new_image(im, out, "WEBP", quality=95, method=6)
            elif ext == ".bmp":
                _save_new_image(im.convert("RGB"), out, "BMP")
            else:
                _save_new_image(im, out, "TIFF", compression="tiff_deflate")
        return verify_source_copy(path, verify_safer_copy(path, out), original_revision)

    if ext == ".pdf":
        if any(x in inspection["findings"] for x in (
            "email address candidate", "phone number candidate", "long numeric identifier candidate"
        )):
            raise ValueError("PDF contains detected text candidates; metadata-only copying is refused.")
        from pypdf import PdfReader, PdfWriter
        reader = PdfReader(str(path), strict=True)
        if reader.is_encrypted:
            raise ValueError("Encrypted PDFs are scan/reject only in this MVP.")
        # The intake scanner checks extractable text on the first 20 pages.
        # Never produce a limited copy when pages beyond that boundary exist.
        if len(reader.pages) > 20:
            raise ValueError("PDF has uninspected pages beyond page 20; no copy created.")
        if any(page.get("/Annots") for page in reader.pages):
            raise ValueError("PDF annotations are outside the inspected scope; no copy created.")
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        strip_pdf_metadata(writer)
        created = False
        try:
            with out.open("xb") as fh:
                created = True
                writer.write(fh)
        except BaseException:
            if created:
                out.unlink(missing_ok=True)
            raise
        return verify_source_copy(path, verify_safer_copy(path, out), original_revision)

    if ext in TEXTLIKE:
        text = read_text_all(path)
        text = redact_email_candidates(text)
        text = PHONE_RE.sub("[REDACTED_PHONE]", text)
        created = False
        try:
            with out.open("x", encoding="utf-8", newline="") as fh:
                created = True
                fh.write(text)
        except BaseException:
            if created:
                out.unlink(missing_ok=True)
            raise
        return verify_source_copy(path, verify_safer_copy(path, out), original_revision)

    raise ValueError("This format is scan-only in the current Windows MVP; no safer copy was created.")


class App:
    def __init__(self, root: Tk):
        self.root = root
        self.root.title("AI Upload Guard — Windows")
        self.root.geometry("900x620")
        self.root.minsize(760, 500)
        self.files: list[Path] = []
        self.results: list[dict] = []
        self.overview = None
        top = Frame(root, padx=12, pady=12)
        top.pack(fill="x")
        Label(top, text="AI Upload Guard", font=("Segoe UI", 20, "bold")).pack(anchor="w")
        Label(top, text="Local pre-upload review. No scan can guarantee that a file is safe.").pack(anchor="w")
        Label(top, text="① Add files & scan  →  ② Rescan if needed  →  ③ Review results and save supported copies", font=("Segoe UI", 10, "bold"), wraplength=840, justify=LEFT).pack(anchor="w", pady=(4, 0))
        Button(top, text="1  Add files", command=self.add_files, width=18).pack(side=LEFT, pady=8)
        Button(top, text="2  Rescan", command=self.scan, width=18).pack(side=LEFT, padx=8)
        Button(top, text="3  Save supported copies", command=self.safe_copies, width=26).pack(side=LEFT)
        self.overview = Label(root, text="No scan yet. LIMITED never means safe.",
                              anchor="w", padx=12)
        self.overview.pack(fill="x")
        mid = Frame(root, padx=12)
        mid.pack(fill=BOTH, expand=True)
        sb = Scrollbar(mid)
        sb.pack(side=RIGHT, fill="y")
        self.listbox = Listbox(mid, yscrollcommand=sb.set, font=("Consolas", 10))
        self.listbox.pack(side=LEFT, fill=BOTH, expand=True)
        sb.config(command=self.listbox.yview)

    def add_files(self):
        for p in filedialog.askopenfilenames(parent=self.root, title="Select files"):
            path = Path(p)
            if path not in self.files:
                self.files.append(path)
        self.render_files()
        if self.files:
            self.scan()

    def render_files(self):
        self.listbox.delete(0, END)
        for p in self.files:
            self.listbox.insert(END, p.name)

    def scan(self):
        if not self.files:
            messagebox.showinfo("AI Upload Guard", "Select one or more files first.")
            return
        self.results = [inspect_file(p) for p in self.files]
        counts = summarize_review(self.results)
        self.overview.configure(text=translate(
            f"BLOCK {counts['BLOCK']} | REVIEW {counts['REVIEW']} | "
            f"LIMITED {counts['LIMITED']} | Not fully checked {counts['not_fully_checked']} "
            "— do not upload without your own review."))
        self.listbox.delete(0, END)
        for r in self.results:
            findings = "; ".join(r["findings"]) or "No candidate matched in checked areas"
            limits = "; ".join(r["unchecked"]) or "Scope is limited to implemented checks"
            self.listbox.insert(END, f"[{r['decision']}] {Path(r['file']).name} — {findings}")
            self.listbox.insert(END, f"    Checked: {', '.join(r['checked'])}")
            self.listbox.insert(END, f"    Not checked: {limits}")

    def safe_copies(self):
        if not self.files:
            messagebox.showinfo("AI Upload Guard", "Select files first.")
            return
        self.results = [inspect_file(p) for p in self.files]
        blocked = [Path(r["file"]).name for r in self.results if r["decision"] == "BLOCK"]
        if blocked:
            return messagebox.showerror(
                "Blocked",
                "One or more inputs failed preflight. Remove blocked files before exporting:\n"
                + "\n".join(blocked[:8]),
            )
        unsupported = [p.name for p in self.files if p.suffix.lower() in {".xlsx", ".docx"}]
        if unsupported:
            messagebox.showwarning("Scan-only files",
                "DOCX/XLSX cannot be transformed and will be SKIPPED:\n" +
                "\n".join(unsupported[:10]))
        eligible = [p for p in self.files if p.suffix.lower() not in {".xlsx", ".docx"}]
        if not eligible:
            return messagebox.showinfo("No supported output",
                "Only scan-only Office files were selected; no copies can be created.")
        if not messagebox.askokcancel(
            "Review limited transformations",
            "Images: metadata re-encoding only. PDF: document-info/XMP only.\n"
            "Text: detected email/phone patterns only; long numbers are warning-only.\n"
            "Office files cannot be transformed. Other hidden information may remain.\n"
            "Please inspect every result before sharing. Continue?",
        ):
            return
        folder = filedialog.askdirectory(parent=self.root, title="Choose output folder")
        if not folder:
            return
        ok, errors = 0, []
        for p in eligible:
            try:
                make_safer_copy(p, Path(folder))
                ok += 1
            except Exception as exc:
                errors.append(f"{p.name}: {exc}")
        msg = (f"Created {ok} limited processed copy/copies; "
               f"{len(unsupported)} scan-only Office file(s) skipped. "
               "No complete privacy guarantee.")
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

from __future__ import annotations

import re
import zipfile
from pathlib import Path
from tkinter import BOTH, END, LEFT, RIGHT, Button, Frame, Label, Listbox, Scrollbar, Tk, filedialog, messagebox

EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?81[- ]?)?0?\d{1,4}[- ]?\d{1,4}[- ]?\d{3,4}(?!\d)")
LONG_ID_RE = re.compile(r"(?<!\d)\d{10,16}(?!\d)")
DANGEROUS = {".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".js", ".vbs", ".msi", ".jar"}
ALLOWED = {".pdf", ".csv", ".xlsx", ".docx", ".txt", ".md", ".json", ".jpg", ".jpeg", ".png", ".webp"}
TEXTLIKE = {".csv", ".txt", ".md", ".json"}


def read_text_sample(path: Path, limit: int = 2_000_000) -> str:
    raw = path.read_bytes()[:limit]
    for enc in ("utf-8-sig", "utf-8", "cp932", "utf-16"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="ignore")


def scan_text(text: str) -> list[str]:
    findings: list[str] = []
    if EMAIL_RE.search(text):
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
                    text_parts.append(data.decode("utf-8", errors="ignore"))
            findings.extend(scan_text("\n".join(text_parts)))
    except zipfile.BadZipFile:
        findings.append("invalid/corrupt Office container")
    return findings


def inspect_image(path: Path) -> list[str]:
    findings: list[str] = []
    try:
        from PIL import Image
        with Image.open(path) as im:
            exif = im.getexif()
            if exif and len(exif):
                findings.append(f"EXIF metadata present ({len(exif)} tags)")
            if "icc_profile" in im.info:
                findings.append("ICC profile present")
    except Exception as exc:
        findings.append(f"image parser warning: {exc}")
    return findings


def inspect_pdf(path: Path) -> list[str]:
    findings: list[str] = []
    try:
        from pypdf import PdfReader
        reader = PdfReader(str(path))
        if reader.metadata:
            findings.append("PDF metadata present")
        text = "\n".join((p.extract_text() or "") for p in reader.pages[:20])
        findings.extend(scan_text(text[:2_000_000]))
    except Exception as exc:
        findings.append(f"PDF parser warning: {exc}")
    return findings


def inspect_file(path: Path) -> dict:
    ext = path.suffix.lower()
    result = {"file": str(path), "size": path.stat().st_size, "status": "accepted", "findings": []}
    if ext in DANGEROUS:
        result["status"] = "rejected"
        result["findings"].append("executable/active-content type")
        return result
    if ext not in ALLOWED:
        result["status"] = "rejected"
        result["findings"].append("unsupported/unknown extension")
        return result
    if path.stat().st_size > 200 * 1024 * 1024:
        result["status"] = "rejected"
        result["findings"].append("file exceeds 200 MB limit")
        return result
    if ext in TEXTLIKE:
        result["findings"].extend(scan_text(read_text_sample(path)))
    elif ext in {".docx", ".xlsx"}:
        result["findings"].extend(inspect_office_container(path))
    elif ext == ".pdf":
        result["findings"].extend(inspect_pdf(path))
    elif ext in {".jpg", ".jpeg", ".png", ".webp"}:
        result["findings"].extend(inspect_image(path))
    if result["findings"]:
        result["status"] = "warning"
    return result


def make_safer_copy(path: Path, output_dir: Path) -> Path:
    ext = path.suffix.lower()
    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / f"{path.stem}_safe{ext}"
    if ext in {".jpg", ".jpeg", ".png", ".webp"}:
        from PIL import Image
        with Image.open(path) as im:
            clean = im.convert("RGB") if ext in {".jpg", ".jpeg"} else im.copy()
            kwargs = {"quality": 95} if ext in {".jpg", ".jpeg"} else {}
            clean.save(out, **kwargs)
        return out
    if ext == ".pdf":
        from pypdf import PdfReader, PdfWriter
        reader = PdfReader(str(path))
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        writer.add_metadata({})
        with out.open("wb") as fh:
            writer.write(fh)
        return out
    if ext in TEXTLIKE:
        text = read_text_sample(path, limit=20_000_000)
        text = EMAIL_RE.sub("[REDACTED_EMAIL]", text)
        text = PHONE_RE.sub("[REDACTED_PHONE]", text)
        out.write_text(text, encoding="utf-8")
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
    root = Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()

# AI Upload Guard — Simplified Windows Review Gate

## User workflow
1. Select files. A preflight scan runs immediately.
2. Read the explicit classification: BLOCK (reject), REVIEW (a candidate/issue), or LIMITED (no candidate found within implemented checks).
3. For each result, see both **Checked** and **Not checked**. LIMITED never means safe.
4. Optionally request a limited transformation. A confirmation describes what formats and sensitive content remain outside scope.
5. Reopen and inspect each generated output before any external upload.

### Scope
- Text files: candidate email/phone/long numeric identifier patterns; only the first ~2MB sampled for scan, and the remaining content explicitly marked uninspected.
- Office DOCX/XLSX: container and some XML checks; scan-only; no "safe copy" conversion.
- PDF: metadata + extractable text from first 20 pages, with page/size limits; images, OCR, attachments, annotations and other hidden objects uninspected.
- Images: EXIF/GPS/ICC indicators; visible content, text, faces and embedded payloads uninspected.
- Limited copy: re-encodes images; removes PDF document-info and XMP metadata only; masks recognized text email/phone patterns. Long-digit identifiers are **warning only** due to ambiguity.
- Outputs use exclusive file creation; no existing output is replaced; a supported post-conversion inspection checks the limited target only.

## Test on Windows
```powershell
py -3 -m pip install pillow "pypdf>=6,<7"
py -3 -m compileall -q windows_app.py i18n.py smoke_test.py tests
py -3 .\smoke_test.py
py -3 -m unittest discover -s tests -v
py -3 .\bilingual_smoke_test.py
py -3 .\windows_app.py
```

Portable EXE builder: `build-windows-portable.ps1`. This is **not** an official MSIX.

## Store release gate — HOLD
Requires Windows CI actually executed (not just queued/failed before checkout), hostile input fixtures, Japanese UI + 100/125/150% DPI checks, source/output integrity rechecks, external transmission review, licensing and dependency review, formal Partner Center identity, MSIX package, install/update/uninstall, certification, price, privacy disclosure, screenshots, and documentation of known limits. A metadata-clean PDF is not a securely redacted PDF.

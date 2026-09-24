# AI Upload Guard — Windows MVP

Windows-only implementation. The Web/Mobile repositories are intentionally not modified.

## Current local checks

- Explicit extension allowlist and executable/active-content rejection
- 200 MB per-file limit
- Validated email / phone / long-number candidates in text-like files. Email checks reject malformed local/domain syntax, URL user-info, and filename-like addresses whose first domain label contains no letter.
- DOCX/XLSX ZIP preflight, macro/external-link/comment indicators, text scan
- PDF metadata + extracted-text scan (first 20 pages)
- Image EXIF / ICC metadata indicators
- Safer-copy generation for images (metadata-stripped), PDFs (metadata removed), and text/CSV/JSON/Markdown (email/phone redaction)

Unknown/unsupported formats fail closed.

## Run from source

```powershell
py -3 -m pip install pillow pypdf
py -3 .\windows_app.py
```

## Build portable EXE

```powershell
powershell -ExecutionPolicy Bypass -File .\build-windows-portable.ps1
```

Output: `dist\AIUploadGuard.exe`

## Sales gate

This branch is an MVP, not automatically a sales release. Before distribution verify regression fixtures, egress/network behavior, parser-failure handling, Windows 10/11 execution, malware scan, Authenticode signing, and SHA256 publication. Do not market unsupported DOCX/XLSX automatic sanitization; those formats are scan-only in this MVP.

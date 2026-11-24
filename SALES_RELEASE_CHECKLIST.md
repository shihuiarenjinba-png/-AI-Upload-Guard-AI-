# Sales release checklist / 販売直前チェック

## Code gates / コード側
- [x] Existing privacy/redaction logic remains isolated from UI-language state
- [x] Packaged entry uses explicit **`言語 / Language`** selector
- [x] Choices are `日本語` / `English` and persist under LocalAppData
- [x] Original bilingual translation dictionary remains in use
- [x] Portable build packages `desktop_entry.py`

## Real Windows / fixture gates / 実機確認
- [ ] Windows 10 and Windows 11 smoke tests
- [ ] Switch 日本語 → English → 日本語 and restart; selected language must persist
- [ ] Check 100%, 125%, 150% display scaling and long warning/error messages
- [ ] Run existing product smoke/regression tests in both languages
- [ ] Test supported image/PDF fixtures and deliberately malformed/unsupported files
- [ ] Verify original input is never silently overwritten
- [ ] Verify metadata/XMP/privacy cleanup behavior against controlled fixtures
- [ ] Verify runtime network egress matches the documented local-first boundary
- [ ] Build the one-file EXE from a path containing spaces/non-ASCII characters
- [ ] Run Windows Defender/AV scan and record release SHA-256
- [ ] Prepare LICENSE/NOTICE/SBOM and lock dependency versions
- [ ] Authenticode-sign the final commercial artifact

Do not mark the product sales-ready until all applicable unchecked items are completed.
未チェック項目が残っている間は販売完成扱いにしません。

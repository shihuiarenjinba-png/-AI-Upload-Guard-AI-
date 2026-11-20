# Market / OSS reference audit — 2026-11-20

Product: **AI Upload Guard**

## References reviewed
- Microsoft Presidio: detects/anonymizes PII but explicitly states automated detection cannot guarantee finding every sensitive item.
  - https://github.com/microsoft/presidio
- Dangerzone: separates document-risk reduction from ordinary viewing by using a deliberately conservative conversion/sandbox model.
  - https://github.com/freedomofpress/dangerzone

## Decisions for this product
- Keep this product an **inspection gate**, not a “magic sanitizer”.
- BLOCK / REVIEW / LIMITED must include understandable reasons; uncertainty must not silently become PASS.
- Do not promise exhaustive PII discovery. High-risk or ambiguous cases should require review.
- Keep raw local paths hidden from normal Store-facing UI and keep processing local by default.
- Dangerous/unsupported file types must fail closed without deleting or modifying the source.
- Treat this document as design evidence only; no third-party code was copied.

## Remaining release evidence
- Build a fixture matrix with clear-safe, clear-block, ambiguous-review, unsupported and malformed files.
- Confirm UI filtering and reason text for every decision class on Windows.
- DPI/visual QA, exact Store version/assets, QA_UNSIGNED MSIX and manifest/hash evidence.

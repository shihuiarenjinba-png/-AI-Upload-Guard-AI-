# Windows real-device QA handoff — 2026-11-20

Product: **AI Upload Guard**

## Frozen GitHub checkpoint
- Branch: `codex/store-p1-ai-upload-guard-20261023`
- Source HEAD before this handoff document: `7a6bcea345f52a3b1787d942a2ab8010dfcb6881`
- Latest Windows Actions run at that checkpoint: `44685727025` — **SUCCESS**
- QA_UNSIGNED MSIX artifact: `group-c-QA_UNSIGNED-validation-msix-44685184342-1`
- Artifact ID: `14606316619`

## Important package scope
The QA_UNSIGNED MSIX is for package structure / manifest / payload verification only. It is **not Store-certified and not a production install package**. Do not weaken Windows security policy or install a certificate merely to force this package to install.

For immediate real-device functional/UI testing, use the verified portable EXE from the same workflow/source checkpoint. Installed-MSIX lifecycle testing belongs after a trusted/test-signed or Store-signed package route is explicitly authorized.

## Required Windows 11 matrix
- Windows 11 x64
- 100% DPI
- 125% DPI
- 150% DPI
- Test at a normal desktop resolution and, where practical, 1024×768-class constrained layout.
- JA and EN UI where the product exposes both languages.

For every matrix cell record:
- OS build
- resolution / DPI
- source HEAD
- EXE SHA-256
- launch result
- core operation result
- error-path result
- screenshot path/name
- PASS / REVIEW / FAIL
- short note for any clipping, unreadable text, disabled control, crash or unexpected file write

## Product functional cases
1. Clearly safe fixture.
2. Clearly sensitive fixture that should BLOCK.
3. Ambiguous fixture that should require REVIEW.
4. Unsupported/dangerous format and malformed file.
5. Confirm reason text is understandable, decision filters work, and raw full local paths are not exposed in normal UI.

## Common safety acceptance
1. Launch succeeds without developer/debug controls exposed in normal UI.
2. Primary action is reachable and understandable.
3. Invalid input does not crash the app.
4. Original user input is not overwritten unless a feature explicitly says otherwise.
5. Output location and success/failure state are clear.
6. Close and relaunch once; stale/corrupt UI-state must not prevent startup.
7. No unexpected network access for products documented as local-only.
8. Capture Store screenshots only from real app UI with synthetic/non-personal fixtures.

## Exit condition
Mark this product `WINDOWS_REAL_DEVICE_QA_PASS` only if all required matrix cells and product functional cases pass or have an explicitly accepted limitation. Any crash, incorrect output, hidden overwrite, misleading privacy result, or unusable DPI layout is a release blocker.

Formal Store candidate generation remains separately blocked until the exact approved Store version and final brand assets are recorded. Never substitute the QA workflow-generated version for that approval.

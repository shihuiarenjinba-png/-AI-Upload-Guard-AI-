# Group C progress evidence — 2026-11-20

Product: **AI Upload Guard**

## Validated source before this record
- Source HEAD: `01bc30017dd3fe70072129e660aa173f72636a02`
- GitHub Actions run: `44685184342`
- build-portable: **SUCCESS**
- regression suite: **SUCCESS**
- packaged EXE self-test: **PASS**
- package-unsigned-msix: **SUCCESS**
- real Store candidate build: **SKIPPED by approval gate**

## QA-only package evidence
- Portable EXE SHA-256: `456E233E149925779032DD0BCFFDE811C558940D5942320D912123CC6E9423B3`
- QA version: `1.0.58.0` — workflow-generated, **NOT an approved Store version**
- Package: `AIUploadGuard_QA_UNSIGNED_1.0.58.0_x64.msix`
- MSIX SHA-256: `4EBEDDB4A68350D092AEBEDDDCAA1B2B9281BF3F42803E8B8FF9046BBE454D2B`
- Manifest identity check: **PASS**
- Artifact ID: `14606316619`
- Sales release: `HOLD`

## Current blockers for a real Store candidate
- package version approval is not OWNER_APPROVED
- brand assets approval is not OWNER_APPROVED
- approved Store version is missing
- approved asset directory and `store-assets/approval.json` are missing
- real fixture matrix for BLOCK/REVIEW/LIMITED plus Windows human UI review remains separate

Do not upload the QA_UNSIGNED package as a production Store package.

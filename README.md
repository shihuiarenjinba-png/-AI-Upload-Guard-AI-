# AI Upload Guard

外部AIへファイルを渡す前に、ローカルで**検査範囲・未検査範囲・要確認項目を可視化するUpload Gate**として設計します。

## 役割

この製品自身がすべての形式を魔法のように匿名化するのではなく、ファイル形式ごとに専用エンジンへ振り分けます。

- CSV/XLSX → Excel / CSV Privacy Cleaner
- PDF → PDF Privacy Toolkit
- screenshot/image → Screenshot / Image Privacy Cleaner
- code/config/research package → Research Reproducibility PackagerのCredential Exposure Gate

## 判定モデル

単純な `SAFE / UNSAFE` 二択にしません。

- **PASS**: 対象範囲を検査し、指定policy違反を検出しなかった
- **REVIEW**: candidate、部分検査、曖昧要素がある
- **BLOCK**: credential候補、禁止metadata、未対応active content等がある
- **UNINSPECTED**: このversionでは内容を十分に検査できない

`UNINSPECTED` を `PASS` に変換しないことを最重要ルールにします。

## 検査例

- 氏名 / email / phone / customer ID等の明示ルール候補
- Credential / API key / token候補
- Excel hidden/veryHidden sheet、comments、external links、formula
- PDF metadata、attachments、annotations、forms、actions
- image EXIF/GPS、OCR candidate、QR/face candidate

## 「安全化コピー」の意味

安全化コピーは、各専用Sanitizerが**実際に処理できた形式だけ**生成します。

- Excel/CSV: allowlist export / field deletion / deterministic pseudonymization
- PDF: true redaction / metadata sanitization / strong flatten + output verification
- image: confirmed boxのpixel置換 + metadata除去 + brand-new image再エンコード

OCRやAIが何も見つけなかっただけでは安全化済みコピーと呼びません。

## Auditability

- 元ファイル非変更
- Before/After SHA256
- 検査engine/version
- 検査できた範囲 / できなかった範囲
- 処理rule
- candidate / block理由
- output verification結果

をreportに残します。

この製品は「AIが全部判断してくれる」ものではなく、**外部送信前に何を確認すべきかを漏らしにくくするローカルGate**として専門化します。

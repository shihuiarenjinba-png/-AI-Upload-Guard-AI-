# Microsoft Store掲載文｜AI Upload Guard｜レビュー準備稿
対象ブランチ: `ui/safe-product-upgrade-20261019`
状態: **文案完成 / 公開未承認 / Store ID・価格の実入力未済**
価格の仮設定: **無料候補（仮）**。正式価格・対応市場は権限のある販売者が承認し、Partner Centerで指定する。

## ja-JP
**製品名（候補）:** AI Upload Guard

**短い説明:**
AIへファイルを渡す前に、検査可能な範囲の個人情報候補と未検査部分を表示します。

**詳細説明（そのまま編集欄へ転記可能）:**
AIサービスに文書や画像を渡す前の確認を助けるローカルツールです。対応形式の内容やメタデータを限定的に検査し、BLOCK・REVIEW・LIMITEDに分けて表示します。一部形式では、対応範囲だけを処理した別コピーを作成できます。

・検査結果をBLOCK・REVIEW・LIMITEDで表示
・検査できなかった部分を明示
・対応する形式に限り限定的な処理コピーを保存

**対応範囲と重要な注意事項:**
機密情報の網羅的な検出、完全な匿名化、アップロード安全性の保証はできません。DOCX/XLSXは検査専用で、処理コピーを作りません。AIサービスへの自動アップロード機能はありません。

**What's new:** 初回提出時は空欄。製品更新の場合のみ新旧の違いを事実確認して記載。

## en-US
**Suggested title:** AI Upload Guard

**Short description:**
Check supported parts of files before sharing them with AI services and see what remains uninspected.

**Full description:**
Review selected files locally for limited patterns and metadata indicators before uploading them elsewhere. Results distinguish blocked files, files needing review and limited inspection. Some supported formats can be exported as processed copies.

• BLOCK, REVIEW and LIMITED decisions
• Visible scope of inspected and uninspected content
• Optional limited copy generation for supported formats

**Important limitations:**
No complete confidential-data detection, anonymization or safe-upload guarantee. DOCX and XLSX are inspection-only and cannot be exported as sanitized copies. This app does not automatically upload files to an AI service.

**What's new:** Leave blank for the initial submission.

## Partner Center 編集チェック
- 描写の対象は各製品の現行ブランチで**実装が確認できる機能のみ**。未知の機能や完全安全保証を足さない。
- 正式名の重複確認、年齢区分質問票、価格、カテゴリ、地域、検索キーワード、機能欄は提出画面で設定する。価格は購入実績の裏付けがない仮説。
- スクリーンショットは実機撮影5枚。本文に外部URL、HTML、未確認の商標や第三者との提携表現を入れない。
- 最終チェック: ユーザー向けの日本語/英語を実画面と照合。英語UIが未合格なら対応言語を無理に追加しない。
- ソースWindows QA、MSIX、Store Identity、プライバシー・サポート情報、ライセンス承認が揃うまで掲載しない。

公式: https://learn.microsoft.com/en-us/windows/apps/publish/publish-your-app/msix/add-and-edit-store-listing-info

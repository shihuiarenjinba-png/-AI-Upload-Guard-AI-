from pathlib import Path
import unittest

import i18n

ROOT = Path(__file__).resolve().parents[1]
UI_FILE = ROOT / "windows_app.py"
SOURCE = "① Add files & scan  →  ② Rescan if needed  →  ③ Review results and save supported copies"
ENGLISH = "① Add files & scan  →  ② Rescan if needed  →  ③ Review results and save supported copies"
JAPANESE = "① ファイル追加と自動スキャン  →  ② 必要なら再スキャン  →  ③ 結果確認と対応コピー保存"


class I18nUiContractTests(unittest.TestCase):
    def tearDown(self):
        i18n.set_language("en")

    def test_guide_switches_both_languages(self):
        i18n.set_language("en")
        self.assertEqual(i18n.translate(SOURCE), ENGLISH)
        i18n.set_language("ja")
        self.assertEqual(i18n.translate(SOURCE), JAPANESE)

    def test_ui_installs_visible_language_switch(self):
        ui = UI_FILE.read_text(encoding="utf-8")
        helper = (ROOT / "i18n.py").read_text(encoding="utf-8")
        self.assertIn("install_bilingual_ui", ui)
        self.assertIn("Language / 言語", helper)

    def test_command_bar_icon_label_switches_language(self):
        i18n.set_language("en")
        self.assertEqual(i18n.translate("＋\nAdd files"), "＋\nAdd files")
        i18n.set_language("ja")
        self.assertEqual(i18n.translate("＋\nAdd files"), "＋\nファイルを追加")


if __name__ == "__main__":
    unittest.main()

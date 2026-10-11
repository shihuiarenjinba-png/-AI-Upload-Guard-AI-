import i18n

original = getattr(i18n, "get_language", lambda: getattr(i18n, "_LANGUAGE", "en"))()
try:
    i18n.set_language("ja")
    assert i18n.translate("Add files") == "ファイルを追加"
    assert i18n.translate("Scan") == "スキャン"
    i18n.set_language("en")
    assert i18n.translate("Add files") == "Add files"
    assert i18n.translate("Scan") == "Scan"
finally:
    i18n.set_language(original)

print("AI Upload Guard bilingual UI smoke test: OK")

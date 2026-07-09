"""
Internationalization (i18n) for eBookSanitizer.
Provides Chinese (Traditional) and English translations.
"""

from typing import Dict, Callable, List

# ── Translation Dictionary ────────────────────────────────────────────
# Key format: "section.key"
# Each key maps to {"en": "...", "zh": "..."}

TRANSLATIONS: Dict[str, Dict[str, str]] = {
    # ── App Title & Header ──
    "app.title": {
        "en": "eBookSanitizer",
        "zh": "eBookSanitizer",
    },
    "app.subtitle": {
        "en": "Scan & Sanitize eBooks for Malicious Content",
        "zh": "掃描並消毒電子書中的惡意內容",
    },

    # ── File Selection ──
    "file.drop_title": {
        "en": "Drop eBook here or click to select",
        "zh": "將電子書拖放到此處，或點擊選擇檔案",
    },
    "file.drop_subtitle": {
        "en": "Supports: EPUB, PDF",
        "zh": "支援格式：EPUB、PDF",
    },
    "file.select_button": {
        "en": "Select File",
        "zh": "選擇檔案",
    },
    "file.selected": {
        "en": "Selected",
        "zh": "已選擇",
    },
    "file.selected_count": {
        "en": "Selected: {} files",
        "zh": "已選擇: {} 個檔案",
    },
    "file.batch_mode": {
        "en": "Selected {} files (Batch Mode)",
        "zh": "已選擇 {} 個檔案 (批次模式)",
    },


    # ── Mode Selection ──
    "mode.title": {
        "en": "Sanitization Mode",
        "zh": "消毒模式",
    },
    "option.scrub_metadata": {
        "en": "🧼 Scrub Metadata (Anonymize Author, Dates, and IDs)",
        "zh": "🧼 抹除元數據 (匿名化作者、日期與識別碼)",
    },
    "mode.standard": {
        "en": "🟢 Standard",
        "zh": "🟢 標準",
    },
    "mode.standard_desc": {
        "en": "Remove known threats (scripts, auto-actions). Preserves links and attachments.",
        "zh": "移除已知威脅（腳本、自動動作）。保留連結與附件。",
    },
    "mode.strict": {
        "en": "🟡 Strict",
        "zh": "🟡 嚴格",
    },
    "mode.strict_desc": {
        "en": "Also neutralize external links, embedded files, and tracking resources.",
        "zh": "額外中立化外部連結、嵌入檔案與追蹤資源。",
    },
    "mode.paranoid": {
        "en": "🔴 Paranoid",
        "zh": "🔴 偏執",
    },
    "mode.paranoid_desc": {
        "en": "Maximum security. Rebuild file structure keeping only safe rendering content.",
        "zh": "最高安全性。重建檔案結構，僅保留安全的渲染內容。",
    },

    # ── Actions ──
    "action.scan": {
        "en": "🔍 Scan Only",
        "zh": "🔍 僅掃描",
    },
    "action.sanitize": {
        "en": "🛡️ Scan & Sanitize",
        "zh": "🛡️ 掃描並消毒",
    },
    "action.scanning": {
        "en": "Scanning...",
        "zh": "掃描中...",
    },
    "action.sanitizing": {
        "en": "Sanitizing...",
        "zh": "消毒中...",
    },

    # ── Results ──
    "result.title": {
        "en": "Scan Results",
        "zh": "掃描結果",
    },
    "result.no_threats": {
        "en": "✅ No threats detected!",
        "zh": "✅ 未偵測到威脅！",
    },
    "result.threats_found": {
        "en": "⚠️ Threats detected",
        "zh": "⚠️ 偵測到威脅",
    },
    "result.high": {
        "en": "High",
        "zh": "高",
    },
    "result.medium": {
        "en": "Medium",
        "zh": "中",
    },
    "result.low": {
        "en": "Low",
        "zh": "低",
    },
    "result.sanitized_ok": {
        "en": "✅ File sanitized successfully!",
        "zh": "✅ 檔案消毒成功！",
    },
    "result.sanitized_fail": {
        "en": "❌ Sanitization failed",
        "zh": "❌ 消毒失敗",
    },
    "result.saved_to": {
        "en": "Saved to",
        "zh": "已儲存至",
    },
    "result.open_folder": {
        "en": "Open Folder",
        "zh": "開啟資料夾",
    },
    "result.sha256": {
        "en": "SHA-256",
        "zh": "SHA-256",
    },
    "action.virustotal": {
        "en": "VirusTotal Lookup",
        "zh": "VirusTotal 查詢",
    },

    # ── Log Panel ──
    "log.title": {
        "en": "Activity Log",
        "zh": "活動日誌",
    },
    "log.clear": {
        "en": "Clear",
        "zh": "清除",
    },

    # ── Settings ──
    "settings.language": {
        "en": "Language",
        "zh": "語言",
    },
    "settings.theme": {
        "en": "Theme",
        "zh": "主題",
    },
    "settings.dark": {
        "en": "Dark",
        "zh": "深色",
    },
    "settings.light": {
        "en": "Light",
        "zh": "淺色",
    },

    # ── Dialogs ──
    "dialog.no_file": {
        "en": "Please select an eBook file first.",
        "zh": "請先選擇一個電子書檔案。",
    },
    "dialog.unsupported": {
        "en": "Unsupported file format. Please use EPUB or PDF.",
        "zh": "不支援的檔案格式。請使用 EPUB 或 PDF。",
    },
    "dialog.error": {
        "en": "Error",
        "zh": "錯誤",
    },

    # ── YARA ──
    "yara.available": {
        "en": "YARA engine: Available",
        "zh": "YARA 引擎：可用",
    },
    "yara.unavailable": {
        "en": "YARA engine: Not installed (optional)",
        "zh": "YARA 引擎：未安裝（選用）",
    },
}


class I18n:
    """Language manager for dynamic UI text switching."""

    SUPPORTED_LANGUAGES = ["en", "zh"]

    def __init__(self, lang: str = "en"):
        self._lang = lang if lang in self.SUPPORTED_LANGUAGES else "en"
        self._listeners: List[Callable[[], None]] = []

    @property
    def lang(self) -> str:
        return self._lang

    @lang.setter
    def lang(self, value: str):
        if value in self.SUPPORTED_LANGUAGES and value != self._lang:
            self._lang = value
            self._notify()

    def t(self, key: str) -> str:
        """Translate a key to the current language."""
        entry = TRANSLATIONS.get(key)
        if entry is None:
            return key  # fallback: return the key itself
        return entry.get(self._lang, entry.get("en", key))

    def toggle(self):
        """Toggle between English and Chinese."""
        self.lang = "zh" if self._lang == "en" else "en"

    def on_change(self, callback: Callable[[], None]):
        """Register a callback to be invoked when the language changes."""
        self._listeners.append(callback)

    def _notify(self):
        for cb in self._listeners:
            cb()

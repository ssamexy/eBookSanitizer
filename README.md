# 🛡️ eBookSanitizer

**Scan & sanitize eBooks for malicious content.**

掃描並消毒電子書中的惡意內容。

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-green.svg)](https://python.org)

---

## ✨ Features | 功能特色

| Feature | 說明 |
|---------|------|
| 🔍 **Three-Layer Detection** | Structure audit + DOM analysis + PDF keyword engine |
| 🛡️ **Three Sanitization Modes** | Standard / Strict / Paranoid |
| 📄 **Format Preservation** | EPUB→EPUB, PDF→PDF (no lossy pixel conversion) |
| 🌐 **Bilingual GUI** | English / 繁體中文 interface |
| 🌗 **Dark & Light Themes** | Modern CustomTkinter UI |
| 🔌 **Optional YARA Support** | Extend with custom malware signature rules |
| 📦 **Zero Docker Dependency** | Pure Python — no containers required |

---

## 🏗️ Detection Architecture | 偵測架構

```
┌─────────────────────────────────────────────────────────┐
│  Layer 1: Structure Audit (EPUB)                        │
│  ├─ ZIP file list traversal (dangerous extensions)      │
│  ├─ ZipSlip directory traversal detection               │
│  └─ Non-standard file extension warnings                │
├─────────────────────────────────────────────────────────┤
│  Layer 2: Semantic DOM Analysis (EPUB)                  │
│  ├─ <script>, <iframe>, <embed>, <object> detection     │
│  ├─ on* event handler scanning                          │
│  ├─ javascript: / data: URI protocol detection          │
│  └─ External URL / tracking pixel scanning              │
├─────────────────────────────────────────────────────────┤
│  Layer 3: PDF Keyword Engine (PDF)                      │
│  ├─ Hex de-obfuscation (#XX decoding, from PDFiD)       │
│  ├─ /JavaScript /OpenAction /AA /Launch detection       │
│  ├─ Action /S sub-type analysis                         │
│  └─ /EmbeddedFiles /XFA /SubmitForm scanning            │
└─────────────────────────────────────────────────────────┘
```

## 🔒 Sanitization Modes | 消毒模式

| Mode | Description | 說明 |
|------|-------------|------|
| 🟢 **Standard** | Remove scripts, auto-actions, event handlers | 移除腳本、自動動作、事件處理器 |
| 🟡 **Strict** | + Neutralize external links, embedded files | + 中立化外部連結、嵌入檔案 |
| 🔴 **Paranoid** | + Rebuild structure with only safe content | + 重建結構，僅保留安全渲染內容 |

---

## 📦 Installation | 安裝

### Prerequisites | 前置需求

- Python 3.10 or higher
- pip (Python package manager)

### Steps | 步驟

```bash
# Clone the repository | 複製儲存庫
git clone https://github.com/YOUR_USERNAME/eBookSanitizer.git
cd eBookSanitizer

# Install dependencies | 安裝依賴
pip install -r requirements.txt

# Launch the GUI | 啟動圖形介面
python main.py
```

### Optional: YARA Support | 選用：YARA 支援

```bash
# Install yara-python for advanced malware signature detection
pip install yara-python
```

Place your `.yar` / `.yara` rule files in `sanitizer/yara_rules/` to enable signature-based scanning.

---

## 🖥️ Usage | 使用方式

1. **Launch** the application with `python main.py`
2. **Select** an EPUB or PDF file (click the file area)
3. **Choose** a sanitization mode (Standard / Strict / Paranoid)
4. **Click** "🔍 Scan Only" to detect threats, or "🛡️ Scan & Sanitize" to clean the file
5. **Review** the activity log for detailed results

啟動應用程式後，選擇電子書檔案，選擇消毒模式，然後點擊「掃描」或「掃描並消毒」。

---

## 🏛️ Project Structure | 專案結構

```
eBookSanitizer/
├── main.py                    # Entry point | 程式入口
├── sanitizer/
│   ├── base.py                # Core classes (Threat, Report, Mode)
│   ├── epub_sanitizer.py      # Layer 1 + 2: EPUB scanner & sanitizer
│   ├── pdf_sanitizer.py       # Layer 3: PDF scanner & sanitizer
│   └── yara_scanner.py        # Optional YARA integration
├── gui/
│   ├── app.py                 # Main GUI application
│   ├── i18n.py                # Bilingual translations
│   └── theme.py               # Color palette & typography
├── requirements.txt
├── LICENSE                    # MIT License
└── README.md
```

---

## 🤝 Contributing | 貢獻

Contributions are welcome! Please feel free to submit a Pull Request.

歡迎貢獻！請隨時提交 Pull Request。

1. Fork this repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📝 License | 授權

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

本專案採用 MIT 授權條款 — 詳見 [LICENSE](LICENSE) 檔案。

---

## 🙏 Acknowledgments | 致謝

This project's detection techniques are informed by:

- **[PDFiD](https://github.com/DidierStevens/DidierStevensSuite)** — Hex de-obfuscation and PDF keyword scanning methodology
- **[Dangerzone](https://github.com/freedomofpress/dangerzone)** — Zero-trust "paranoid mode" philosophy
- **[OWASP XSS Prevention](https://owasp.org)** — EPUB DOM sanitization rules
- **[QuickSand](https://github.com/tylabs/quicksand)** — YARA-based malware signature scanning concept

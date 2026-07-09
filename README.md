# 🛡️ eBookSanitizer

**Scan & sanitize eBooks for malicious and dynamic content.**

[繁體中文版](README_zh.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-green.svg)](https://python.org)

eBookSanitizer is a security utility that scans and sanitizes EPUB and PDF files to remove malicious code, embedded executables, dynamic scripts, and tracking resources. It features both a CLI and a GUI, and **preserves the original layout and searchable text of your eBooks**, avoiding lossy pixelization methods.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Three-Layer Detection** | Combined structure audit, XHTML DOM analysis, and PDF keyword scanning. |
| 🛡️ **Three Sanitization Modes** | Standard, Strict, and Paranoid modes to match your security needs. |
| 📁 **Native Drag & Drop** | Easily drag one or multiple files into the window to load them. |
| 📚 **Batch Processing Queue** | Import multiple files at once. The app will queue scan/sanitize tasks and output a summary. |
| 📄 **Format & Text Preservation** | EPUB→EPUB, PDF→PDF. Never rasterizes; layout and searchable text remain 100% intact. |
| 💻 **Dual CLI / GUI Modes** | Automatically runs GUI when launched without arguments; switches to CLI when commands are passed. |
| 🌐 **Bilingual Interface** | Switch between English and Traditional Chinese seamlessly. |
| 🔌 **Optional YARA Support** | Load custom YARA rules to detect known malware byte signatures in document streams. |

---

## 🏗️ Detection Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Layer 1: Structure Audit (EPUB)                        │
│  ├─ ZIP archive file list traversal (detects .exe, .bat)│
│  ├─ ZipSlip directory traversal defense (../ checking)  │
│  └─ Non-standard file extension warnings                │
├─────────────────────────────────────────────────────────┤
│  Layer 2: Semantic DOM Analysis (EPUB)                  │
│  ├─ Detects <script>, <iframe>, <embed>, <object> tags  │
│  ├─ Scans for inline event handlers (onload, onerror)   │
│  ├─ Identifies javascript: and data: URI pseudo-protocols│
│  └─ Finds tracking pixels and external resource URLs    │
├─────────────────────────────────────────────────────────┤
│  Layer 3: PDF Keyword Engine (PDF)                      │
│  ├─ Hex de-obfuscation (decodes /J#61vaScript -> /JS)   │
│  ├─ Counts /JS, /JavaScript, /OpenAction, /AA, /Launch  │
│  ├─ Action /S sub-type recursive analysis               │
│  └─ Detects embedded files, XFA forms, and submissions  │
└─────────────────────────────────────────────────────────┘
```

## 🔒 Sanitization Modes

| Mode | Description | Action Details |
|------|-------------|----------------|
| 🟢 **Standard** | Removes active code, preserves links | Strips `<script>`, inline events, `/JS`, and `/Launch`. Keeps hyperlinks and non-active attachments. |
| 🟡 **Strict** | Neutralizes external links & assets | Standard + replaces external links with `#`, strips `/EmbeddedFiles`, `/XFA`, and form submissions. |
| 🔴 **Paranoid** | Full structural rebuild | Strict + (EPUB) deletes all non-whitelisted files; (PDF) strips all non-whitelisted catalog/page attributes. |

---

## 📦 Installation

### Prerequisites
- Python 3.10 or higher
- pip (Python package manager)

### Steps
```bash
# Clone the repository
git clone https://github.com/ssamexy/eBookSanitizer.git
cd eBookSanitizer

# Install dependencies
pip install -r requirements.txt

# Launch the application
python main.py
```

### Optional: YARA Support
To enable YARA signature scanning:
```bash
pip install yara-python
```
Place your `.yar` / `.yara` rule files inside the `sanitizer/yara_rules/` folder. They will be compiled and loaded automatically on startup.

---

## 🖥️ Usage

### Running the App

#### 1. Graphical User Interface (GUI)
Simply run `python main.py` with no arguments.
- **Drag & Drop**: Drag one or multiple files into the window to load them.
- **Batch Processing**: Select multiple files in the file dialog. The log panel will show progress queue logs.
- **Dark/Light Theme**: Click the theme toggle at the top right to switch themes.

#### 2. Command Line Interface (CLI)
Pass arguments to automatically run in CLI mode.

##### 🔎 Scan Only (No modification)
```bash
# Scan a file and output a summary report
python main.py scan book.epub

# Scan with detailed step logs
python main.py scan book.pdf --verbose

# Output pure JSON data (verbose logs are redirected to stderr)
python main.py scan book.epub --json
```

##### 🛡️ Sanitize (Generates a clean copy)
The clean copy will be saved with a `_sanitized` suffix.
```bash
# Sanitize using standard mode
python main.py sanitize book.epub

# Sanitize in strict mode with a custom output path
python main.py sanitize book.pdf -o clean.pdf --mode strict
```

---

## 🏛️ Project Structure

```
eBookSanitizer/
├── main.py                    # Entry point (auto-dispatches GUI/CLI)
├── cli.py                     # CLI implementation and arguments parser
├── sanitizer/
│   ├── __init__.py
│   ├── base.py                # Core base classes & report structure
│   ├── epub_sanitizer.py      # Layer 1 & 2 EPUB engine
│   ├── pdf_sanitizer.py       # Layer 3 PDF engine
│   └── yara_scanner.py        # Optional YARA scanning integration
├── gui/
│   ├── __init__.py
│   ├── app.py                 # CustomTkinter interface & drag/drop hook
│   ├── i18n.py                # Bilingual translation dictionary
│   └── theme.py               # Theme colors and fonts configuration
├── test_sanitizer.py          # Complete test suite containing 65 tests
├── requirements.txt
├── LICENSE                    # MIT License
└── README.md
```

---

## 📝 License

This project is licensed under the [MIT License](LICENSE).

---

## 🙏 Credits

The logic and analysis techniques in this project are inspired by:

- **[PDFiD](https://github.com/DidierStevens/DidierStevensSuite)** — PDF name object hex decoding & scanning methodologies
- **[Dangerzone](https://github.com/freedomofpress/dangerzone)** — Zero-trust "paranoid mode" structural rebuild concept
- **[OWASP XSS Prevention](https://owasp.org)** — XHTML DOM XSS attributes filtering list
- **[QuickSand](https://github.com/tylabs/quicksand)** — Document decoding & YARA signature scan concepts

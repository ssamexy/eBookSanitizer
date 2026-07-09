# eBookSanitizer Test Reference Guide (TEST_NOTE.md)

This directory consolidates all test-related files, data, and scripts into a single, clean workspace location under `tests/`.

---

## 📁 Directory Structure

```
tests/
├── test_data/                    # Mock/Real eBooks for verification (Ignored by Git)
│   ├── The Five Principles of Parenting... .epub
│   ├── Thinking, Fast and Slow... .epub
│   └── Thinking, Fast and Slow... .pdf
├── test_sanitizer.py             # Baseline Functional and Unit Tests (65 tests)
├── test_adversarial.py           # Adversarial Testing Suite - Round 1 (81 tests)
├── test_adversarial_round2.py    # Adversarial Testing Suite - Round 2 (68 tests)
├── test_adversarial_round3.py    # Adversarial Testing Suite - Round 3 (46 tests)
└── TEST_NOTE.md                  # This documentation file
```

---

## 📊 Test Suite Coverage Summary

Across all suites, a total of **260 tests** are executed to validate both application logic and robust security parsing:

### 1. Base Framework & Report Validation
* **Scope**: Verifies `Threat`, `SanitizeReport`, and `SanitizeMode` models.
* **Checks**: Ensures JSON serialization logic, custom log callbacks, error messaging, and threat level reporting are fully functional.

### 2. EPUB Structure & DOM Evasion Attacks
* **Layer 1: Structural Audit**:
  * Blocks directory traversal (ZipSlip) inside archive entries (`../`, `..\\`, absolute paths, symlink-like nodes).
  * Validates detection of dangerous file extensions (`.exe`, `.bat`, `.ps1`, `.vbs`, `.hta`, etc.) and multi-extension tricks (`.xhtml.exe`).
  * Employs Unicode visual spoofing filters (e.g., U+2024 ONE DOT LEADER, full-width `.EXE`) to prevent extension-matching bypasses.
* **Layer 2: DOM-based XSS Evasion**:
  * Flagging malicious tags: `<script>`, `<iframe>`, `<embed>`, `<object>`, `<applet>`, `<form>` (using mixed-case variations like `<ScRiPt>`).
  * Neutralizing standard and lesser-known events: `onerror`, `onload`, `onclick`, `onfocus`, `onblur`, `onmouseover`, `onstart`, `ontoggle`.
  * Evasions: Null-byte injection, HTML entity encoding (`&#106;avascript:`), compact slash separators (`<img/src=x/onerror=...>`), tab characters inside protocols, namespace confusion (MathML `<math>`, SVG `<foreignObject>`).
  * Strict & Paranoid Sanitization: Blocks meta refresh redirection, strips external links, drops inline CSS `@import url()`, removes background-image tracking links, and filters external stylesheets.

### 3. XML & XXE Injection in EPUB
* **Scope**: Validates that parsing OPF (`content.opf`), container files (`container.xml`), or XHTML documents containing custom `DOCTYPE` declarations, external parameter entities, or DTD references does not cause parser crashes, Server-Side Request Forgery (SSRF), or local file system readout.

### 4. PDF Keyword De-obfuscation & Reconstruction
* **Keyword Decoding (Layer 3)**:
  * Reverses PDF Hex-obfuscated names (e.g., `/J#61vaScript` -> `/JavaScript`, mixed case, nested hexadecimal encodings).
  * Audits dangerous catalog keys: `/JS`, `/JavaScript`, `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFiles`, `/XFA`, `/SubmitForm`, `/ImportData`.
  * Examines Annotation actions, parsing sub-types like `/S` (supporting `/JavaScript`, `/Launch`, `/SubmitForm`, `/ImportData`, `/URI`, `/GoToR`, `/GoToE`, `/Rendition`).
* **Sanitization Rebuild**:
  * Standard/Strict: Removes target active keys and cleans interactive `/Names` trees.
  * Paranoid: Performs full in-place page rebuild keeping ONLY safe rendering keys (whitelist includes `/Contents`, `/Resources`, `/MediaBox`, etc.).

### 5. Performance, DoS, and ReDoS Resistance
* **Checks**: Verifies regex patterns (like `DANGEROUS_PROTOCOLS` and `ON_EVENT_RE`) do not crash or lock up under catastrophic backtracking attempts. Stress-tests scanning with 500+ tags, 200+ event handlers, 50+ internal EPUB sub-files, and multi-page PDFs under concurrent multi-threaded execution.

### 6. CLI & GUI Core Logic
* **Scope**: Command line subcommands (`scan`/`sanitize`/`gui`), JSON outputs, log routing to `stderr`, and GUI translation mechanisms (`I18n` locale switching, callbacks, layout assets).

---

## 🏃 How to Run the Tests

Execute the following commands from the project root directory:

```bash
# 1. Run baseline functional and unit tests
python tests/test_sanitizer.py

# 2. Run adversarial checks (Round 1)
python tests/test_adversarial.py

# 3. Run supplemental adversarial checks (Round 2)
python tests/test_adversarial_round2.py

# 4. Run supplemental adversarial checks (Round 3)
python tests/test_adversarial_round3.py
```

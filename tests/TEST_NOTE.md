# eBookSanitizer 測試說明文件 (TEST_NOTE.md)

本目錄將所有測試相關檔案（測試腳本、測試資料）統一整理至 `tests/` 資料夾，以維護專案根目錄的乾淨與清晰度。

---

## 📁 目錄結構

```
tests/
├── test_data/                    # 測試電子書資料夾
│   ├── The Five Principles of Parenting... .epub
│   ├── Thinking, Fast and Slow... .epub
│   └── Thinking, Fast and Slow... .pdf
├── test_sanitizer.py             # 基礎功能測試集 (共 65 項測試)
├── test_adversarial.py           # 第一輪進階對抗防禦測試 (共 81 項測試)
├── test_adversarial_round2.py    # 第二輪增補對抗防禦測試 (共 68 項測試)
└── TEST_NOTE.md                  # 本說明文件
```

---

## 📊 測試項目總覽

所有測試覆蓋了專案的各個核心模組，涵蓋 **功能性測試** 與 **安全性對抗測試**，總計 **214 項測試**：

### 1. 基礎模組與報告系統 (Base Module & Report)
* **測試項目**：驗證 `Threat`、`SanitizeReport`、`SanitizeMode` 的屬性、格式序列化與字典轉換。
* **涵蓋目標**：確保報告輸出正確、JSON 序列化相容性、錯誤日誌與回呼 (Callback) 機制穩定運作。

### 2. EPUB 掃描與消毒防禦 (EPUB Evasion & Spec)
* **結構審計 (Layer 1)**：
  * ZipSlip 目錄走訪漏洞防禦（支援 `../`、`..\\`、絕對路徑與符號連結模擬）。
  * 阻擋高危險副檔名（`.exe`、`.bat`、`.ps1`、`.vbs`、`.hta` 等）。
  * 偵測雙副檔名欺騙（`.xhtml.exe`）與非標準副檔名警告。
  * 偵測 Unicode 視覺欺騙繞過漏洞。
* **DOM 分析與過濾 (Layer 2)**：
  * HTML 危險標籤偵測：`<script>`、`<iframe>`、`<embed>`、`<object>`、`<applet>`、`<form>`（包括大小寫混合 `<ScRiPt>`）。
  * 行內事件監聽器過濾：`onerror`、`onclick`、`onload` 等 event handlers。
  * 偽協議與編碼繞過：`javascript:`（含前置空白、換行字元）、`vbscript:`、`data:text/html` 與 `data:application/*` 及其 base64 編碼格式。
  * SVG 專屬嵌入向量：`<script>` 在 SVG、`onload` 在 `<svg>`、`xlink:href="javascript:..."`。
  * 行內 CSS `@import url()`、外部 CSS 連結 `<link rel="stylesheet">`、行內背景圖與多重載入規則過濾。
  * 空白、實體編碼繞過、損毀/不完整標籤與非 UTF-8 編碼處理。
* **EPUB 規格合規性**：
  * 消毒後重建 ZIP 壓縮檔：確保第一個 Entry 為 `mimetype`、不壓縮且內容為 `application/epub+zip`。
  * 其他檔案均使用 `DEFLATED` 壓縮，路徑使用 `/` 確保跨平台相容性。

### 3. PDF 掃描與消毒防禦 (PDF Evasion & Reconstruction)
* **關鍵字偵測與還原 (Layer 3)**：
  * 十六進位混淆解碼（如 `/J#61vaScript` -> `/JavaScript`，支援大小寫及多重混淆）。
  * 偵測高危與中危特徵：`/JS`、`/JavaScript`、`/OpenAction`、`/AA`、`/Launch`、`/EmbeddedFiles`、`/XFA`、`/SubmitForm`、`/ImportData`。
  * Annotation (註解) 層級掃描，Action 的 `/S` 子類型分析（包括 `/URI`、`/SubmitForm`、`/Launch`、`/ImportData`）。
* **結構重建與消毒**：
  * Page 字典重建：Paranoid 模式下僅保留白名單渲染鍵（`/Contents`、`/Resources`、`/MediaBox` 等），徹底清除所有未經授權的動作與附件。
  * Root 字典重建：過濾目錄樹中的 `/Names`、`/JavaScript` 與 `/EmbeddedFiles`。
  * 頁數一致性與 MediaBox 尺寸保真度驗證。

### 4. CLI 命令行與自動化 (CLI Functionality)
* **測試項目**：支援 `scan` 與 `sanitize` 子命令、`-o` 預設檔名、全模式參數（`standard`、`strict`、`paranoid`）。
* **涵蓋目標**：JSON 輸出驗證、將詳細日誌重導向至 `stderr` 以避免污染主管道、特殊路徑字元處理與無參數自動跳轉至 GUI。

### 5. GUI 邏輯單元 (GUI Core Unit Tests)
* **測試項目**：驗證調度器 `create_sanitizer()` 副檔名分流正確性、多語系 `I18n` 佔位符與監聽器穩定性、拖放路徑位元組解碼與主題樣式資源載入。

### 6. 效能與安全性邊界 (Performance & Security Bounds)
* **對抗性極限測試**：
  * 預防 Regex ReDoS（對 `DANGEROUS_PROTOCOLS` 及 `ON_EVENT_RE` 餵入超長重複字串與空白）。
  * 效能測試：500 個標籤檔案、200 個事件處理器、50 個 EPUB 內置子檔案消毒與 10 頁 PDF 的掃描速度控制。
  * Concurrency：多線程並行掃描執行時無數據競爭與變數污染。
  * 零位元組檔案、截斷/損毀 PDF、無 central directory 之 zip 檔的優雅容錯。
  * 臨時目錄垃圾回收與資源釋放（無 leaked temp files）。

### 7. YARA 模組整合 (YARA Scanner)
* **測試項目**：在無編譯 `yara-python` 下的優雅降級機制、空數據流/非正常目錄指派下的容錯與巨量二進位流掃描。

---

## 🏃 如何執行測試

可在專案根目錄下執行以下指令以執行各個測試集：

```bash
# 1. 執行基礎功能測試 (65 tests)
python tests/test_sanitizer.py

# 2. 執行第一輪對抗防禦測試 (81 tests)
python tests/test_adversarial.py

# 3. 執行第二輪對抗防禦測試 (68 tests)
python tests/test_adversarial_round2.py
```

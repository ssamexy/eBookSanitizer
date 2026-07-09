# 🛡️ eBookSanitizer

**掃描並消毒電子書中的惡意與動態內容。**

[English Version](README.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-green.svg)](https://python.org)

eBookSanitizer 是一款專為電子書安全設計的雙系統（CLI & GUI）消毒工具。它能有效偵測並清除 EPUB 與 PDF 檔案中的 JavaScript 惡意代碼、動態事件、隱蔽超連結及可疑的夾帶附件，同時**保留您電子書原有的排版格式與可搜尋文字**，不像 Dangerzone 那樣將內容強行轉為像素圖片。

---

## ✨ 功能特色

| 功能 | 說明 |
|------|------|
| 🔍 **三層式威脅偵測** | 整合結構審計、XSS DOM 語意分析與 PDF 十六進位反混淆關鍵字掃描。 |
| 🛡️ **三級式安全消毒** | 提供標準 (Standard)、嚴格 (Strict) 與偏執 (Paranoid) 三種消毒等級。 |
| 📁 **拖放上傳 (Drag & Drop)** | 支援 Windows 原生拖放，可直接拖入一個或多個電子書進行處理。 |
| 📚 **批次排隊處理 (Batch Mode)** | 支援多檔同時匯入與排隊處理，詳細記錄每本書的掃描消毒報告。 |
| 📄 **無損結構與排版** | EPUB→EPUB, PDF→PDF。絕不使用像素化，不破壞排版、不損毀可搜尋文字。 |
| 💻 **雙系統並行 (CLI & GUI)** | 無參數時自動啟動美觀的 GUI 介面；帶有指令參數時直接於終端機執行，支援純淨的 `--json` 數據流。 |
| 🌐 **中英雙語切換** | 介面隨點隨換，支援完整國際化。 |
| 🔌 **可選 YARA 整合** | 支援載入自定義 YARA 規則庫，掃描已知惡意軟體的位元組特徵碼。 |

---

## 🏗️ 三層偵測架構

```
┌─────────────────────────────────────────────────────────┐
│  Layer 1: 結構化審計 (EPUB)                              │
│  ├─ ZIP 壓縮檔清單遍歷，偵測夾帶的危險副檔名 (.exe, .bat)  │
│  ├─ ZipSlip 目錄遍歷攻擊檢測 (防禦 ../ 寫入)            │
│  └─ 非標準 EPUB 副檔名警告                             │
├─────────────────────────────────────────────────────────┤
│  Layer 2: XHTML DOM 語意分析 (EPUB)                     │
│  ├─ 偵測 <script>, <iframe>, <embed>, <object> 等危險標籤 │
│  ├─ 掃描 on* (onload, onerror) 內聯事件處理器            │
│  ├─ 偵測 javascript: 或 data: URI 等偽協議             │
│  └─ 偵測外部追蹤像素 (Tracking pixel) 與外連資源       │
├─────────────────────────────────────────────────────────┤
│  Layer 3: 關鍵字解碼引擎 (PDF)                          │
│  ├─ 十六進位反混淆解碼 (解密 /J#61vaScript -> /JavaScript) │
│  ├─ 統計 /JS, /JavaScript, /OpenAction, /AA, /Launch     │
│  ├─ Action /S 子類型深入分析                             │
│  └─ 偵測嵌入檔案 (/EmbeddedFiles)、XFA 表單與表單提交   │
└─────────────────────────────────────────────────────────┘
```

## 🔒 消毒模式

| 消毒等級 | 說明 | 處理細節 |
|----------|------|----------|
| 🟢 **標準 (Standard)** | 移除已知危險內容，保留外連 | 移除 `<script>`、`on*` 事件、`/JS`、`/Launch`，但保留書中的正常超連結與附件。 |
| 🟡 **嚴格 (Strict)** | 額外中立化外連與嵌入資源 | 標準 + 將所有外連替換為 `#`，移除 `/EmbeddedFiles`、`/XFA` 與表單提交，防止資料外洩與 IP 追蹤。 |
| 🔴 **偏執 (Paranoid)** | 重建結構，僅保留安全內容 | 嚴格 + (EPUB) 移除所有非白名單副檔名檔案；(PDF) 移除所有非白名單的頁面/根節點屬性，只留純粹的渲染物件。 |

---

## 📦 安裝

### 前置需求
- Python 3.10 或更高版本
- pip (Python 套件管理器)

### 步驟
```bash
# 複製儲存庫
git clone https://github.com/ssamexy/eBookSanitizer.git
cd eBookSanitizer

# 安裝依賴套件
pip install -r requirements.txt

# 啟動應用程式
python main.py
```

### 選用功能：YARA 支援
如果您需要掃描已知惡意軟體特徵：
```bash
pip install yara-python
```
您可以將您的 `.yar` / `.yara` 規則檔案放入 `sanitizer/yara_rules/` 目錄中，掃描器在啟動時會自動加載它們。

---

## 🖥️ 使用說明

### 雙系統執行方式

#### 1. 圖形使用者介面 (GUI)
直接執行 `python main.py`（或在無參數時啟動）。
- **拖放檔案**：將一或多個電子書拖入視窗內任何地方即可加載。
- **批次處理**：支持一次點選多個檔案，日誌視窗將顯示佇列處理進度。
- **雙語與主題**：右上角可自由切換「中文/English」與「深色/淺色主題」。

#### 2. 命令列介面 (CLI)
帶有子命令參數時自動切換至 CLI。

##### 🔎 僅掃描偵測 (不修改檔案)
```bash
# 掃描單一檔案，輸出標準報告
python main.py scan book.epub

# 輸出詳細偵測日誌
python main.py scan book.pdf --verbose

# 輸出為 JSON 數據流 (stdout 為純淨 JSON，verbose 日誌會自動導向 stderr)
python main.py scan book.epub --json
```

##### 🛡️ 檔案消毒 (產出安全副本)
消毒後檔案預設會於相同目錄下加上 `_sanitized` 後綴。
```bash
# 使用標準模式消毒
python main.py sanitize book.epub

# 使用嚴格模式消毒，並自定義輸出路徑
python main.py sanitize book.pdf -o clean.pdf --mode strict

# 批次消毒 (可以使用 shell 迴圈，或直接使用 GUI 的拖放批次處理)
```

---

## 🏛️ 專案結構

```
eBookSanitizer/
├── main.py                    # 程式主入口 (雙系統自動切換)
├── cli.py                     # CLI 子命令及參數控制
├── sanitizer/
│   ├── __init__.py
│   ├── base.py                # 報告、威脅結構與消毒基類
│   ├── epub_sanitizer.py      # Layer 1 + 2 EPUB 引擎
│   ├── pdf_sanitizer.py       # Layer 3 PDF 引擎
│   └── yara_scanner.py        # 可選的 YARA 掃描器
├── gui/
│   ├── __init__.py
│   ├── app.py                 # CustomTkinter 介面與拖放、批次控制
│   ├── i18n.py                # 翻譯字典
│   └── theme.py               # 設計配色主題
├── test_sanitizer.py          # 包含 65 個測試的完整測試套件
├── requirements.txt
├── LICENSE                    # MIT
└── README.md
```

---

## 📝 授權條款

本專案採用 [MIT License](LICENSE) 授權。

---

## 🙏 致謝

本專案的消毒與偵測邏輯借鏡了以下優秀開源專案的研究成果：

- **[PDFiD](https://github.com/DidierStevens/DidierStevensSuite)** — PDF 十六進位 Name Object 反混淆與統計思路
- **[Dangerzone](https://github.com/freedomofpress/dangerzone)** — 零信任安全性與「偏執模式」結構重建思路
- **[OWASP XSS Prevention](https://owasp.org)** — XHTML DOM XSS 惡意屬性過濾清單
- **[QuickSand](https://github.com/tylabs/quicksand)** — 文件解碼與 YARA 特徵碼掃描擴充思路

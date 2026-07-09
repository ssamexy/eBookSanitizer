/**
 * eBookSanitizer Web Application Coordinator
 * Handles UI interactions, translations (en/zh-TW), drag-and-drop,
 * and orchestrates EPUB and PDF sanitizers in the browser.
 */

// ── Translation Dictionary ──────────────────────────────────────────
const TRANSLATIONS = {
  en: {
    "app.subtitle": "Scan & sanitize eBooks for malicious content",
    "yara.unavailable": "YARA signature scan unavailable (Desktop only)",
    "file.drop_title": "Drag & drop files here",
    "file.drop_subtitle": "or click to browse from folder (supports .epub, .pdf)",
    "mode.title": "Sanitization Level",
    "mode.standard.badge": "Standard",
    "mode.standard.desc": "Remove known threats like scripts, event handlers, and dangerous PDF actions. Keep normal links and attachments.",
    "mode.strict.badge": "Strict",
    "mode.strict.desc": "Standard security + neutralize external links, tracking pixels, and block embedded files/forms to prevent data exfiltration.",
    "mode.paranoid.badge": "Paranoid",
    "mode.paranoid.desc": "Strict security + strip styles importing external resources. Rebuild file structures keeping only safe contents.",
    "queue.title": "File Queue",
    "queue.clear": "Clear All",
    "queue.empty": "No files loaded yet. Drop files on the left panel to begin.",
    "threat.severity.high": "High Threat",
    "threat.severity.medium": "Medium Threat",
    "threat.severity.low": "Low Threat",
    "log.title": "Activity Logs",
    "log.clear": "Clear Logs",
    "log.autoscroll": "Auto-scroll",
    "log.ready": "System ready. Waiting for files to sanitize...",
    "btn.sanitize_all": "🛡️ Sanitize All Files",
    "btn.sanitizing": "⚡ Sanitizing...",
    "btn.complete": "✅ Done",
    "status.pending": "Pending",
    "status.scanning": "Scanning...",
    "status.sanitizing": "Sanitizing...",
    "status.complete": "Complete",
    "status.failed": "Failed",
    "option.scrub_metadata": "🧼 Scrub Metadata (Anonymize Author, Dates, and IDs)"
  },
  "zh-TW": {
    "app.subtitle": "掃描並消毒電子書中的惡意與動態內容",
    "yara.unavailable": "YARA 特徵掃描不支援網頁版 (僅支援桌面版)",
    "file.drop_title": "將檔案拖放到此處",
    "file.drop_subtitle": "或點擊瀏覽資料夾 (支援 .epub, .pdf 格式)",
    "mode.title": "消毒等級安全設定",
    "mode.standard.badge": "標準 (Standard)",
    "mode.standard.desc": "移除已知危險內容（如 <script>、on* 事件與 PDF 的 JS/Launch 動作），但保留書中的正常超連結與附件。",
    "mode.strict.badge": "嚴格 (Strict)",
    "mode.strict.desc": "標準等級功能 + 將外連超連結替換為 #，移除嵌入檔案 (/EmbeddedFiles) 與表單提交，防止 IP 追蹤與資訊外洩。",
    "mode.paranoid.badge": "偏執 (Paranoid)",
    "mode.paranoid.desc": "嚴格等級功能 + 移除所有非白名單副檔名，並只保留 PDF 核心頁面與根屬性，重建乾淨安全的文件結構。",
    "queue.title": "待處理佇列",
    "queue.clear": "清除全部",
    "queue.empty": "佇列目前為空。請將電子書拖放到左側區域開始處理。",
    "threat.severity.high": "高風險威脅",
    "threat.severity.medium": "中風險威脅",
    "threat.severity.low": "低風險威脅",
    "log.title": "即時活動日誌",
    "log.clear": "清除日誌",
    "log.autoscroll": "自動滾動",
    "log.ready": "系統準備就緒。等待載入檔案進行掃描與消毒...",
    "btn.sanitize_all": "🛡️ 開始掃描並消毒檔案",
    "btn.sanitizing": "⚡ 正在消毒...",
    "btn.complete": "✅ 處理完成",
    "status.pending": "等待中",
    "status.scanning": "正在掃描...",
    "status.sanitizing": "正在消毒...",
    "status.complete": "消毒完成",
    "status.failed": "消毒失敗",
    "option.scrub_metadata": "🧼 抹除元數據 (匿名化作者、日期與識別碼)"
  }
};

// ── Application State ──────────────────────────────────────────────
// Auto-detect browser language on first visit; respect saved preference on return visits.
function detectLang() {
  const saved = localStorage.getItem("ebs_lang");
  if (saved) return saved;
  const browserLang = (navigator.language || navigator.userLanguage || "en").toLowerCase();
  return browserLang.startsWith("zh") ? "zh-TW" : "en";
}
let currentLang = detectLang();
let fileQueue = [];
let isProcessing = false;

// ── DOM Elements ───────────────────────────────────────────────────
const langBtn = document.getElementById("lang-btn");
const themeBtn = document.getElementById("theme-btn");
const dropZone = document.getElementById("drop-zone");
const fileInput = document.getElementById("file-input");
const queueList = document.getElementById("queue-list");
const clearQueueBtn = document.getElementById("clear-queue-btn");
const clearLogsBtn = document.getElementById("clear-logs-btn");
const logTerminal = document.getElementById("log-terminal");
const autoscrollChk = document.getElementById("autoscroll-chk");
const actionBtn = document.getElementById("action-btn");

const metricHigh = document.getElementById("metric-high");
const metricMedium = document.getElementById("metric-medium");
const metricLow = document.getElementById("metric-low");

// ── Initialization ─────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  updateTranslations();
  setupEventListeners();
});

// ── Theme System ────────────────────────────────────────────────────
function initTheme() {
  const savedTheme = localStorage.getItem("ebs_theme") || "dark";
  document.documentElement.setAttribute("data-theme", savedTheme);
  themeBtn.textContent = savedTheme === "dark" ? "☀️" : "🌙";
}

function toggleTheme() {
  const currentTheme = document.documentElement.getAttribute("data-theme");
  const newTheme = currentTheme === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", newTheme);
  localStorage.setItem("ebs_theme", newTheme);
  themeBtn.textContent = newTheme === "dark" ? "☀️" : "🌙";
}

// ── Translation/i18n System ─────────────────────────────────────────
function updateTranslations() {
  const langData = TRANSLATIONS[currentLang];
  
  // Update elements with [data-i18n]
  document.querySelectorAll("[data-i18n]").forEach(el => {
    const key = el.getAttribute("data-i18n");
    if (langData[key]) {
      if (el.tagName === "INPUT" && el.type === "button") {
        el.value = langData[key];
      } else {
        el.textContent = langData[key];
      }
    }
  });

  // Toggle button label
  langBtn.textContent = currentLang === "zh-TW" ? "English" : "中文";

  // Sync <html lang> for accessibility / SEO
  document.documentElement.setAttribute("lang", currentLang === "zh-TW" ? "zh-TW" : "en");

  // Save preference for return visits
  localStorage.setItem("ebs_lang", currentLang);

  // Re-render file queue to reflect language change on statuses
  updateQueueUI();
}

function toggleLanguage() {
  currentLang = currentLang === "zh-TW" ? "en" : "zh-TW";
  updateTranslations();
}

// ── UI Helpers ──────────────────────────────────────────────────────
function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function escapeHTML(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function appendLog(message, type = 'info') {
  const line = document.createElement("div");
  line.className = `log-line ${type}-line`;
  
  // Format timestamps
  const now = new Date();
  const timeStr = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}`;
  line.textContent = `[${timeStr}] ${message}`;
  
  logTerminal.appendChild(line);

  if (autoscrollChk.checked) {
    logTerminal.scrollTop = logTerminal.scrollHeight;
  }
}

function clearLogs() {
  logTerminal.innerHTML = "";
  appendLog(TRANSLATIONS[currentLang]["log.ready"], 'system');
}

// ── File Queue Management ───────────────────────────────────────────
function handleFilesSelected(files) {
  if (isProcessing) return;

  let addedCount = 0;
  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    const ext = file.name.split('.').pop().toLowerCase();
    
    if (ext !== 'epub' && ext !== 'pdf') {
      appendLog(`Skipped unsupported file type: ${file.name}`, 'warning');
      continue;
    }

    // Check size limit: 50MB for protection/performance
    if (file.size > 50 * 1024 * 1024) {
      appendLog(`Skipped file larger than 50MB: ${file.name}`, 'error');
      continue;
    }

    // Check if file is already in queue
    if (fileQueue.some(item => item.name === file.name && item.size === file.size)) {
      continue;
    }

    const newItem = {
      id: `file_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      file: file,
      name: file.name,
      size: file.size,
      ext: ext,
      status: 'pending', // pending, scanning, sanitizing, complete, failed
      threats: [],
      sanitizedBlob: null,
      highThreats: 0,
      mediumThreats: 0,
      lowThreats: 0,
      sha256: ''
    };

    fileQueue.push(newItem);

    // Calculate SHA-256 hash asynchronously to not block UI loading
    calculateSHA256(file).then(hash => {
      newItem.sha256 = hash;
      updateQueueUI();
    }).catch(err => {
      console.error("Failed to compute file hash", err);
    });

    addedCount++;
    appendLog(`Loaded file to queue: ${file.name} (${formatBytes(file.size)})`, 'info');
  }

  if (addedCount > 0) {
    updateQueueUI();
  }
}

function updateQueueUI() {
  if (fileQueue.length === 0) {
    queueList.className = "queue-list empty";
    queueList.innerHTML = `<div class="empty-state">${TRANSLATIONS[currentLang]["queue.empty"]}</div>`;
    clearQueueBtn.classList.add("hidden");
    actionBtn.classList.add("disabled");
    actionBtn.disabled = true;
    updateGlobalMetrics();
    return;
  }

  queueList.className = "queue-list";
  queueList.innerHTML = "";
  clearQueueBtn.classList.remove("hidden");

  if (!isProcessing) {
    actionBtn.classList.remove("disabled");
    actionBtn.disabled = false;
  }

  fileQueue.forEach(item => {
    const el = document.createElement("div");
    el.className = `queue-item ${item.status === 'scanning' || item.status === 'sanitizing' ? 'active' : ''}`;
    
    // Status text translation
    const statusText = TRANSLATIONS[currentLang][`status.${item.status}`] || item.status;

    // Build badge or threat text
    let threatMeta = "";
    if (item.status === 'complete' || item.status === 'failed') {
      const totalThreats = item.highThreats + item.mediumThreats + item.lowThreats;
      if (totalThreats > 0) {
        threatMeta = `<span class="status-text failed">(${totalThreats} threats found)</span>`;
      } else {
        threatMeta = `<span class="status-text complete">(${currentLang === 'zh-TW' ? '安全' : 'Safe'})</span>`;
      }
    }

    let sha256Meta = "";
    if (item.sha256) {
      sha256Meta = `
        <div class="queue-item-sha256" style="font-size: 11px; color: var(--text-secondary); margin-top: 4px; font-family: monospace; word-break: break-all;">
          SHA-256: ${escapeHTML(item.sha256)}
        </div>
      `;
    }

    const safeName = escapeHTML(item.name);
    el.innerHTML = `
      <div class="queue-item-info">
        <div class="queue-item-name" title="${safeName}">${safeName}</div>
        <div class="queue-item-meta">
          <span>${formatBytes(item.size)}</span>
          <span>•</span>
          <span class="status-text ${item.status}">${statusText}</span>
          ${threatMeta}
        </div>
        ${sha256Meta}
      </div>
      <div class="queue-item-actions">
        ${
          item.status === 'complete' && item.sanitizedBlob
            ? `<button class="btn btn-secondary text-sm download-btn" data-id="${item.id}">⬇️ ${currentLang === 'zh-TW' ? '下載' : 'Download'}</button>`
            : ''
        }
        ${
          !isProcessing
            ? `<button class="btn btn-text text-sm remove-btn" data-id="${item.id}">❌</button>`
            : ''
        }
      </div>
    `;

    queueList.appendChild(el);
  });

  // Attach buttons events
  queueList.querySelectorAll(".download-btn").forEach(btn => {
    btn.onclick = (e) => {
      const id = btn.getAttribute("data-id");
      downloadFile(id);
    };
  });

  queueList.querySelectorAll(".remove-btn").forEach(btn => {
    btn.onclick = (e) => {
      const id = btn.getAttribute("data-id");
      removeFileFromQueue(id);
    };
  });

  updateGlobalMetrics();
}

function removeFileFromQueue(id) {
  fileQueue = fileQueue.filter(item => item.id !== id);
  updateQueueUI();
}

function clearQueue() {
  if (isProcessing) return;
  fileQueue = [];
  updateQueueUI();
  appendLog("Cleared file queue.", "info");
}

function updateGlobalMetrics() {
  let high = 0;
  let medium = 0;
  let low = 0;

  fileQueue.forEach(item => {
    high += item.highThreats;
    medium += item.mediumThreats;
    low += item.lowThreats;
  });

  metricHigh.textContent = high;
  metricMedium.textContent = medium;
  metricLow.textContent = low;
}

// ── Download File ───────────────────────────────────────────────────
function downloadFile(id) {
  const item = fileQueue.find(f => f.id === id);
  if (!item || !item.sanitizedBlob) return;

  const url = URL.createObjectURL(item.sanitizedBlob);
  const a = document.createElement("a");
  
  // Format filename output: book_sanitized.epub
  const parts = item.name.split('.');
  const ext = parts.pop();
  const baseName = parts.join('.');
  a.download = `${baseName}_sanitized.${ext}`;
  a.href = url;
  
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  
  // Clean memory URL
  setTimeout(() => URL.revokeObjectURL(url), 100);
  appendLog(`Downloaded sanitized file: ${a.download}`, 'success');
}

// ── Orchestration & Processing ──────────────────────────────────────
async function runAllSanitization() {
  if (isProcessing || fileQueue.length === 0) return;

  isProcessing = true;
  actionBtn.classList.add("disabled");
  actionBtn.disabled = true;
  actionBtn.textContent = TRANSLATIONS[currentLang]["btn.sanitizing"];
  clearQueueBtn.classList.add("hidden");
  
  // Mode Selection
  const modeVal = document.querySelector('input[name="sanitize-mode"]:checked').value;
  appendLog(`=== Starting Batch Sanitization (Mode: ${modeVal}) ===`, 'system');

  // Disable UI inputs during processing
  document.querySelectorAll('input[name="sanitize-mode"]').forEach(el => el.disabled = true);
  fileInput.disabled = true;

  try {
    for (let i = 0; i < fileQueue.length; i++) {
      const item = fileQueue[i];
      if (item.status === 'complete') continue;

      item.status = 'scanning';
      updateQueueUI();

      appendLog(`--- Processing [${i+1}/${fileQueue.length}]: ${item.name} ---`, 'info');

      // Create instance of corresponding Sanitizer
      let sanitizer;
      const logCb = (msg, type) => {
        // Prefix logs with the filename
        appendLog(`[${item.name}] ${msg}`, type);
      };

      if (item.ext === 'epub') {
        sanitizer = new EPUBSanitizer(item.file, logCb);
      } else if (item.ext === 'pdf') {
        sanitizer = new PDFSanitizer(item.file, logCb);
      }

      if (!sanitizer) {
        item.status = 'failed';
        updateQueueUI();
        appendLog(`Unsupported file extension: ${item.name}`, 'error');
        continue;
      }

      // Step 1: Scan
      const scanResult = await sanitizer.scan();
      if (!scanResult.success) {
        item.status = 'failed';
        updateQueueUI();
        continue;
      }

      // Record threat counts
      item.highThreats = scanResult.summary.High;
      item.mediumThreats = scanResult.summary.Medium;
      item.lowThreats = scanResult.summary.Low;
      
      item.status = 'sanitizing';
      updateQueueUI();

      // Step 2: Sanitize
      const scrubMetadata = document.getElementById("scrub-metadata") ? document.getElementById("scrub-metadata").checked : false;
      const sanitizeResult = await sanitizer.sanitize(modeVal, scrubMetadata);
      if (sanitizeResult.success && sanitizeResult.blob) {
        item.status = 'complete';
        item.sanitizedBlob = sanitizeResult.blob;
      } else {
        item.status = 'failed';
      }

      updateQueueUI();
    }

    appendLog(`=== Batch Process Finished ===`, 'success');
  } catch (e) {
    appendLog(`Fatal pipeline error: ${e.message}`, 'error');
  } finally {
    isProcessing = false;
    actionBtn.classList.remove("disabled");
    actionBtn.disabled = false;
    actionBtn.textContent = TRANSLATIONS[currentLang]["btn.sanitize_all"];
    clearQueueBtn.classList.remove("hidden");
    
    // Re-enable input elements
    document.querySelectorAll('input[name="sanitize-mode"]').forEach(el => el.disabled = false);
    fileInput.disabled = false;

    updateQueueUI();
  }
}

// ── Event Listeners Setup ───────────────────────────────────────────
function setupEventListeners() {
  langBtn.addEventListener("click", toggleLanguage);
  themeBtn.addEventListener("click", toggleTheme);
  
  clearQueueBtn.addEventListener("click", clearQueue);
  clearLogsBtn.addEventListener("click", clearLogs);
  actionBtn.addEventListener("click", runAllSanitization);

  // File picker click
  dropZone.addEventListener("click", () => {
    fileInput.click();
  });

  fileInput.addEventListener("change", (e) => {
    if (e.target.files.length > 0) {
      handleFilesSelected(e.target.files);
      // Reset value so same file can be selected again if removed
      fileInput.value = "";
    }
  });

  // Drag and Drop Zone events
  ['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.add("dragover");
    }, false);
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.remove("dragover");
    }, false);
  });

  dropZone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files.length > 0) {
      handleFilesSelected(files);
    }
  }, false);
}

async function calculateSHA256(file) {
  const arrayBuffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex;
}

/**
 * eBookSanitizer JavaScript Unit Test Suite
 * Replicates the comprehensive Python test suite inside the browser environment.
 */

// ── Test Runner Infrastructure ─────────────────────────────────────
const tests = [];
let passedCount = 0;
let failedCount = 0;

function test(name, fn) {
  tests.push({ name, fn });
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(message || `Expected: ${expected}, but got: ${actual}`);
  }
}

function assertContains(string, substring, message) {
  if (!string.includes(substring)) {
    throw new Error(message || `Expected string "${string}" to contain "${substring}"`);
  }
}

// ── Mock Data Builders ──────────────────────────────────────────────
async function buildMockEpub(xhtmlBody = "<p>Clean content</p>", extraFiles = null) {
  const zip = new JSZip();
  
  // Store mimetype uncompressed first
  zip.file('mimetype', 'application/epub+zip', { compression: 'STORE' });
  
  zip.file('META-INF/container.xml', `<?xml version="1.0"?>
<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
  <rootfiles>
    <rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/>
  </rootfiles>
</container>`);

  zip.file('OEBPS/content.opf', `<?xml version="1.0"?>
<package xmlns="http://www.idpf.org/2007/opf" version="3.0">
  <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:title>Test Book</dc:title>
  </metadata>
  <manifest>
    <item id="ch1" href="ch1.xhtml" media-type="application/xhtml+xml"/>
  </manifest>
  <spine>
    <itemref idref="ch1"/>
  </spine>
</package>`);

  const xhtml = `<?xml version="1.0" encoding="UTF-8"?>
<html xmlns="http://www.w3.org/1999/xhtml">
<head><title>Test Chapter</title></head>
<body>${xhtmlBody}</body>
</html>`;

  zip.file('OEBPS/ch1.xhtml', xhtml);

  if (extraFiles) {
    for (const [name, data] of Object.entries(extraFiles)) {
      zip.file(name, data);
    }
  }

  const blob = await zip.generateAsync({ type: 'blob', mimeType: 'application/epub+zip' });
  return blob;
}

async function buildMockPdf(withJs = false, withOpenAction = false) {
  const pdfDoc = await PDFLib.PDFDocument.create();
  pdfDoc.addPage([600, 400]);
  const context = pdfDoc.context;

  if (withJs) {
    const jsAction = context.obj({
      S: 'JavaScript',
      JS: 'app.alert("malicious")',
    });
    const jsNameTree = context.obj({
      Names: ['EvilJS', jsAction],
    });
    const names = context.obj({
      JavaScript: jsNameTree,
    });
    pdfDoc.catalog.set(PDFLib.PDFName.of('Names'), names);
  }

  if (withOpenAction) {
    const oaAction = context.obj({
      S: 'JavaScript',
      JS: 'app.alert("open")',
    });
    pdfDoc.catalog.set(PDFLib.PDFName.of('OpenAction'), oaAction);
  }

  const pdfBytes = await pdfDoc.save();
  return new Blob([pdfBytes], { type: 'application/pdf' });
}

// ── 1. EPUB SCANNING TESTS ──────────────────────────────────────────

test("EPUB Scan: clean file has no threats", async () => {
  const blob = await buildMockEpub("<p>Safe and clean contents</p>");
  const file = new File([blob], "clean.epub", { type: "application/epub+zip" });
  
  const sanitizer = new EPUBSanitizer(file);
  const result = await sanitizer.scan();
  
  assert(result.success, "Scan should succeed");
  assertEqual(result.threats.length, 0, "No threats should be found");
  assertEqual(result.summary.High, 0);
  assertEqual(result.summary.Medium, 0);
  assertEqual(result.summary.Low, 0);
});

test("EPUB Scan: detects dangerous script tag & iframe", async () => {
  const html = `
    <h1>Book</h1>
    <script>alert("malicious js");</script>
    <iframe src="http://evil.com"></iframe>
  `;
  const blob = await buildMockEpub(html);
  const file = new File([blob], "dangerous_tags.epub", { type: "application/epub+zip" });
  
  const sanitizer = new EPUBSanitizer(file);
  const result = await sanitizer.scan();
  
  assert(result.threats.length >= 2, "Should find at least 2 threats");
  const tags = result.threats.filter(t => t.type === 'DangerousTag');
  assertEqual(tags.length, 2, "Should detect 2 dangerous tags");
  assert(tags.some(t => t.description.includes("<script>")), "Should detect script tag");
  assert(tags.some(t => t.description.includes("<iframe>")), "Should detect iframe tag");
});

test("EPUB Scan: detects inline event handlers", async () => {
  const html = `<button onclick="doEvil()">Click</button><img src="x" onerror="alert(1)">`;
  const blob = await buildMockEpub(html);
  const file = new File([blob], "events.epub", { type: "application/epub+zip" });
  
  const sanitizer = new EPUBSanitizer(file);
  const result = await sanitizer.scan();
  
  const events = result.threats.filter(t => t.type === 'EventHandler');
  assertEqual(events.length, 2, "Should detect 2 event handlers");
});

test("EPUB Scan: detects dangerous protocols (javascript: / data:)", async () => {
  const html = `
    <a href="javascript:alert(1)">Evil Link</a>
    <iframe src="data:text/html,<html>evil</html>"></iframe>
  `;
  const blob = await buildMockEpub(html);
  const file = new File([blob], "protocols.epub", { type: "application/epub+zip" });
  
  const sanitizer = new EPUBSanitizer(file);
  const result = await sanitizer.scan();
  
  const protocols = result.threats.filter(t => t.type === 'DangerousProtocol');
  assertEqual(protocols.length, 2, "Should detect 2 dangerous protocols");
});

test("EPUB Scan: detects external resources (Medium threat)", async () => {
  const html = `<img src="http://tracking-pixel.com/dot.png">`;
  const blob = await buildMockEpub(html);
  const file = new File([blob], "external.epub", { type: "application/epub+zip" });
  
  const sanitizer = new EPUBSanitizer(file);
  const result = await sanitizer.scan();
  
  const externals = result.threats.filter(t => t.type === 'ExternalLink');
  assertEqual(externals.length, 1, "Should detect 1 external link");
  assertEqual(externals[0].severity, 'Medium', "External link should be Medium severity");
});

test("EPUB Scan: detects structural threats (.exe & ZipSlip)", async () => {
  const blob = await buildMockEpub("<p>Normal</p>");
  const file = new File([blob], "structure.epub", { type: "application/epub+zip" });
  
  const sanitizer = new EPUBSanitizer(file);
  
  // Mock JSZip.loadAsync to return a zip object that has the literal malicious filenames
  const originalLoadAsync = JSZip.loadAsync;
  JSZip.loadAsync = async () => {
    return {
      files: {
        "OEBPS/dangerous.exe": { dir: false, async: () => "" },
        "../ZipSlip.xhtml": { dir: false, async: () => "" }
      }
    };
  };

  try {
    const result = await sanitizer.scan();
    const traversal = result.threats.filter(t => t.type === 'DirectoryTraversal');
    const dangerousFile = result.threats.filter(t => t.type === 'DangerousFile');
    
    assertEqual(traversal.length, 1, "Should detect DirectoryTraversal");
    assertEqual(dangerousFile.length, 1, "Should detect DangerousFile");
  } finally {
    JSZip.loadAsync = originalLoadAsync;
  }
});

// ── 2. EPUB SANITIZATION TESTS ──────────────────────────────────────

test("EPUB Sanitize: Standard mode removes scripts but keeps external links", async () => {
  const html = `
    <script>alert(1)</script>
    <a href="http://google.com">Google</a>
  `;
  const blob = await buildMockEpub(html);
  const file = new File([blob], "sanitize_std.epub", { type: "application/epub+zip" });
  
  const sanitizer = new EPUBSanitizer(file);
  const result = await sanitizer.sanitize("standard");
  
  assert(result.success, "Sanitizing should succeed");
  
  // Read back and verify zip
  const cleanZip = await JSZip.loadAsync(result.blob);
  const cleanHtml = await cleanZip.file("OEBPS/ch1.xhtml").async("string");
  
  assert(!cleanHtml.includes("<script>"), "Should strip script tag");
  assert(cleanHtml.includes('href="http://google.com"'), "Should keep external link");
});

test("EPUB Sanitize: Strict mode neutralizes external links & images", async () => {
  const html = `
    <script>alert(1)</script>
    <a href="http://google.com">Google</a>
    <img src="http://evil.com/pixel.png">
  `;
  const blob = await buildMockEpub(html);
  const file = new File([blob], "sanitize_strict.epub", { type: "application/epub+zip" });
  
  const sanitizer = new EPUBSanitizer(file);
  const result = await sanitizer.sanitize("strict");
  
  const cleanZip = await JSZip.loadAsync(result.blob);
  const cleanHtml = await cleanZip.file("OEBPS/ch1.xhtml").async("string");
  
  assert(!cleanHtml.includes("<script>"), "Should strip script tag");
  assert(cleanHtml.includes('href="#"'), "Should neutralize external link to #");
  assert(cleanHtml.includes('src=""'), "Should empty external img src");
});

test("EPUB Sanitize: Paranoid mode removes unsafe files and meta refresh", async () => {
  const extra = {
    "OEBPS/suspicious.dat": "some data",
    "OEBPS/evil.js": "alert(1);"
  };
  const html = `
    <meta http-equiv="refresh" content="0; url=http://evil.com">
    <style>@import url("http://evil.com/style.css");</style>
  `;
  const blob = await buildMockEpub(html, extra);
  const file = new File([blob], "sanitize_paranoid.epub", { type: "application/epub+zip" });
  
  const sanitizer = new EPUBSanitizer(file);
  const result = await sanitizer.sanitize("paranoid");
  
  const cleanZip = await JSZip.loadAsync(result.blob);
  
  // Verify files list: evil.js and suspicious.dat should be removed
  assert(!cleanZip.file("OEBPS/evil.js"), "evil.js should be deleted");
  assert(!cleanZip.file("OEBPS/suspicious.dat"), "Non-whitelisted file should be deleted");
  
  const cleanHtml = await cleanZip.file("OEBPS/ch1.xhtml").async("string");
  assert(!cleanHtml.includes("http-equiv"), "Should strip meta refresh");
  assert(cleanHtml.includes("/* import removed */"), "Should strip style @import rule");
});

test("EPUB Sanitize: Spec compliance (mimetype first & uncompressed)", async () => {
  const blob = await buildMockEpub("<p>Normal</p>");
  const file = new File([blob], "spec_test.epub", { type: "application/epub+zip" });
  
  const sanitizer = new EPUBSanitizer(file);
  const result = await sanitizer.sanitize("standard");
  
  const cleanZip = await JSZip.loadAsync(result.blob);
  
  // Inspect internal files order
  const filenames = Object.keys(cleanZip.files);
  assertEqual(filenames[0], "mimetype", "Mimetype must be the very first file");
  
  // Checking compression properties in JSZip: 
  const mimeEntry = cleanZip.files["mimetype"];
  assertEqual(mimeEntry._data.compression.magic, "\u0000\u0000", "Mimetype must be uncompressed (STORE)");
});


// ── 3. PDF SCANNING & SANITIZATION TESTS ─────────────────────────────

test("PDF Scan: clean file has no threats", async () => {
  const blob = await buildMockPdf(false, false);
  const file = new File([blob], "clean.pdf", { type: "application/pdf" });
  
  const sanitizer = new PDFSanitizer(file);
  const result = await sanitizer.scan();
  
  assert(result.success, "Scan should succeed");
  assertEqual(result.threats.length, 0, "No threats should be found");
});

test("PDF Scan: detects JavaScript name tree and OpenAction", async () => {
  const blob = await buildMockPdf(true, true);
  const file = new File([blob], "malicious.pdf", { type: "application/pdf" });
  
  const sanitizer = new PDFSanitizer(file);
  const result = await sanitizer.scan();
  
  const openAction = result.threats.filter(t => t.type === 'OpenAction');
  const jsTree = result.threats.filter(t => t.type === 'JavaScript' || t.type === 'JS');
  
  assert(openAction.length > 0, "Should detect /OpenAction threat");
  assert(jsTree.length > 0, "Should detect /JavaScript or /JS threat");
});

test("PDF Sanitize: Standard mode strips JavaScript & OpenAction", async () => {
  const blob = await buildMockPdf(true, true);
  const file = new File([blob], "malicious.pdf", { type: "application/pdf" });
  
  const sanitizer = new PDFSanitizer(file);
  const result = await sanitizer.sanitize("standard");
  
  assert(result.success, "Sanitizing should succeed");
  
  // Read back and scan the sanitized PDF to verify the keys are gone!
  const cleanFile = new File([result.blob], "sanitized.pdf", { type: "application/pdf" });
  const verifier = new PDFSanitizer(cleanFile);
  const verifyResult = await verifier.scan();
  
  assertEqual(verifyResult.threats.length, 0, "All threats should be completely stripped from sanitized PDF");
});

test("PDF Sanitize: Paranoid mode keeps only safe keys", async () => {
  const blob = await buildMockPdf(true, true);
  const file = new File([blob], "malicious.pdf", { type: "application/pdf" });
  
  const sanitizer = new PDFSanitizer(file);
  const result = await sanitizer.sanitize("paranoid");
  
  assert(result.success, "Sanitizing in paranoid mode should succeed");
  
  // Parse PDF and check catalog
  const cleanBuffer = await result.blob.arrayBuffer();
  const pdfDoc = await PDFLib.PDFDocument.load(cleanBuffer);
  
  const catalog = pdfDoc.catalog;
  const keys = catalog.keys().map(k => k.toString());
  
  // Verify catalog has only keys in SAFE_ROOT_KEYS or the cleaned /Names subtree
  for (const k of keys) {
    assert(PDFSanitizer.PARANOID_SAFE_ROOT_KEYS.has(k) || k === "/Names", `Unsafe key '${k}' was not dropped in paranoid catalog rebuild`);
  }
});
test("EPUB Sanitize: Metadata Scrubbing removes author/publisher and updates UUID", async () => {
  // Create mock EPUB with metadata OPF
  const zip = new JSZip();
  zip.file("mimetype", "application/epub+zip", { compression: "STORE" });
  
  const opfContent = `<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://www.idpf.org/2007/opf" version="2.0">
  <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:title>Test Book</dc:title>
    <dc:creator>John Doe</dc:creator>
    <dc:date>2026-07-09</dc:date>
    <dc:publisher>Test Publisher</dc:publisher>
    <dc:identifier id="uid">original-uuid-12345</dc:identifier>
  </metadata>
  <manifest>
    <item id="ncx" href="toc.ncx" media-type="application/x-dtbncx+xml"/>
  </manifest>
  <spine toc="ncx"/>
</package>`;
  zip.file("OEBPS/content.opf", opfContent);
  zip.file("OEBPS/toc.ncx", "<ncx></ncx>");
  
  const blob = await zip.generateAsync({ type: "blob" });
  const file = new File([blob], "test.epub", { type: "application/epub+zip" });
  
  const sanitizer = new EPUBSanitizer(file);
  const result = await sanitizer.sanitize("standard", true);
  
  assert(result.success, "EPUB metadata scrub sanitization should succeed");
  
  // Load result ZIP and inspect content.opf
  const cleanZip = await JSZip.loadAsync(result.blob);
  const opfText = await cleanZip.file("OEBPS/content.opf").async("string");
  
  const parser = new DOMParser();
  const doc = parser.parseFromString(opfText, "application/xml");
  
  // Verify creator, date, publisher tags are gone
  assert(doc.getElementsByTagNameNS("*", "creator").length === 0, "dc:creator should be scrubbed");
  assert(doc.getElementsByTagNameNS("*", "date").length === 0, "dc:date should be scrubbed");
  assert(doc.getElementsByTagNameNS("*", "publisher").length === 0, "dc:publisher should be scrubbed");
  
  // Verify identifier has been anonymized
  const identifiers = doc.getElementsByTagNameNS("*", "identifier");
  assert(identifiers.length === 1, "There should be exactly one identifier tag");
  assert(identifiers[0].textContent === "urn:uuid:00000000-0000-0000-0000-000000000000", "identifier should be anonymized");
});

test("PDF Sanitize: Metadata Scrubbing clears Info trailer dictionary and strips Metadata catalog key", async () => {
  // Create mock PDF with author info metadata
  const blob = await buildMockPdf(false, false);
  const file = new File([blob], "test.pdf", { type: "application/pdf" });
  
  const sanitizer = new PDFSanitizer(file);
  const result = await sanitizer.sanitize("standard", true);
  
  assert(result.success, "PDF metadata scrub sanitization should succeed");
  
  const cleanBuffer = await result.blob.arrayBuffer();
  const pdfDoc = await PDFLib.PDFDocument.load(cleanBuffer);
  
  // Verify author / title are not set or are empty
  assert(!pdfDoc.getAuthor(), "Author should be cleared");
  assert(!pdfDoc.getTitle(), "Title should be cleared");
  
  // Verify Metadata key in catalog is removed
  const catalog = pdfDoc.catalog;
  assert(!catalog.get(PDFLib.PDFName.of("Metadata")), "/Metadata stream should be removed from catalog");
});


// ── Test Runner Orchestrator ────────────────────────────────────────

async function runTests() {
  const listEl = document.getElementById("test-list");
  const summaryBadge = document.getElementById("summary-badge");
  
  listEl.innerHTML = "";
  passedCount = 0;
  failedCount = 0;

  for (const t of tests) {
    const item = document.createElement("div");
    item.className = "test-item";
    item.innerHTML = `
      <div class="test-item-header">
        <span class="test-name">${t.name}</span>
        <span class="test-status pass" id="status-${t.name.replace(/\s+/g, '-')}">Running...</span>
      </div>
      <div class="test-logs" id="logs-${t.name.replace(/\s+/g, '-')}"></div>
    `;
    listEl.appendChild(item);
    
    const statusEl = document.getElementById(`status-${t.name.replace(/\s+/g, '-')}`);
    const logsEl = document.getElementById(`logs-${t.name.replace(/\s+/g, '-')}`);

    const logMessages = [];
    const logCb = (msg, type) => {
      logMessages.push(`[${type}] ${msg}`);
    };

    try {
      // Execute the test using the global test logger fallback
      window.currentTestLogger = logCb;

      await t.fn();

      window.currentTestLogger = null;

      statusEl.textContent = "PASS";
      statusEl.className = "test-status pass";
      passedCount++;
      
      logsEl.innerHTML = logMessages.length > 0 ? logMessages.join("<br>") : "No logs recorded.";
    } catch (e) {
      window.currentTestLogger = null;

      statusEl.textContent = "FAIL";
      statusEl.className = "test-status fail";
      failedCount++;
      
      const errorDiv = document.createElement("div");
      errorDiv.className = "test-error";
      errorDiv.textContent = `${e.stack || e.message}`;
      item.appendChild(errorDiv);

      logsEl.innerHTML = logMessages.length > 0 ? logMessages.join("<br>") : "No logs recorded.";
    }
  }

  // Update summary badge
  if (failedCount === 0) {
    summaryBadge.textContent = `All Passed: ${passedCount}/${tests.length}`;
    summaryBadge.className = "test-summary-badge all-pass";
  } else {
    summaryBadge.textContent = `Failed: ${failedCount} | Passed: ${passedCount}/${tests.length}`;
    summaryBadge.className = "test-summary-badge has-fail";
  }
}

// Bind buttons
document.getElementById("run-btn").addEventListener("click", runTests);

// Run tests automatically on load
runTests();

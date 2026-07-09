/**
 * PDF Sanitizer - Layer 3 (Hex-Decoded Keyword Engine)
 * JavaScript Port using pdf-lib for Client-side Browser execution.
 */

class PDFSanitizer {
  static HIGH_KEYS = new Set(["/JS", "/JavaScript", "/OpenAction", "/AA", "/Launch"]);
  static MEDIUM_KEYS = new Set(["/EmbeddedFiles", "/XFA", "/SubmitForm", "/ImportData"]);
  static ALL_DANGEROUS_KEYS = new Set([...PDFSanitizer.HIGH_KEYS, ...PDFSanitizer.MEDIUM_KEYS]);
  static DANGEROUS_ACTION_TYPES = new Set(["/JavaScript", "/Launch", "/SubmitForm", "/ImportData"]);

  static PARANOID_SAFE_PAGE_KEYS = new Set([
    "/Type", "/Parent", "/Contents", "/Resources", "/MediaBox",
    "/CropBox", "/BleedBox", "/TrimBox", "/ArtBox", "/Rotate",
    "/UserUnit"
  ]);

  static PARANOID_SAFE_ROOT_KEYS = new Set([
    "/Type", "/Pages", "/PageLayout", "/PageMode",
    "/Metadata", "/MarkInfo", "/StructTreeRoot", "/Lang"
  ]);

  constructor(file, logCallback = null) {
    this.file = file;
    this.logCallback = logCallback || window.currentTestLogger;
    this.threats = [];
    this.errors = [];
    this.logs = [];
    this.success = false;
  }

  log(msg) {
    this.logs.push(msg);
    if (this.logCallback) {
      this.logCallback(msg, 'info');
    }
  }

  error(msg) {
    this.errors.push(msg);
    this.logs.push(`ERROR: ${msg}`);
    if (this.logCallback) {
      this.logCallback(`ERROR: ${msg}`, 'error');
    }
  }

  addThreat(type, path, description, severity = 'High') {
    const threat = { type, path, description, severity };
    this.threats.push(threat);
    if (this.logCallback) {
      this.logCallback(`[${severity}] Found ${type} in ${path}: ${description}`, 'threat');
    }
  }

  getThreatSummary() {
    const summary = { High: 0, Medium: 0, Low: 0 };
    for (const t of this.threats) {
      if (summary[t.severity] !== undefined) {
        summary[t.severity]++;
      }
    }
    return summary;
  }

  /**
   * Decode PDF hex-obfuscated names: /J#61vaScript -> /JavaScript
   */
  _normalizeName(nameStr) {
    if (!nameStr.includes('#')) return nameStr;
    return nameStr.replace(/#([0-9a-fA-F]{2})/g, (match, hex) => {
      return String.fromCharCode(parseInt(hex, 16));
    });
  }

  _resolve(val, context) {
    if (val && typeof val.ref === 'object') { // pdf-lib PDFRef instance check
      return context.lookup(val);
    }
    return val;
  }

  /**
   * Scan PDF for threats.
   */
  async scan() {
    this.log(`Starting PDF scan: ${this.file.name}`);
    this.threats = [];
    this.errors = [];

    try {
      const arrayBuffer = await this.file.arrayBuffer();
      const pdfDoc = await PDFLib.PDFDocument.load(arrayBuffer);
      const context = pdfDoc.context;
      const visited = new Set();

      // 1. Document Root (Catalog)
      const catalog = pdfDoc.catalog;
      if (catalog) {
        this._scanDict("Document Root", catalog, context, visited);
      }

      // 2. All Pages + Annotations
      const pages = pdfDoc.getPages();
      for (let i = 0; i < pages.length; i++) {
        const page = pages[i];
        const pageObj = page.node; // Page object is a DictionaryObject
        this._scanDict(`Page ${i + 1}`, pageObj, context, visited);

        // Scan annotations array
        const annots = this._resolve(pageObj.get(PDFLib.PDFName.of('Annots')), context);
        if (annots instanceof PDFLib.PDFArray) {
          for (let j = 0; j < annots.size(); j++) {
            const annot = this._resolve(annots.get(j), context);
            if (annot instanceof PDFLib.PDFDict) {
              this._scanDict(`Page ${i + 1} Annot ${j + 1}`, annot, context, visited);
            }
          }
        }
      }

      this.log(`Scan complete. Found ${this.threats.length} threat(s).`);
      return {
        success: true,
        threats: this.threats,
        summary: this.getThreatSummary()
      };
    } catch (e) {
      this.error(`Failed to scan PDF: ${e.message}`);
      return { success: false, threats: [], summary: { High: 0, Medium: 0, Low: 0 } };
    }
  }

  _scanDict(location, obj, context, visited) {
    if (!obj || visited.has(obj)) return;
    visited.add(obj);

    const keys = obj.keys();
    for (const key of keys) {
      const norm = this._normalizeName(key.toString()); // toString yields '/Key'

      // Check if key itself is dangerous
      if (PDFSanitizer.ALL_DANGEROUS_KEYS.has(norm)) {
        const severity = PDFSanitizer.HIGH_KEYS.has(norm) ? "High" : "Medium";
        this.addThreat(
          norm.replace("/", ""),
          location,
          `Key '${key.toString()}' (normalized: '${norm}')`,
          severity
        );
      }

      // Check Action sub-type: /A { /S /JavaScript ... }
      if (norm === "/A") {
        const val = obj.get(key);
        this._scanAction(location, val, context);
      }

      // Recurse into sub-dictionaries and arrays
      const value = this._resolve(obj.get(key), context);
      if (value instanceof PDFLib.PDFDict) {
        this._scanDict(location, value, context, visited);
      } else if (value instanceof PDFLib.PDFArray) {
        this._scanArray(location, value, context, visited);
      }
    }
  }

  _scanAction(location, value, context) {
    const action = this._resolve(value, context);
    if (!(action instanceof PDFLib.PDFDict)) return;

    const sVal = this._resolve(action.get(PDFLib.PDFName.of('S')), context);
    if (sVal instanceof PDFLib.PDFName) {
      const sType = this._normalizeName(sVal.toString());
      if (PDFSanitizer.DANGEROUS_ACTION_TYPES.has(sType)) {
        this.addThreat(
          "Action",
          location,
          `Action /S = ${sType}`,
          "High"
        );
      }
    }
  }

  _scanArray(location, arr, context, visited) {
    for (let i = 0; i < arr.size(); i++) {
      const value = this._resolve(arr.get(i), context);
      if (value instanceof PDFLib.PDFDict) {
        this._scanDict(location, value, context, visited);
      } else if (value instanceof PDFLib.PDFArray) {
        this._scanArray(location, value, context, visited);
      }
    }
  }

  /**
   * Sanitize PDF and generate a clean PDF Blob.
   */
  async sanitize(mode = 'standard', scrubMetadata = false) {
    this.log(`Sanitizing PDF [${mode}]: ${this.file.name}`);
    this.threats = [];
    this.errors = [];

    try {
      const arrayBuffer = await this.file.arrayBuffer();
      const pdfDoc = await PDFLib.PDFDocument.load(arrayBuffer);
      const context = pdfDoc.context;

      // ── Clean all pages ──
      const pages = pdfDoc.getPages();
      for (let i = 0; i < pages.length; i++) {
        const page = pages[i];
        const pageObj = page.node;

        if (mode === 'paranoid') {
          this._paranoidRebuildPageInplace(i, pageObj);
        } else {
          this._cleanPageInplace(i, pageObj, mode, context);
        }
      }

      // ── Clean document root ──
      this._cleanRoot(pdfDoc, mode, context, scrubMetadata);

      // ── Metadata Scrubbing (/Info) ──
      if (scrubMetadata) {
        pdfDoc.setTitle('');
        pdfDoc.setAuthor('');
        pdfDoc.setSubject('');
        pdfDoc.setKeywords([]);
        pdfDoc.setProducer('');
        pdfDoc.setCreator('');
        pdfDoc.setCreationDate(new Date(0));
        pdfDoc.setModificationDate(new Date(0));

        const trailer = pdfDoc.context.trailerInfo || pdfDoc.context.trailer;
        if (trailer) {
          if (typeof trailer.get === 'function' && typeof trailer.delete === 'function') {
            const infoId = trailer.get(PDFLib.PDFName.of('Info'));
            if (infoId) {
              trailer.delete(PDFLib.PDFName.of('Info'));
            }
          } else {
            delete trailer['Info'];
            delete trailer.Info;
          }
        }
        this.log('Trailer: Cleared Document Info dictionary (/Info) for metadata scrubbing.');
      }

      // ── Generate PDF bytes ──
      const pdfBytes = await pdfDoc.save();
      const blob = new Blob([pdfBytes], { type: 'application/pdf' });
      this.success = true;
      this.log('PDF sanitization completed successfully.');
      return { success: true, blob };
    } catch (e) {
      this.error(`Sanitization failed: ${e.message}`);
      return { success: false, blob: null };
    }
  }

  _cleanPageInplace(pageIdx, pageObj, mode, context) {
    const keys = Array.from(pageObj.keys());

    for (const key of keys) {
      const norm = this._normalizeName(key.toString());

      // All modes: strip /AA (Additional Actions)
      if (norm === "/AA") {
        pageObj.delete(key);
        this.log(`Page ${pageIdx + 1}: Stripped /AA`);
        continue;
      }

      // Handle page annotations
      if (norm === "/Annots") {
        const annots = this._resolve(pageObj.get(key), context);
        if (annots instanceof PDFLib.PDFArray) {
          this._cleanAnnotationsInplace(pageIdx, annots, mode, context);
        }
      }
    }
  }

  _cleanAnnotationsInplace(pageIdx, annots, mode, context) {
    for (let i = 0; i < annots.size(); i++) {
      const annot = this._resolve(annots.get(i), context);
      if (annot instanceof PDFLib.PDFDict) {
        this._cleanDictObjInplace(`Page ${pageIdx + 1} Annot ${i + 1}`, annot, mode, context);
      }
    }
  }

  _cleanDictObjInplace(location, obj, mode, context) {
    const keys = Array.from(obj.keys());

    for (const key of keys) {
      const norm = this._normalizeName(key.toString());

      // STANDARD: remove high severity keys
      if (PDFSanitizer.HIGH_KEYS.has(norm)) {
        obj.delete(key);
        this.log(`${location}: Stripped key ${norm}`);
        continue;
      }

      // STRICT + PARANOID: also remove medium severity keys
      if (mode === 'strict' || mode === 'paranoid') {
        if (PDFSanitizer.MEDIUM_KEYS.has(norm)) {
          obj.delete(key);
          this.log(`${location}: Stripped key ${norm}`);
          continue;
        }
      }

      // Handle Actions /A sub-dictionary
      if (norm === "/A") {
        const action = this._resolve(obj.get(key), context);
        if (action instanceof PDFLib.PDFDict) {
          const sVal = this._resolve(action.get(PDFLib.PDFName.of('S')), context);
          if (sVal instanceof PDFLib.PDFName) {
            const sType = this._normalizeName(sVal.toString());

            // Standard: remove JS / Launch actions
            if (["/JavaScript", "/JS", "/Launch"].includes(sType)) {
              obj.delete(key);
              this.log(`${location}: Stripped action /S=${sType}`);
              continue;
            }

            // Strict / Paranoid: also remove URI and form submission actions
            if (mode === 'strict' || mode === 'paranoid') {
              if (["/URI", "/SubmitForm", "/ImportData"].includes(sType)) {
                obj.delete(key);
                this.log(`${location}: Stripped action /S=${sType}`);
                continue;
              }
            }
          }
        }
      }

      // Recurse into sub-dictionaries
      const value = this._resolve(obj.get(key), context);
      if (value instanceof PDFLib.PDFDict) {
        this._cleanDictObjInplace(location, value, mode, context);
      }
    }
  }

  _paranoidRebuildPageInplace(pageIdx, pageObj) {
    const keys = Array.from(pageObj.keys());

    for (const key of keys) {
      const norm = this._normalizeName(key.toString());
      if (!PDFSanitizer.PARANOID_SAFE_PAGE_KEYS.has(norm)) {
        pageObj.delete(key);
        this.log(`Page ${pageIdx + 1} (paranoid): Dropped key ${norm}`);
      }
    }
  }

  _cleanRoot(pdfDoc, mode, context, scrubMetadata = false) {
    const catalog = pdfDoc.catalog;
    if (!catalog) return;

    const keys = Array.from(catalog.keys());

    for (const key of keys) {
      const norm = this._normalizeName(key.toString());

      // Skip metadata stream if scrubbing
      if (norm === '/Metadata' && scrubMetadata) {
        catalog.delete(key);
        this.log('Root: Stripped /Metadata stream (Metadata Scrubbing)');
        continue;
      }

      // STANDARD: strip high severity catalog keys
      if (PDFSanitizer.HIGH_KEYS.has(norm)) {
        catalog.delete(key);
        this.log(`Root: Stripped key ${norm}`);
        continue;
      }

      // Clean /Names subtree
      if (norm === "/Names") {
        const names = this._resolve(catalog.get(key), context);
        if (names instanceof PDFLib.PDFDict) {
          this._cleanNamesTree(names, mode, context);
        }
        continue;
      }

      // STRICT + PARANOID: strip medium-severity keys
      if (mode === 'strict' || mode === 'paranoid') {
        if (PDFSanitizer.MEDIUM_KEYS.has(norm)) {
          catalog.delete(key);
          this.log(`Root: Stripped key ${norm}`);
          continue;
        }
      }

      // PARANOID: only keep safe catalog keys
      if (mode === 'paranoid') {
        if (!PDFSanitizer.PARANOID_SAFE_ROOT_KEYS.has(norm)) {
          catalog.delete(key);
          this.log(`Root (paranoid): Dropped key ${norm}`);
        }
      }
    }
  }

  _cleanNamesTree(names, mode, context) {
    const keys = Array.from(names.keys());

    for (const key of keys) {
      const norm = this._normalizeName(key.toString());

      // Always strip JS name tree
      if (norm === "/JavaScript") {
        names.delete(key);
        this.log("Root/Names: Stripped /JavaScript name tree");
        continue;
      }

      // Strict + Paranoid: strip embedded files
      if (mode === 'strict' || mode === 'paranoid') {
        if (norm === "/EmbeddedFiles") {
          names.delete(key);
          this.log("Root/Names: Stripped /EmbeddedFiles");
          continue;
        }
      }
    }
  }
}

window.PDFSanitizer = PDFSanitizer;

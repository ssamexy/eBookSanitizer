/**
 * EPUB Sanitizer - Layer 1 (Structure Audit) + Layer 2 (Semantic DOM Analysis)
 * JavaScript Port for Client-side Browser execution.
 */

class EPUBSanitizer {
  static DANGEROUS_EXTENSIONS = new Set([
    'exe', 'dll', 'bat', 'cmd', 'sh', 'py', 'pl', 'php',
    'js', 'vbs', 'wsf', 'jar', 'scr', 'pif', 'msi', 'com',
    'ps1', 'cpl', 'hta', 'inf', 'reg', 'rgs', 'sct', 'wsc'
  ]);

  static SAFE_EXTENSIONS = new Set([
    'xhtml', 'html', 'htm', 'xml', 'opf', 'ncx',
    'css', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'bmp',
    'otf', 'ttf', 'woff', 'woff2',
    'mp3', 'mp4', 'ogg', 'wav', 'm4a',
    'smil', 'pls',
    '' // files without extension (e.g., mimetype, container)
  ]);

  static DANGEROUS_TAGS = ['script', 'iframe', 'embed', 'object', 'applet', 'form'];

  static ON_EVENT_RE = /^on\w+$/i;

  static DANGEROUS_PROTOCOLS = /^\s*(javascript|vbscript|data\s*:.*text\/html|data\s*:.*application)/i;

  constructor(file, logCallback = null) {
    this.file = file; // File object from input
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

  _isExternalUrl(url) {
    if (!url) return false;
    const u = url.toLowerCase().trim();
    return u.startsWith('http://') || u.startsWith('https://') || u.startsWith('//');
  }

  /**
   * Scan the EPUB ZIP archive for threats.
   */
  async scan() {
    this.log(`Starting EPUB scan: ${this.file.name}`);
    this.threats = [];
    this.errors = [];

    try {
      const zip = await JSZip.loadAsync(this.file);
      
      for (const [filename, zipEntry] of Object.entries(zip.files)) {
        if (zipEntry.dir) continue;

        // ── Layer 1: Structure Audit ──
        this._scanStructure(filename);

        // ── Layer 2: DOM Analysis (for HTML-like files) ──
        const ext = filename.split('.').pop().toLowerCase();
        if (['xhtml', 'html', 'htm', 'xml', 'svg'].includes(ext)) {
          try {
            const content = await zipEntry.async('string');
            this._scanDom(filename, content);
          } catch (e) {
            this.log(`Warning: Could not read ${filename}: ${e.message}`);
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
      this.error(`Failed to scan EPUB zip archive: ${e.message}`);
      return { success: false, threats: [], summary: { High: 0, Medium: 0, Low: 0 } };
    }
  }

  _scanStructure(filename) {
    // Directory Traversal Detection
    if (filename.includes('..') || filename.startsWith('/') || filename.startsWith('\\')) {
      this.addThreat(
        'DirectoryTraversal',
        filename,
        'Path contains directory traversal components (../ or absolute path)',
        'High'
      );
    }

    const ext = filename.includes('.') ? filename.split('.').pop().toLowerCase() : '';

    // Dangerous extensions
    if (EPUBSanitizer.DANGEROUS_EXTENSIONS.has(ext)) {
      this.addThreat(
        'DangerousFile',
        filename,
        `Contains executable/script file: '.${ext}'`,
        'High'
      );
    } 
    // Non-standard extensions
    else if (ext && !EPUBSanitizer.SAFE_EXTENSIONS.has(ext)) {
      this.addThreat(
        'SuspiciousFile',
        filename,
        `Non-standard EPUB file extension: '.${ext}'`,
        'Medium'
      );
    }
  }

  _scanDom(filename, content) {
    const parser = new DOMParser();
    // Parse as XML if it's XHTML/XML to avoid namespace loss, fall back to HTML if parser error occurs
    let doc;
    const isXml = filename.endsWith('.xhtml') || filename.endsWith('.xml') || filename.endsWith('.svg');
    
    try {
      doc = parser.parseFromString(content, isXml ? 'application/xhtml+xml' : 'text/html');
      const parserError = doc.querySelector('parsererror');
      if (parserError) {
        // Fallback to text/html if XML parser fails
        doc = parser.parseFromString(content, 'text/html');
      }
    } catch (e) {
      doc = parser.parseFromString(content, 'text/html');
    }

    // A. Dangerous tags
    for (const tagName of EPUBSanitizer.DANGEROUS_TAGS) {
      const tags = doc.getElementsByTagName(tagName);
      if (tags.length > 0) {
        const severity = ['script', 'iframe', 'applet'].includes(tagName) ? 'High' : 'Medium';
        this.addThreat(
          'DangerousTag',
          filename,
          `Found ${tags.length} <${tagName}> tag(s)`,
          severity
        );
      }
    }

    // Inspect all elements for inline event handlers and URI schemas
    const allElements = doc.getElementsByTagName('*');
    let externalUrlCount = 0;
    let firstExternalUrl = '';

    for (let i = 0; i < allElements.length; i++) {
      const el = allElements[i];
      
      // B. Inline event handlers (on*)
      const attrs = el.attributes;
      for (let j = 0; j < attrs.length; j++) {
        const attr = attrs[j];
        if (EPUBSanitizer.ON_EVENT_RE.test(attr.name)) {
          this.addThreat(
            'EventHandler',
            filename,
            `Inline event: ${attr.name}="${attr.value.substring(0, 80)}"`,
            'High'
          );
        }

        // C. Dangerous protocols in attributes
        if (['href', 'src', 'action', 'xlink:href', 'formaction'].includes(attr.name)) {
          if (EPUBSanitizer.DANGEROUS_PROTOCOLS.test(attr.value)) {
            this.addThreat(
              'DangerousProtocol',
              filename,
              `<${el.tagName.toLowerCase()}> ${attr.name}="${attr.value.substring(0, 100)}"`,
              'High'
            );
          }

          // D. External URLs (http/https) tracking
          if (this._isExternalUrl(attr.value)) {
            externalUrlCount++;
            if (!firstExternalUrl) {
              firstExternalUrl = attr.value;
            }
          }
        }
      }
    }

    if (externalUrlCount > 0) {
      this.addThreat(
        'ExternalLink',
        filename,
        `${externalUrlCount} external URL(s), e.g., "${firstExternalUrl.substring(0, 80)}"`,
        'Medium'
      );
    }
  }

  /**
   * Sanitize EPUB contents and repackage as a clean EPUB Blob.
   */
  async sanitize(mode = 'standard', scrubMetadata = false) {
    this.log(`Sanitizing EPUB [${mode}]: ${this.file.name}`);
    this.threats = [];
    this.errors = [];

    try {
      const oldZip = await JSZip.loadAsync(this.file);
      const newZip = new JSZip();

      // EPUB Spec: 'mimetype' MUST be the very first file and MUST NOT be compressed.
      // We write it first so JSZip puts it first in the byte stream.
      let mimeContent = 'application/epub+zip';
      if (oldZip.files['mimetype']) {
        mimeContent = await oldZip.files['mimetype'].async('string');
        mimeContent = mimeContent.trim();
      }
      newZip.file('mimetype', mimeContent, { compression: 'STORE' });

      // Process and transfer all other entries
      for (const [filename, zipEntry] of Object.entries(oldZip.files)) {
        if (filename === 'mimetype') continue;

        // Skip directory traversal paths
        if (filename.includes('..') || filename.startsWith('/') || filename.startsWith('\\')) {
          this.log(`SKIP (ZipSlip): ${filename}`);
          continue;
        }

        const ext = filename.includes('.') ? filename.split('.').pop().toLowerCase() : '';

        // Remove dangerous files (all modes)
        if (EPUBSanitizer.DANGEROUS_EXTENSIONS.has(ext)) {
          this.log(`REMOVED dangerous file: ${filename}`);
          continue;
        }

        // PARANOID Mode: remove non-whitelisted files
        if (mode === 'paranoid' && ext && !EPUBSanitizer.SAFE_EXTENSIONS.has(ext)) {
          this.log(`REMOVED non-whitelisted file (paranoid): ${filename}`);
          continue;
        }

        if (zipEntry.dir) {
          newZip.folder(filename);
          continue;
        }

        let fileData = await zipEntry.async('uint8array');

        // Sanitize HTML-like content
        if (['xhtml', 'html', 'htm', 'xml', 'svg'].includes(ext)) {
          const stringContent = new TextDecoder('utf-8').decode(fileData);
          const sanitizedString = this._sanitizeHtml(filename, stringContent, mode);
          fileData = new TextEncoder().encode(sanitizedString);
        }

        // Scrub metadata from OPF manifest file
        if (ext === 'opf' && scrubMetadata) {
          const stringContent = new TextDecoder('utf-8').decode(fileData);
          const scrubbedString = this._scrubOpfMetadata(stringContent);
          fileData = new TextEncoder().encode(scrubbedString);
        }

        // Add file to new zip with compression
        newZip.file(filename, fileData, { compression: 'DEFLATE' });
      }

      // Generate clean zip file as Blob
      const blob = await newZip.generateAsync({ type: 'blob', mimeType: 'application/epub+zip' });
      this.success = true;
      this.log('EPUB sanitization completed successfully.');
      return { success: true, blob };
    } catch (e) {
      this.error(`Sanitization failed: ${e.message}`);
      return { success: false, blob: null };
    }
  }

  _scrubOpfMetadata(content) {
    try {
      const parser = new DOMParser();
      const doc = parser.parseFromString(content, 'application/xml');
      const metadata = doc.getElementsByTagNameNS('*', 'metadata')[0] || doc.getElementsByTagName('metadata')[0];
      if (metadata) {
        const tagsToRemove = ['creator', 'contributor', 'date', 'publisher', 'rights', 'identifier', 'meta'];
        tagsToRemove.forEach(tagLocal => {
          const elems = Array.from(metadata.getElementsByTagNameNS('*', tagLocal)).concat(
            Array.from(metadata.getElementsByTagName(tagLocal))
          );
          elems.forEach(el => {
            if (el.parentNode === metadata) {
              if (tagLocal === 'meta') {
                const prop = el.getAttribute('property') || '';
                const name = el.getAttribute('name') || '';
                if (prop.includes('modified') || prop.includes('date') || name.includes('calibre')) {
                  metadata.removeChild(el);
                }
              } else {
                metadata.removeChild(el);
              }
            }
          });
        });

        // Re-insert safe dc:identifier (pub-id)
        const dcNamespace = 'http://purl.org/dc/elements/1.1/';
        const idEl = doc.createElementNS(dcNamespace, 'dc:identifier');
        idEl.setAttribute('id', 'pub-id');
        idEl.textContent = 'urn:uuid:00000000-0000-0000-0000-000000000000';
        metadata.appendChild(idEl);

        this.log('EPUB: Anonymized metadata inside OPF manifest.');
      }
      return new XMLSerializer().serializeToString(doc);
    } catch (e) {
      this.log(`Warning: Failed to scrub OPF metadata: ${e.message}`);
      return content;
    }
  }

  _sanitizeHtml(filename, content, mode) {
    const parser = new DOMParser();
    let doc;
    const isXml = filename.endsWith('.xhtml') || filename.endsWith('.xml') || filename.endsWith('.svg');
    
    try {
      doc = parser.parseFromString(content, isXml ? 'application/xhtml+xml' : 'text/html');
      const parserError = doc.querySelector('parsererror');
      if (parserError) {
        doc = parser.parseFromString(content, 'text/html');
      }
    } catch (e) {
      doc = parser.parseFromString(content, 'text/html');
    }

    let modified = false;

    // ── All modes: remove dangerous tags ──
    for (const tagName of EPUBSanitizer.DANGEROUS_TAGS) {
      const tags = Array.from(doc.getElementsByTagName(tagName));
      if (tags.length > 0) {
        for (const tag of tags) {
          tag.parentNode.removeChild(tag);
        }
        modified = true;
        this.log(`[${filename}] Removed <${tagName}>`);
      }
    }

    // ── Inspect all elements for inline event handlers and URI schemas ──
    const allElements = doc.getElementsByTagName('*');
    for (let i = 0; i < allElements.length; i++) {
      const el = allElements[i];
      
      // A. Strip on* event handlers
      const attrs = Array.from(el.attributes);
      for (const attr of attrs) {
        if (EPUBSanitizer.ON_EVENT_RE.test(attr.name)) {
          el.removeAttribute(attr.name);
          modified = true;
        }

        // B. Neutralize dangerous protocols (href, src, action, xlink:href, formaction)
        if (['href', 'src', 'action', 'xlink:href', 'formaction'].includes(attr.name)) {
          if (EPUBSanitizer.DANGEROUS_PROTOCOLS.test(attr.value)) {
            el.setAttribute(attr.name, '#disabled_by_sanitizer');
            modified = true;
            this.log(`[${filename}] Neutralized ${attr.name}="${attr.value.substring(0, 60)}"`);
          }
        }
      }

      // ── STRICT & PARANOID Modes: Neutralize external URLs ──
      if (mode === 'strict' || mode === 'paranoid') {
        // Neutralize external links in <a> tags
        if (el.tagName.toLowerCase() === 'a' && el.hasAttribute('href')) {
          const href = el.getAttribute('href');
          if (this._isExternalUrl(href)) {
            el.setAttribute('href', '#');
            modified = true;
            this.log(`[${filename}] Neutralized link: ${href.substring(0, 60)}`);
          }
        }

        // Block external images in <img> or <image>
        if (['img', 'image'].includes(el.tagName.toLowerCase())) {
          for (const attrName of ['src', 'xlink:href', 'href']) {
            if (el.hasAttribute(attrName)) {
              const val = el.getAttribute(attrName);
              if (this._isExternalUrl(val)) {
                el.setAttribute(attrName, '');
                modified = true;
                this.log(`[${filename}] Blocked external image: ${val.substring(0, 60)}`);
              }
            }
          }
        }

        // Block external CSS in <link> tags
        if (el.tagName.toLowerCase() === 'link' && el.getAttribute('rel') === 'stylesheet' && el.hasAttribute('href')) {
          const href = el.getAttribute('href');
          if (this._isExternalUrl(href)) {
            el.parentNode.removeChild(el);
            modified = true;
            this.log(`[${filename}] Blocked external CSS stylesheet: ${href.substring(0, 60)}`);
          }
        }
      }
    }

    // ── PARANOID Mode: strip <style> with @import and <meta http-equiv="refresh"> ──
    if (mode === 'paranoid') {
      // Remove meta refresh redirects
      const metas = Array.from(doc.getElementsByTagName('meta'));
      for (const meta of metas) {
        if (meta.hasAttribute('http-equiv') && /refresh/i.test(meta.getAttribute('http-equiv'))) {
          meta.parentNode.removeChild(meta);
          modified = true;
          this.log(`[${filename}] Removed meta refresh redirect`);
        }
      }

      // Remove @import in <style>
      const styles = Array.from(doc.getElementsByTagName('style'));
      for (const style of styles) {
        if (style.textContent && /@import\s+url\s*\(/i.test(style.textContent)) {
          style.textContent = style.textContent.replace(/@import\s+url\s*\([^)]*\)\s*;?/gi, '/* import removed */');
          modified = true;
          this.log(`[${filename}] Stripped external CSS @import rule`);
        }
      }
    }

    if (!modified) {
      return content;
    }

    // Serialize back to String
    let serialized;
    if (isXml) {
      serialized = new XMLSerializer().serializeToString(doc);
    } else {
      serialized = doc.documentElement.outerHTML;
      // Add doctype back if missing
      if (!serialized.startsWith('<!DOCTYPE')) {
        serialized = '<!DOCTYPE html>\n' + serialized;
      }
    }
    return serialized;
  }
}

window.EPUBSanitizer = EPUBSanitizer;

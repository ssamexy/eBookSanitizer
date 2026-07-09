# 🌐 eBookSanitizer - Web Version

This is a client-side web application version of **eBookSanitizer** designed to run entirely in the browser. It scans and sanitizes EPUB and PDF files without a backend server, making it extremely fast, private, and compatible with static hosting services like **GitHub Pages**.

---

## ✨ Features

* **Client-side Processing:** Files are scanned and processed locally in the user's browser. Files never leave their device, guaranteeing 100% privacy.
* **EPUB Scan & Sanitize:** Uses [JSZip](https://stuk.github.io/jszip/) and native browser `DOMParser` APIs to extract, analyze, clean, and rebuild EPUB archives.
* **PDF Scan & Sanitize:** Uses [pdf-lib](https://pdf-lib.js.org/) to traverse PDF dictionary object trees, detect and strip prohibited actions and scripts.
* **Zero Infrastructure Cost:** Can be hosted on any static hosting environment for free.
* **Premium Design:** Glassmorphic modern dark/light UI with real-time monospaced logging, drag-and-drop support, file batch queue, and threat counters.

*Note: YARA byte signature scanning is omitted from the web version due to its reliance on compiled C libraries.*

---

## 🚀 Running Locally

You can run the web version locally in two ways:

### Method 1: Python HTTP Server (Recommended)
Since we are in a Python project repository, you can spin up a local server easily:
```bash
# Navigate to the web folder
cd web

# Start a simple HTTP server
python -m http.server 8000
```
Then open your browser and navigate to `http://localhost:8000`.

### Method 2: Double-click `index.html`
Because this app is written with pure standard vanilla CSS and JS, and all external libraries (JSZip, pdf-lib) are loaded via CDNs, you can also double-click `index.html` to open it in your browser directly via the `file://` protocol. 

---

## 📦 Deployment to GitHub Pages

To host this on GitHub Pages, you can use one of the following methods:

### Method A: Serve from `docs` folder on `main` branch
This is the simplest way:
1. Rename the `web` folder to `docs` (or copy its contents there) in your git repository.
2. Push your changes to GitHub.
3. Go to your repository settings page on GitHub.
4. Navigate to **Pages** under the Code and Automation section.
5. Under **Build and deployment**, select **Deploy from a branch**.
6. Select your branch (e.g., `main` or `web-version`) and choose the `/docs` folder, then click **Save**.
7. Your app will be live at `https://<your-username>.github.io/<repo-name>/`.

### Method B: Deploy to a dedicated `gh-pages` branch
If you want to keep the directory layout exactly as is, you can deploy using a simple GitHub Action:
Create a `.github/workflows/deploy-pages.yml` file with contents similar to:
```yaml
name: Deploy Web Version to GitHub Pages

on:
  push:
    branches:
      - main
      - web-version
    paths:
      - 'web/**'

permissions:
  contents: write

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Deploy to GitHub Pages
        uses: JamesIves/github-pages-deploy-action@v4
        with:
          folder: web
          branch: gh-pages
```
Go to your repository settings > **Pages**, and set the source branch to `gh-pages` and root folder `/`.

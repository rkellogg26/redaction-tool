#!/usr/bin/env python3
"""
Document Redaction Tool - Web Interface
"""

import os
import re
import uuid
import shutil
import tempfile
from pathlib import Path
from dataclasses import dataclass, field
from flask import Flask, render_template_string, request, send_file, jsonify, redirect, url_for
import fitz  # PyMuPDF
from docx import Document

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

# Use temp directories for Render (ephemeral filesystem)
UPLOAD_FOLDER = Path(tempfile.gettempdir()) / 'redaction_uploads'
OUTPUT_FOLDER = Path(tempfile.gettempdir()) / 'redaction_outputs'
UPLOAD_FOLDER.mkdir(exist_ok=True)
OUTPUT_FOLDER.mkdir(exist_ok=True)


@dataclass
class SensitiveCategory:
    name: str
    description: str
    patterns: list = field(default_factory=list)
    examples: list = field(default_factory=list)
    enabled: bool = True


PREDEFINED_CATEGORIES = {
    "ssn": SensitiveCategory(
        name="Social Security Numbers",
        description="XXX-XX-XXXX format",
        patterns=[r'\b\d{3}-\d{2}-\d{4}\b', r'\b\d{9}\b'],
        examples=["123-45-6789"]
    ),
    "email": SensitiveCategory(
        name="Email Addresses",
        description="user@domain.com",
        patterns=[r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'],
        examples=["example@email.com"]
    ),
    "phone": SensitiveCategory(
        name="Phone Numbers",
        description="Various US formats",
        patterns=[
            r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',
            r'\(\d{3}\)\s*\d{3}[-.\s]?\d{4}\b'
        ],
        examples=["555-123-4567"]
    ),
    "creditcard": SensitiveCategory(
        name="Credit Card Numbers",
        description="13-19 digit card numbers",
        patterns=[r'\b(?:\d{4}[-\s]?){3,4}\d{1,4}\b'],
        examples=["4111-1111-1111-1111"]
    ),
    "date": SensitiveCategory(
        name="Dates",
        description="Various date formats",
        patterns=[
            r'\b\d{1,2}/\d{1,2}/\d{2,4}\b',
            r'\b\d{1,2}-\d{1,2}-\d{2,4}\b',
            r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4}\b'
        ],
        examples=["01/15/2024"]
    ),
}


class SensitiveInfoDetector:
    def __init__(self):
        self.categories = {}
        self.custom_terms = []

    def add_category(self, key: str, category: SensitiveCategory):
        self.categories[key] = category

    def set_custom_terms(self, terms: list):
        self.custom_terms = [t.strip() for t in terms if t.strip()]

    def find_sensitive_text(self, text: str) -> list:
        matches = []

        for key, category in self.categories.items():
            if not category.enabled:
                continue
            for pattern in category.patterns:
                try:
                    for match in re.finditer(pattern, text, re.IGNORECASE):
                        matches.append((match.start(), match.end(), match.group(), category.name))
                except re.error:
                    continue

        for term in self.custom_terms:
            escaped = re.escape(term)
            try:
                for match in re.finditer(escaped, text, re.IGNORECASE):
                    matches.append((match.start(), match.end(), match.group(), "Custom Terms"))
            except re.error:
                continue

        matches.sort(key=lambda x: (x[0], -(x[1] - x[0])))
        filtered = []
        last_end = -1
        for match in matches:
            if match[0] >= last_end:
                filtered.append(match)
                last_end = match[1]
        return filtered


def redact_pdf(input_path: str, output_path: str, detector: SensitiveInfoDetector) -> dict:
    doc = fitz.open(input_path)
    stats = {"pages": 0, "redactions": 0, "categories": {}}

    for page in doc:
        stats["pages"] += 1
        text_dict = page.get_text("dict")

        for block in text_dict.get("blocks", []):
            if block.get("type") != 0:
                continue
            for line in block.get("lines", []):
                for span in line.get("spans", []):
                    text = span.get("text", "")
                    if not text:
                        continue
                    matches = detector.find_sensitive_text(text)
                    for start, end, matched_text, category in matches:
                        instances = page.search_for(matched_text)
                        for inst in instances:
                            page.add_redact_annot(inst, fill=(0, 0, 0))
                            stats["redactions"] += 1
                            stats["categories"][category] = stats["categories"].get(category, 0) + 1
        page.apply_redactions()

    doc.save(output_path)
    doc.close()
    return stats


def redact_docx(input_path: str, output_path: str, detector: SensitiveInfoDetector) -> dict:
    doc = Document(input_path)
    stats = {"paragraphs": 0, "redactions": 0, "categories": {}}

    def process_paragraph(para):
        full_text = para.text
        if not full_text:
            return
        matches = detector.find_sensitive_text(full_text)
        if not matches:
            return

        new_text = list(full_text)
        for start, end, matched_text, category in matches:
            for i in range(start, end):
                new_text[i] = "█"
            stats["redactions"] += 1
            stats["categories"][category] = stats["categories"].get(category, 0) + 1

        new_text = "".join(new_text)
        if para.runs:
            first_run = para.runs[0]
            font_name = first_run.font.name
            font_size = first_run.font.size
            bold = first_run.font.bold
            italic = first_run.font.italic
            for run in para.runs:
                run.text = ""
            para.runs[0].text = new_text
            para.runs[0].font.name = font_name
            para.runs[0].font.size = font_size
            para.runs[0].font.bold = bold
            para.runs[0].font.italic = italic

    for para in doc.paragraphs:
        stats["paragraphs"] += 1
        process_paragraph(para)

    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for para in cell.paragraphs:
                    stats["paragraphs"] += 1
                    process_paragraph(para)

    doc.save(output_path)
    return stats


def extract_text(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    if ext == ".pdf":
        doc = fitz.open(file_path)
        text = ""
        for page in doc:
            text += page.get_text() + "\n"
        doc.close()
        return text
    elif ext == ".docx":
        doc = Document(file_path)
        return "\n".join([para.text for para in doc.paragraphs])
    return ""


HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document Redaction Tool</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            color: #fff;
            padding: 20px;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
        }
        h1 {
            text-align: center;
            margin-bottom: 10px;
            font-size: 2.5rem;
            background: linear-gradient(90deg, #00d4ff, #7b2cbf);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .subtitle {
            text-align: center;
            color: #888;
            margin-bottom: 30px;
        }
        .card {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
        }
        .card h2 {
            font-size: 1.2rem;
            margin-bottom: 16px;
            color: #00d4ff;
        }
        .upload-zone {
            border: 2px dashed rgba(255, 255, 255, 0.3);
            border-radius: 12px;
            padding: 40px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        .upload-zone:hover {
            border-color: #00d4ff;
            background: rgba(0, 212, 255, 0.05);
        }
        .upload-zone.dragover {
            border-color: #00d4ff;
            background: rgba(0, 212, 255, 0.1);
        }
        .upload-icon {
            font-size: 48px;
            margin-bottom: 10px;
        }
        .file-input {
            display: none;
        }
        .file-name {
            margin-top: 15px;
            padding: 10px 15px;
            background: rgba(0, 212, 255, 0.2);
            border-radius: 8px;
            display: none;
        }
        .file-name.visible {
            display: inline-block;
        }
        .categories {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 12px;
        }
        .category-item {
            display: flex;
            align-items: center;
            padding: 12px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .category-item:hover {
            background: rgba(255, 255, 255, 0.1);
        }
        .category-item input[type="checkbox"] {
            width: 20px;
            height: 20px;
            margin-right: 12px;
            accent-color: #00d4ff;
        }
        .category-item label {
            cursor: pointer;
            flex: 1;
        }
        .category-name {
            font-weight: 500;
        }
        .category-example {
            font-size: 0.8rem;
            color: #888;
        }
        .custom-terms textarea {
            width: 100%;
            height: 120px;
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 8px;
            padding: 12px;
            color: #fff;
            font-family: monospace;
            font-size: 14px;
            resize: vertical;
        }
        .custom-terms textarea:focus {
            outline: none;
            border-color: #00d4ff;
        }
        .custom-terms textarea::placeholder {
            color: #666;
        }
        .buttons {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }
        .btn {
            padding: 14px 28px;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .btn-primary {
            background: linear-gradient(90deg, #00d4ff, #7b2cbf);
            color: #fff;
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(0, 212, 255, 0.3);
        }
        .btn-secondary {
            background: rgba(255, 255, 255, 0.1);
            color: #fff;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        .btn-secondary:hover {
            background: rgba(255, 255, 255, 0.2);
        }
        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }
        .results {
            display: none;
        }
        .results.visible {
            display: block;
        }
        .results-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 16px;
        }
        .results-header .icon {
            width: 48px;
            height: 48px;
            background: linear-gradient(90deg, #00d4ff, #7b2cbf);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
            gap: 12px;
            margin-bottom: 20px;
        }
        .stat-item {
            background: rgba(0, 0, 0, 0.3);
            padding: 16px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-value {
            font-size: 2rem;
            font-weight: bold;
            color: #00d4ff;
        }
        .stat-label {
            font-size: 0.85rem;
            color: #888;
        }
        .preview-box {
            background: rgba(0, 0, 0, 0.4);
            border-radius: 8px;
            padding: 16px;
            max-height: 300px;
            overflow-y: auto;
            font-family: monospace;
            font-size: 13px;
            line-height: 1.6;
            white-space: pre-wrap;
            word-break: break-word;
        }
        .preview-box .match {
            background: #ffeb3b;
            color: #000;
            padding: 2px 4px;
            border-radius: 3px;
        }
        .loading {
            display: none;
            text-align: center;
            padding: 40px;
        }
        .loading.visible {
            display: block;
        }
        .spinner {
            width: 50px;
            height: 50px;
            border: 3px solid rgba(255, 255, 255, 0.1);
            border-top-color: #00d4ff;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        .download-btn {
            display: none;
            margin-top: 20px;
        }
        .download-btn.visible {
            display: inline-flex;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Document Redaction Tool</h1>
        <p class="subtitle">Automatically redact sensitive information from PDFs and Word documents</p>

        <form id="redactionForm" enctype="multipart/form-data">
            <div class="card">
                <h2>1. Upload Document</h2>
                <div class="upload-zone" id="uploadZone">
                    <div class="upload-icon">📄</div>
                    <p>Drag & drop your PDF or Word document here</p>
                    <p style="color: #666; margin-top: 8px;">or click to browse</p>
                    <input type="file" name="file" id="fileInput" class="file-input" accept=".pdf,.docx">
                </div>
                <div class="file-name" id="fileName"></div>
            </div>

            <div class="card">
                <h2>2. Select Information to Redact</h2>
                <div class="categories">
                    {% for key, cat in categories.items() %}
                    <div class="category-item">
                        <input type="checkbox" name="categories" value="{{ key }}" id="cat_{{ key }}" checked>
                        <label for="cat_{{ key }}">
                            <div class="category-name">{{ cat.name }}</div>
                            <div class="category-example">e.g., {{ cat.examples[0] }}</div>
                        </label>
                    </div>
                    {% endfor %}
                </div>
            </div>

            <div class="card">
                <h2>3. Custom Terms (Optional)</h2>
                <p style="color: #888; margin-bottom: 12px;">Add names, project names, or other specific terms to redact (one per line)</p>
                <div class="custom-terms">
                    <textarea name="custom_terms" id="customTerms" placeholder="John Doe&#10;Project Alpha&#10;Confidential"></textarea>
                </div>
            </div>

            <div class="card">
                <div class="buttons">
                    <button type="button" class="btn btn-secondary" id="previewBtn" disabled>
                        👁️ Preview
                    </button>
                    <button type="submit" class="btn btn-primary" id="redactBtn" disabled>
                        🔒 Redact Document
                    </button>
                </div>
            </div>
        </form>

        <div class="card loading" id="loading">
            <div class="spinner"></div>
            <p>Processing your document...</p>
        </div>

        <div class="card results" id="results">
            <div class="results-header">
                <div class="icon">✓</div>
                <div>
                    <h2 style="margin: 0;">Redaction Complete!</h2>
                    <p style="color: #888; margin-top: 4px;" id="outputFileName"></p>
                </div>
            </div>
            <div class="stats" id="statsContainer"></div>
            <a href="#" class="btn btn-primary download-btn" id="downloadBtn">
                📥 Download Redacted Document
            </a>
        </div>

        <div class="card results" id="previewResults">
            <h2>Preview - Items to Redact</h2>
            <div class="stats" id="previewStats"></div>
            <h3 style="margin: 16px 0 8px; font-size: 1rem;">Document Preview:</h3>
            <div class="preview-box" id="previewContent"></div>
        </div>
    </div>

    <script>
        const uploadZone = document.getElementById('uploadZone');
        const fileInput = document.getElementById('fileInput');
        const fileName = document.getElementById('fileName');
        const previewBtn = document.getElementById('previewBtn');
        const redactBtn = document.getElementById('redactBtn');
        const form = document.getElementById('redactionForm');
        const loading = document.getElementById('loading');
        const results = document.getElementById('results');
        const previewResults = document.getElementById('previewResults');

        // File upload handling
        uploadZone.addEventListener('click', () => fileInput.click());

        uploadZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadZone.classList.add('dragover');
        });

        uploadZone.addEventListener('dragleave', () => {
            uploadZone.classList.remove('dragover');
        });

        uploadZone.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadZone.classList.remove('dragover');
            if (e.dataTransfer.files.length) {
                fileInput.files = e.dataTransfer.files;
                updateFileName();
            }
        });

        fileInput.addEventListener('change', updateFileName);

        function updateFileName() {
            if (fileInput.files.length) {
                fileName.textContent = '📎 ' + fileInput.files[0].name;
                fileName.classList.add('visible');
                previewBtn.disabled = false;
                redactBtn.disabled = false;
            }
        }

        // Preview
        previewBtn.addEventListener('click', async () => {
            const formData = new FormData(form);

            loading.classList.add('visible');
            results.classList.remove('visible');
            previewResults.classList.remove('visible');

            try {
                const response = await fetch('/preview', {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();
                loading.classList.remove('visible');

                if (data.error) {
                    alert('Error: ' + data.error);
                    return;
                }

                // Show preview stats
                let statsHtml = '';
                statsHtml += `<div class="stat-item"><div class="stat-value">${data.total}</div><div class="stat-label">Total Items</div></div>`;
                for (const [cat, count] of Object.entries(data.categories)) {
                    statsHtml += `<div class="stat-item"><div class="stat-value">${count}</div><div class="stat-label">${cat}</div></div>`;
                }
                document.getElementById('previewStats').innerHTML = statsHtml;

                // Show preview content with highlights
                document.getElementById('previewContent').innerHTML = data.preview_html;
                previewResults.classList.add('visible');

            } catch (err) {
                loading.classList.remove('visible');
                alert('Error: ' + err.message);
            }
        });

        // Redact
        form.addEventListener('submit', async (e) => {
            e.preventDefault();

            const formData = new FormData(form);

            loading.classList.add('visible');
            results.classList.remove('visible');
            previewResults.classList.remove('visible');

            try {
                const response = await fetch('/redact', {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();
                loading.classList.remove('visible');

                if (data.error) {
                    alert('Error: ' + data.error);
                    return;
                }

                // Show results
                document.getElementById('outputFileName').textContent = data.output_filename;

                let statsHtml = '';
                statsHtml += `<div class="stat-item"><div class="stat-value">${data.stats.redactions}</div><div class="stat-label">Total Redactions</div></div>`;
                for (const [cat, count] of Object.entries(data.stats.categories)) {
                    statsHtml += `<div class="stat-item"><div class="stat-value">${count}</div><div class="stat-label">${cat}</div></div>`;
                }
                document.getElementById('statsContainer').innerHTML = statsHtml;

                const downloadBtn = document.getElementById('downloadBtn');
                downloadBtn.href = '/download/' + data.output_id;
                downloadBtn.classList.add('visible');

                results.classList.add('visible');

            } catch (err) {
                loading.classList.remove('visible');
                alert('Error: ' + err.message);
            }
        });
    </script>
</body>
</html>
'''


@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE, categories=PREDEFINED_CATEGORIES)


@app.route('/preview', methods=['POST'])
def preview():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'})

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'})

    ext = Path(file.filename).suffix.lower()
    if ext not in ['.pdf', '.docx']:
        return jsonify({'error': 'Unsupported file type. Please upload a PDF or Word document.'})

    # Save uploaded file
    file_id = str(uuid.uuid4())
    input_path = UPLOAD_FOLDER / f"{file_id}{ext}"
    file.save(str(input_path))

    # Setup detector
    detector = SensitiveInfoDetector()
    categories = request.form.getlist('categories')
    for cat_key in categories:
        if cat_key in PREDEFINED_CATEGORIES:
            detector.add_category(cat_key, PREDEFINED_CATEGORIES[cat_key])

    custom_terms = request.form.get('custom_terms', '').strip().split('\n')
    detector.set_custom_terms(custom_terms)

    # Extract text and find matches
    try:
        text = extract_text(str(input_path))
        matches = detector.find_sensitive_text(text)

        # Build preview HTML with highlights
        preview_html = ""
        last_end = 0
        for start, end, matched_text, category in matches:
            preview_html += escape_html(text[last_end:start])
            preview_html += f'<span class="match">{escape_html(matched_text)}</span>'
            last_end = end
        preview_html += escape_html(text[last_end:])

        # Count by category
        category_counts = {}
        for _, _, _, category in matches:
            category_counts[category] = category_counts.get(category, 0) + 1

        # Cleanup
        os.remove(input_path)

        return jsonify({
            'total': len(matches),
            'categories': category_counts,
            'preview_html': preview_html[:50000]  # Limit preview size
        })

    except Exception as e:
        if input_path.exists():
            os.remove(input_path)
        return jsonify({'error': str(e)})


@app.route('/redact', methods=['POST'])
def redact():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'})

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'})

    ext = Path(file.filename).suffix.lower()
    if ext not in ['.pdf', '.docx']:
        return jsonify({'error': 'Unsupported file type'})

    # Save uploaded file
    file_id = str(uuid.uuid4())
    input_path = UPLOAD_FOLDER / f"{file_id}{ext}"
    file.save(str(input_path))

    # Setup detector
    detector = SensitiveInfoDetector()
    categories = request.form.getlist('categories')
    for cat_key in categories:
        if cat_key in PREDEFINED_CATEGORIES:
            detector.add_category(cat_key, PREDEFINED_CATEGORIES[cat_key])

    custom_terms = request.form.get('custom_terms', '').strip().split('\n')
    detector.set_custom_terms(custom_terms)

    # Output path
    original_name = Path(file.filename).stem
    output_filename = f"{original_name}_redacted{ext}"
    output_id = str(uuid.uuid4())
    output_path = OUTPUT_FOLDER / f"{output_id}{ext}"

    try:
        if ext == '.pdf':
            stats = redact_pdf(str(input_path), str(output_path), detector)
        else:
            stats = redact_docx(str(input_path), str(output_path), detector)

        # Cleanup input
        os.remove(input_path)

        # Store output filename mapping
        with open(OUTPUT_FOLDER / f"{output_id}.meta", 'w') as f:
            f.write(output_filename)

        return jsonify({
            'success': True,
            'output_id': output_id,
            'output_filename': output_filename,
            'stats': stats
        })

    except Exception as e:
        if input_path.exists():
            os.remove(input_path)
        return jsonify({'error': str(e)})


@app.route('/download/<output_id>')
def download(output_id):
    # Find the file
    for ext in ['.pdf', '.docx']:
        output_path = OUTPUT_FOLDER / f"{output_id}{ext}"
        meta_path = OUTPUT_FOLDER / f"{output_id}.meta"

        if output_path.exists():
            # Get original filename
            download_name = f"redacted_document{ext}"
            if meta_path.exists():
                with open(meta_path) as f:
                    download_name = f.read().strip()

            return send_file(
                str(output_path),
                as_attachment=True,
                download_name=download_name
            )

    return "File not found", 404


def escape_html(text):
    return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    debug = os.environ.get('FLASK_ENV') != 'production'

    if debug:
        print("\n" + "="*50)
        print("Document Redaction Tool - Web Interface")
        print("="*50)
        print(f"\nOpen your browser and go to:")
        print(f"\n  http://localhost:{port}")
        print("\n" + "="*50 + "\n")

    app.run(debug=debug, host='0.0.0.0', port=port)

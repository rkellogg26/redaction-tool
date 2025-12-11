# Document Redaction Tool

A Python application that redacts sensitive information from PDF and Word documents by placing black redaction boxes over detected content.

## Features

- **PDF Redaction**: True redaction that permanently removes text content (not just visual overlay)
- **Word Document Redaction**: Replaces sensitive text with black blocks (█)
- **Predefined Categories**: SSN, Email, Phone, Credit Card, Dates
- **Custom Terms**: Add your own words, phrases, or names to redact
- **Preview Mode**: See what will be redacted before committing
- **GUI Interface**: Easy-to-use graphical interface

## Installation

1. Ensure you have Python 3.8+ installed

2. Install dependencies:
```bash
cd redaction-tool
pip install -r requirements.txt
```

## Usage

1. Run the application:
```bash
python redaction_tool.py
```

2. **Select a Document**: Click "Browse..." to select a PDF or Word document

3. **Choose Categories**: Check/uncheck the predefined categories you want to redact:
   - Social Security Numbers (XXX-XX-XXXX)
   - Email Addresses
   - Phone Numbers
   - Credit Card Numbers
   - Dates

4. **Add Custom Terms** (optional):
   - Check "Custom Terms"
   - Enter words/phrases in the text box (one per line)
   - Click "Update Custom Terms"

5. **Preview**: Click "Preview Redactions" to see highlighted text that will be redacted

6. **Redact**: Click "Redact Document" to create the redacted version
   - Choose where to save the output file
   - The tool will process the document and report statistics

## Examples of Custom Terms

Enter custom terms like:
```
John Doe
Jane Smith
Project Phoenix
Acme Corporation
Confidential
```

## Output

- **PDF**: Creates a new PDF with black boxes permanently covering redacted text
- **Word**: Creates a new document with redacted text replaced by █ characters

## Security Notes

- PDF redactions are permanent - the original text is removed from the document
- Always verify the redacted output before sharing
- Keep backups of original documents
- The tool processes documents locally - no data is sent externally

## Supported Formats

- PDF (.pdf)
- Word Documents (.docx)

## Dependencies

- PyMuPDF (fitz) - PDF processing
- python-docx - Word document processing
- tkinter - GUI framework (included with Python)
- Pillow - Image processing

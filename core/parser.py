import io
import base64
import chardet
import fitz
from docx import Document
from core.schemas import AnalyzeRequest

Lines = list[tuple[int, str]]


def parse(request: AnalyzeRequest) -> Lines:
    if request.input_type in ("text", "chat", "sql"):
        return _from_string(request.content)

    elif request.input_type == "log":
        return _from_string(request.content)

    elif request.input_type == "file":
        filename = (request.filename or "").lower()
        if filename.endswith(".pdf"):
            return _from_pdf(request.content)
        elif filename.endswith((".docx", ".doc")):
            return _from_docx(request.content)
        else:
            return _from_string(request.content)

    return _from_string(request.content)


def _from_string(text: str) -> Lines:
    # Strip UTF-8 BOM if present
    text = text.lstrip("\ufeff")

    # Handle literal \n from some HTTP clients
    if "\n" not in text and "\\n" in text:
        text = text.replace("\\n", "\n")

    # Strip null bytes and non-printable junk
    text = text.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")

    lines = []
    for i, line in enumerate(text.splitlines()):
        clean = line.strip()
        if clean and clean.isprintable():
            lines.append((i, clean))

    return lines


def _safe_decode(raw_bytes: bytes) -> str:
    """Detect encoding and decode bytes to string safely."""
    # Try UTF-8 with BOM first
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        return raw_bytes[3:].decode("utf-8", errors="replace")
    # Try UTF-16
    if raw_bytes.startswith(b"\xff\xfe") or raw_bytes.startswith(b"\xfe\xff"):
        return raw_bytes.decode("utf-16", errors="replace")
    # Use chardet for everything else
    detected = chardet.detect(raw_bytes[:4096])  # sample first 4KB
    encoding = detected.get("encoding") or "utf-8"
    return raw_bytes.decode(encoding, errors="replace")


def _from_pdf(content: str) -> Lines:
    try:
        raw_bytes = base64.b64decode(content)
        doc = fitz.open(stream=raw_bytes, filetype="pdf")
        all_lines: Lines = []
        line_num = 0
        for page in doc:
            for line in page.get_text().splitlines():
                if line.strip():
                    all_lines.append((line_num, line.strip()))
                    line_num += 1
        return all_lines
    except Exception as e:
        return [(0, f"PDF parse error: {e}")]


def _from_docx(content: str) -> Lines:
    try:
        raw_bytes = base64.b64decode(content)
        doc = Document(io.BytesIO(raw_bytes))
        return [
            (i, para.text.strip())
            for i, para in enumerate(doc.paragraphs)
            if para.text.strip()
        ]
    except Exception as e:
        return [(0, f"DOCX parse error: {e}")]
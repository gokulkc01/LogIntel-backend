import io
import base64
import re
import chardet
import fitz
from docx import Document
from core.schemas import AnalyzeRequest

Lines = list[tuple[int, str]]
OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def parse(request: AnalyzeRequest) -> Lines:
    if request.input_type in ("text", "chat", "sql"):
        return _from_string(request.content)

    elif request.input_type == "log":
        return _from_string(request.content)

    elif request.input_type == "file":
        filename = (request.filename or "").lower()
        if filename.endswith(".pdf"):
            return _from_pdf(request.content)
        elif filename.endswith(".docx"):
            return _from_docx(request.content)
        elif filename.endswith(".doc"):
            return _from_doc(request.content)
        else:
            return _from_string(request.content)

    return _from_string(request.content)


def parse_upload(input_type: str, raw_bytes: bytes, filename: str | None = None) -> Lines:
    normalized_type = input_type.lower()
    normalized_name = (filename or "").lower()

    if normalized_type in ("text", "chat", "sql", "log"):
        return _from_string(_safe_decode(raw_bytes))

    if normalized_type == "file":
        if normalized_name.endswith(".pdf"):
            return _from_pdf_bytes(raw_bytes)
        if normalized_name.endswith(".docx"):
            return _from_docx_bytes(raw_bytes)
        if normalized_name.endswith(".doc"):
            return _from_doc_bytes(raw_bytes)
        return _from_string(_safe_decode(raw_bytes))

    return _from_string(_safe_decode(raw_bytes))


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


def _decode_base64(content: str) -> bytes:
    return base64.b64decode(content, validate=False)


def _normalize_text_lines(text: str) -> Lines:
    return _from_string(text)


def _from_pdf(content: str) -> Lines:
    try:
        raw_bytes = _decode_base64(content)
        return _from_pdf_bytes(raw_bytes)
    except Exception as e:
        return [(0, f"PDF parse error: {e}")]


def _from_docx(content: str) -> Lines:
    try:
        raw_bytes = _decode_base64(content)
        return _from_docx_bytes(raw_bytes)
    except Exception as e:
        return [(0, f"DOCX parse error: {e}")]


def _from_doc(content: str) -> Lines:
    try:
        raw_bytes = _decode_base64(content)
        return _from_doc_bytes(raw_bytes)
    except Exception as e:
        return [(0, f"DOC parse error: {e}")]


def _from_pdf_bytes(raw_bytes: bytes) -> Lines:
    doc = fitz.open(stream=raw_bytes, filetype="pdf")
    all_lines: Lines = []
    line_num = 0
    for page in doc:
        for line in page.get_text().splitlines():
            if line.strip():
                all_lines.append((line_num, line.strip()))
                line_num += 1
    return all_lines


def _from_docx_bytes(raw_bytes: bytes) -> Lines:
    doc = Document(io.BytesIO(raw_bytes))
    return [
        (i, para.text.strip())
        for i, para in enumerate(doc.paragraphs)
        if para.text.strip()
    ]


def _from_doc_bytes(raw_bytes: bytes) -> Lines:
    # Best-effort support for legacy OLE Word documents. We extract readable
    # text runs so the scanner can still analyze the content instead of failing
    # the whole request.
    if raw_bytes.startswith(OLE2_MAGIC):
        text = raw_bytes.decode("utf-16le", errors="ignore")
    else:
        text = _safe_decode(raw_bytes)

    text = text.replace("\x00", " ")
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]+", " ", text)
    lines = _normalize_text_lines(text)
    meaningful = [line for _, line in lines if len(line) >= 3]
    if meaningful:
        return lines

    return [
        (
            0,
            "DOC parse warning: legacy Word content could not be reliably extracted. Convert to DOCX or TXT for best results.",
        )
    ]

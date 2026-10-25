import io
import zipfile

from werkzeug.utils import secure_filename

ALLOWED = {
    "pdf": "application/pdf",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "txt": "text/plain",
    "csv": "text/csv",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}


def _magic_ok(ext, data):
    if ext == "pdf":
        return data.startswith(b"%PDF-")
    if ext == "png":
        return data.startswith(b"\x89PNG\r\n\x1a\n")
    if ext in ("jpg", "jpeg"):
        return data.startswith(b"\xff\xd8\xff")
    if ext in ("txt", "csv"):
        if b"\x00" in data:
            return False
        try:
            data.decode("utf-8")
            return True
        except UnicodeDecodeError:
            return False
    if ext in ("docx", "xlsx"):
        try:
            infos = zipfile.ZipFile(io.BytesIO(data)).infolist()
        except zipfile.BadZipFile:
            return False
        if len(infos) > 2000 or sum(i.file_size for i in infos) > 100 * 1024 * 1024:
            return False  # zip-bomb guard
        names = {i.filename for i in infos}
        prefix = "word/" if ext == "docx" else "xl/"
        return "[Content_Types].xml" in names and any(n.startswith(prefix) for n in names)
    return False


def validate_upload(f, max_bytes):
    """Returns (clean_name, mime, data) or raises ValueError(message).
    The browser-supplied name and content-type are never trusted."""
    if not f or not f.filename:
        raise ValueError("No file selected")
    name = secure_filename(f.filename)[:100]
    if not name or "." not in name:
        raise ValueError("Invalid file name")
    ext = name.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED:
        raise ValueError("File type not allowed")
    data = f.stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("File too large")
    if not data:
        raise ValueError("File is empty")
    if not _magic_ok(ext, data):
        raise ValueError("File content does not match its extension")
    return name, ALLOWED[ext], data


def clean_title(value):
    value = (value or "").strip()
    if not 1 <= len(value) <= 100 or not value.isprintable():
        raise ValueError("Name must be 1-100 printable characters")
    return value

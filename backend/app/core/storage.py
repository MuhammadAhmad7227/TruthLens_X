# fmt: off
"""Private filesystem storage for evidence originals.

M5 keeps evidence bytes outside PostgreSQL and never derives a storage path from a client filename.
Writes are streamed into quarantine, hashed while reading, then atomically published under a
content-addressed SHA-256 path.
"""
from __future__ import annotations

import hashlib
import os
from collections.abc import BinaryIO, Iterator
from contextlib import suppress
from tempfile import NamedTemporaryFile
from typing import NamedTuple

from app.core.config import Settings

_SIGNATURE_PREFIX_BYTES = 64
_RIFF_HEADER_BYTES = 12
_TEXT_RATIO = 0.95


class StoredUpload(NamedTuple):
    sha256: str
    size_bytes: int
    detected_mime: str
    declared_mime: str | None
    storage_path: str


_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"RIFF", "audio/wav"),
    (b"ID3", "audio/mpeg"),
    (b"%PDF-", "application/pdf"),
    (b"PK\x03\x04", "application/zip"),
    (b"\x1a\x45\xdf\xa3", "video/webm"),
    (b"\x00\x00\x00", "video/mp4"),
)


def detect_mime(prefix: bytes) -> str:
    """Detect a conservative MIME type from file-signature bytes."""
    if prefix.startswith(b"RIFF") and len(prefix) >= _RIFF_HEADER_BYTES:
        if prefix[8:12] == b"WEBP":
            return "image/webp"
        if prefix[8:12] == b"WAVE":
            return "audio/wav"
    if len(prefix) >= _RIFF_HEADER_BYTES and prefix[4:8] == b"ftyp":
        return "video/mp4"
    for signature, mime in _SIGNATURES:
        if prefix.startswith(signature):
            return mime
    try:
        decoded = prefix.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Unsupported or unrecognised file signature") from exc
    if decoded and "\x00" not in decoded and sum(
        ch.isprintable() or ch in "\r\n\t" for ch in decoded
    ) / len(decoded) > _TEXT_RATIO:
        return "text/plain"
    raise ValueError("Unsupported or unrecognised file signature")


def sanitise_filename(filename: str | None) -> str:
    """Return a display-only filename with path components removed."""
    raw = (filename or "evidence").replace("\\", "/")
    name = raw.rsplit("/", 1)[-1].strip().replace("\x00", "")
    if not name or name in {".", ".."}:
        return "evidence"
    return name[:255]


def _object_relative_path(sha256: str) -> str:
    return f"{sha256[:2]}/{sha256[2:4]}/{sha256}"


def stream_to_quarantine(
    source: BinaryIO,
    *,
    settings: Settings,
    declared_mime: str | None,
) -> StoredUpload:
    """Stream an upload once, enforcing the configured byte limit and computing SHA-256."""
    root = settings.quarantine_root
    root.mkdir(parents=True, exist_ok=True)
    hasher = hashlib.sha256()
    size = 0
    prefix = bytearray()
    tmp_name = None
    try:
        with NamedTemporaryFile(
            mode="wb", dir=root, prefix=".upload-", suffix=".part", delete=False
        ) as tmp:
            tmp_name = tmp.name
            while True:
                chunk = source.read(settings.hash_block_bytes)
                if not chunk:
                    break
                if len(prefix) < _SIGNATURE_PREFIX_BYTES:
                    prefix.extend(chunk[: _SIGNATURE_PREFIX_BYTES - len(prefix)])
                size += len(chunk)
                if size > settings.max_upload_bytes:
                    raise ValueError("Upload exceeds the configured maximum size")
                hasher.update(chunk)
                tmp.write(chunk)
            tmp.flush()
            os.fsync(tmp.fileno())
        detected = detect_mime(bytes(prefix))
        digest = hasher.hexdigest()
        relative = _object_relative_path(digest)
        destination = settings.evidence_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            os.unlink(tmp_name)
        else:
            os.replace(tmp_name, destination)
        tmp_name = None
        return StoredUpload(digest, size, detected, declared_mime, relative)
    finally:
        if tmp_name:
            with suppress(FileNotFoundError):
                os.unlink(tmp_name)


def open_object(*, settings: Settings, storage_path: str) -> BinaryIO:
    """Open an evidence object only from the configured evidence root."""
    root = settings.evidence_root.resolve()
    candidate = (root / storage_path).resolve()
    if not candidate.is_relative_to(root):
        raise ValueError("Storage path escapes the evidence root")
    return candidate.open("rb")


def iter_object(*, settings: Settings, storage_path: str, chunk_size: int = 1_048_576) -> Iterator[bytes]:
    with open_object(settings=settings, storage_path=storage_path) as source:
        while chunk := source.read(chunk_size):
            yield chunk

# fmt: on

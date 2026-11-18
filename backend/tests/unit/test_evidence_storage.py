# fmt: off
# ruff: isort: skip_file
from __future__ import annotations

import io

import pytest

from app.core.config import Settings
from app.core.storage import detect_mime, sanitise_filename, stream_to_quarantine



def test_detect_mime_uses_magic_bytes() -> None:
    assert detect_mime(b"\x89PNG\r\n\x1a\nrest") == "image/png"
    assert detect_mime(b"%PDF-1.7") == "application/pdf"
    assert detect_mime(b"RIFFxxxxWEBP") == "image/webp"
    assert detect_mime(b"\x00\x00\x00\x18ftypisom") == "video/mp4"
    assert detect_mime(b"plain UTF-8 text\n") == "text/plain"


def test_detect_mime_rejects_unknown_binary() -> None:
    with pytest.raises(ValueError, match="Unsupported"):
        detect_mime(b"\x00\x01\x02\x03\xff\xfe")


def test_filename_is_display_only() -> None:
    assert sanitise_filename("../../secret.txt") == "secret.txt"
    assert sanitise_filename("C:\\temp\\photo.jpg") == "photo.jpg"
    assert sanitise_filename("..") == "evidence"


def test_stream_to_quarantine_hashes_and_content_addresses(dev_settings: Settings) -> None:
    payload = b"%PDF-1.7\nforensic evidence\n"
    result = stream_to_quarantine(
        io.BytesIO(payload),
        settings=dev_settings,
        declared_mime="application/pdf",
    )
    assert result.size_bytes == len(payload)
    assert result.sha256
    assert result.detected_mime == "application/pdf"
    assert result.storage_path.endswith(result.sha256)
    destination = dev_settings.evidence_root / result.storage_path
    assert destination.read_bytes() == payload


def test_stream_to_quarantine_enforces_size_limit(dev_settings: Settings) -> None:
    dev_settings.max_upload_bytes = 4
    with pytest.raises(ValueError, match="maximum size"):
        stream_to_quarantine(
            io.BytesIO(b"%PDF-12345"),
            settings=dev_settings,
            declared_mime="application/pdf",
        )

# fmt: on

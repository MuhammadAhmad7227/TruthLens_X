"""Safe, reproducible metadata extraction.

ExifTool is preferred when present. Fallbacks are deliberately conservative: they return only
metadata that can be extracted without guessing and identify the extractor used.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import struct
import subprocess  # nosec B404
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from app.core.config import Settings

SCHEMA_VERSION = "1.0"
EXIFTOOL_DEFAULT = "exiftool"
OFFSET_WITH_COLON_LENGTH = 5
TIFF_MAGIC = 42
MAX_IFD_DEPTH = 3
INLINE_VALUE_BYTES = 4
EXIF_IFD_POINTER_TAG = 0x8769
TYPE_ASCII = 2
TYPE_SHORT = 3
TYPE_LONG = 4

_TIMESTAMP_FIELDS = {
    "DateTimeOriginal": ("device_clock", "medium", "second"),
    "CreateDate": ("container", "medium", "second"),
    "ModifyDate": ("container", "low", "second"),
    "FileModifyDate": ("filesystem", "low", "second"),
    "DateTime": ("device_clock", "medium", "second"),
    "XMP:CreateDate": ("embedded_xmp", "medium", "second"),
    "XMP:ModifyDate": ("embedded_xmp", "low", "second"),
}


@dataclass(frozen=True)
class ExtractionResult:
    extractor: str
    extractor_version: str
    invocation_args: dict[str, Any]
    raw_tags: dict[str, Any]
    normalised: dict[str, Any]
    stripping_signals: dict[str, Any]


class MetadataExtractionError(RuntimeError):
    """Metadata extraction failed without modifying the source evidence."""


def _parse_exif_timestamp(value: str) -> dict[str, Any] | None:
    raw = value.strip()
    match = re.fullmatch(
        r"(\d{4})[:/-](\d{2})[:/-](\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:([+-]\d{2}:?\d{2}))?",
        raw,
    )
    if not match:
        return None
    year, month, day, hour, minute, second, offset = match.groups()
    try:
        dt = datetime.fromisoformat(
            f"{year}-{month}-{day}T{hour}:{minute}:{second}"
            + (
                (offset[:3] + ":" + offset[-2:])
                if offset and len(offset) == OFFSET_WITH_COLON_LENGTH
                else (offset or "")
            )
        )
    except ValueError:
        return None
    return {
        "raw_value": raw,
        "utc": dt.astimezone().isoformat() if dt.tzinfo else None,
        "original_offset": offset,
        "provenance": "device_clock",
        "reliability": "medium",
        "precision": "second",
    }


def _normalise_timestamp(field: str, value: Any) -> dict[str, Any] | None:
    if not isinstance(value, str):
        return None
    parsed = _parse_exif_timestamp(value)
    if parsed is None:
        return None
    provenance, reliability, precision = _TIMESTAMP_FIELDS.get(
        field, ("unknown", "unknown", "second")
    )
    parsed["field"] = field
    parsed["provenance"] = provenance
    parsed["reliability"] = reliability
    parsed["precision"] = precision
    return parsed


def _normalise(raw: dict[str, Any], mime: str) -> dict[str, Any]:
    dimensions: dict[str, Any] = {
        "width": raw.get("ImageWidth") or raw.get("ExifImageWidth"),
        "height": raw.get("ImageHeight") or raw.get("ExifImageHeight"),
        "unit": "px",
    }
    device = {
        "make": raw.get("Make"),
        "model": raw.get("Model"),
        "serial": raw.get("SerialNumber") or raw.get("SerialNumberIdentifier"),
        "lens": raw.get("LensModel"),
    }
    software = {
        "creator": raw.get("Software"),
        "editor": raw.get("CreatorTool"),
        "encoder_tag": raw.get("Encoder"),
    }
    author = {
        "name": raw.get("Artist") or raw.get("Author"),
        "org": raw.get("OwnerName"),
    }
    timestamps: list[dict[str, Any]] = []
    for key, value in raw.items():
        timestamp = _normalise_timestamp(key, value)
        if timestamp:
            timestamps.append(timestamp)

    distinct_timestamp_values = {item["raw_value"] for item in timestamps}
    if len(distinct_timestamp_values) > 1:
        for item in timestamps:
            item["conflict_group"] = "timestamp-1"

    latitude = raw.get("GPSLatitude")
    longitude = raw.get("GPSLongitude")
    location = None
    if latitude is not None and longitude is not None:
        location = {
            "latitude": _coordinate(latitude),
            "longitude": _coordinate(longitude),
            "datum": raw.get("GPSMapDatum") or "WGS84",
            "altitude_m": _number(raw.get("GPSAltitude")),
            "precision_digits": 6,
            "uncertainty_radius_m": None,
            "source": "exif_gps",
        }

    encoding = {
        "mime": mime,
        "codec": raw.get("Compressor") or raw.get("VideoCodec"),
        "bitrate": _number(raw.get("BitRate")),
        "sample_rate": _number(raw.get("AudioSampleRate")),
        "channels": _number(raw.get("AudioChannels")),
        "bit_depth": _number(raw.get("BitsPerSample")),
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "dimensions": dimensions,
        "duration_seconds": _number(raw.get("Duration")),
        "device": device,
        "software": software,
        "author": author,
        "timestamps": timestamps,
        "location": location,
        "encoding": encoding,
        "integrity_hints": {
            "jpeg_quality_estimate": _number(raw.get("JPEGQualityEstimate")),
            "dqt_signature": raw.get("DQTSignature"),
            "double_compression": raw.get("DoubleCompression"),
            "re_encode_likelihood": raw.get("ReEncodeLikelihood"),
        },
    }


def _number(value: Any) -> int | float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return value
    try:
        return float(str(value).split()[0])
    except (ValueError, TypeError):
        return None


def _coordinate(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.split()[0])
        except ValueError:
            return None
    return None


def _stripping_signals(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "missing_camera_make": not bool(raw.get("Make")),
        "missing_camera_model": not bool(raw.get("Model")),
        "uniform_timestamps": len(
            {
                str(v)
                for k, v in raw.items()
                if "DateTime" in k or k.endswith("Date")
                if v is not None
            }
        )
        <= 1,
        "editor_software": raw.get("Software") or raw.get("CreatorTool"),
    }


class MetadataExtractor:
    """Extract metadata using ExifTool, then safe fallbacks."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def extract(self, source: Path, mime: str) -> ExtractionResult:
        if not source.is_file():
            raise MetadataExtractionError("Evidence source is unavailable")

        exiftool = shutil.which(self.settings.exiftool_binary) or (
            str(self.settings.exiftool_binary)
            if Path(self.settings.exiftool_binary).is_file()
            else None
        )
        if exiftool and self.settings.enable_exiftool:
            try:
                return self._extract_exiftool(exiftool, source, mime)
            except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
                pass

        return self._extract_fallback(source, mime)

    def _extract_exiftool(self, executable: str, source: Path, mime: str) -> ExtractionResult:
        with tempfile.TemporaryDirectory(prefix="tlx-meta-") as workdir:
            working_copy = Path(workdir) / source.name
            shutil.copyfile(source, working_copy)
            args = [
                executable,
                "-j",
                "-G1",
                "-a",
                "-s",
                "-n",
                str(working_copy),
            ]
            completed = subprocess.run(  # nosec S603
                args,
                cwd=workdir,
                check=True,
                capture_output=True,
                text=True,
                timeout=self.settings.exiftool_timeout_seconds,
                shell=False,  # nosec B603
                env={"PATH": os.environ.get("PATH", "")},
            )
            payload = json.loads(completed.stdout)
            if not payload or not isinstance(payload[0], dict):
                raise MetadataExtractionError("ExifTool returned no metadata")
            raw = {str(k): v for k, v in payload[0].items() if k != "SourceFile"}
            version = self._version(executable)
            return ExtractionResult(
                extractor="exiftool",
                extractor_version=version,
                invocation_args={
                    "argv": [*args[:-1], "<working-copy>"],
                    "timeout_seconds": self.settings.exiftool_timeout_seconds,
                },
                raw_tags=raw,
                normalised=_normalise(raw, mime),
                stripping_signals=_stripping_signals(raw),
            )

    def _version(self, executable: str) -> str:
        completed = subprocess.run(  # nosec S603
            [executable, "-ver"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,  # nosec B603
            env={"PATH": os.environ.get("PATH", "")},
        )
        return completed.stdout.strip() or "unknown"

    def _extract_fallback(self, source: Path, mime: str) -> ExtractionResult:
        raw: dict[str, Any] = {
            "FileName": source.name,
            "FileSize": source.stat().st_size,
            "FileModifyDate": datetime.fromtimestamp(source.stat().st_mtime).isoformat(),
            "MIMEType": mime,
        }
        if mime == "image/jpeg":
            raw.update(_jpeg_basic_exif(source))
        version = "builtin-1"
        return ExtractionResult(
            extractor="pure_python",
            extractor_version=version,
            invocation_args={"argv": ["builtin"], "timeout_seconds": 0},
            raw_tags=raw,
            normalised=_normalise(raw, mime),
            stripping_signals=_stripping_signals(raw),
        )


def _jpeg_basic_exif(path: Path) -> dict[str, Any]:
    """Read a minimal TIFF/EXIF subset without third-party packages."""
    data = path.read_bytes()[: 4 * 1024 * 1024]
    marker = b"Exif\x00\x00"
    pos = data.find(marker)
    if pos < 0:
        return {}
    tiff = pos + 6
    if len(data) < tiff + 8:
        return {}
    endian = data[tiff : tiff + 2]
    if endian == b"II":
        order = "<"
    elif endian == b"MM":
        order = ">"
    else:
        return {}
    magic = struct.unpack_from(order + "H", data, tiff + 2)[0]
    if magic != TIFF_MAGIC:
        return {}
    ifd_offset = struct.unpack_from(order + "I", data, tiff + 4)[0]
    return _read_ifd(data, tiff, tiff + ifd_offset, order, 0)


def _read_ifd(data: bytes, tiff: int, offset: int, order: str, depth: int) -> dict[str, Any]:
    if depth > MAX_IFD_DEPTH or offset + 2 > len(data):
        return {}
    count = struct.unpack_from(order + "H", data, offset)[0]
    values: dict[str, Any] = {}
    tags = {
        0x010F: "Make",
        0x0110: "Model",
        0x0131: "Software",
        0x0132: "ModifyDate",
        0x9003: "DateTimeOriginal",
        0x9004: "CreateDate",
        0x8825: "GPSInfo",
    }
    for index in range(min(count, 256)):
        entry = offset + 2 + index * 12
        if entry + 12 > len(data):
            break
        tag, typ, count_value = struct.unpack_from(order + "HHI", data, entry)
        raw_value = data[entry + 8 : entry + 12]
        size = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8}.get(typ)
        if size is None:
            continue
        total = size * count_value
        if total <= INLINE_VALUE_BYTES:
            payload = raw_value[:total]
        else:
            pointer = struct.unpack(order + "I", raw_value)[0]
            start = tiff + pointer
            payload = data[start : start + total]
        if typ == TYPE_ASCII:
            value: Any = payload.rstrip(b"\x00").decode("utf-8", "replace")
        elif typ == TYPE_SHORT:
            value = struct.unpack(order + "H", payload[:2])[0] if payload else None
        elif typ == TYPE_LONG:
            value = struct.unpack(order + "I", payload[:4])[0] if payload else None
        else:
            value = payload.hex()
        name = tags.get(tag)
        if name:
            values[name] = value
        if tag == EXIF_IFD_POINTER_TAG and typ == TYPE_LONG:
            child = struct.unpack(order + "I", raw_value)[0]
            values.update(_read_ifd(data, tiff, tiff + child, order, depth + 1))
    return values

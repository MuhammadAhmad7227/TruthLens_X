from pathlib import Path

from app.core.config import Settings
from app.forensics.metadata.extractor import MetadataExtractor


def test_fallback_extraction_is_reproducible(monkeypatch, tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    source.write_bytes(b"truthlens")
    monkeypatch.setattr("app.forensics.metadata.extractor.shutil.which", lambda _: None)

    settings = Settings(
        testing=True,
        tlx_env="test",
        evidence_root=tmp_path / "evidence",
        derivatives_root=tmp_path / "derivatives",
        intake_root=tmp_path / "intake",
        quarantine_root=tmp_path / "quarantine",
    )
    result = MetadataExtractor(settings).extract(source, "application/octet-stream")

    assert result.extractor == "pure_python"
    assert result.normalised["schema_version"] == "1.0"
    assert result.raw_tags["FileName"] == "sample.bin"
    assert result.normalised["encoding"]["mime"] == "application/octet-stream"


def test_timestamp_conflicts_are_retained() -> None:
    from app.forensics.metadata.extractor import _normalise

    raw = {
        "DateTimeOriginal": "2026:03:14 18:22:07",
        "ModifyDate": "2026:03:15 09:00:00",
        "Make": "Example",
        "Model": "Camera",
    }
    timestamps = _normalise(raw, "image/jpeg")["timestamps"]

    assert len(timestamps) == 2
    assert {item["field"] for item in timestamps} == {"DateTimeOriginal", "ModifyDate"}

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.forensics.contracts.results import validate_result


def _valid_payload() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "pipeline": "image.ela",
        "pipeline_version": "1.0.0",
        "summary": "Observed an image-level indicator.",
        "indicators": [{"code": "ela_region", "value": 0.8}],
        "provenance": {
            "engine": "truthlens-test",
            "engine_version": "0.1.0",
            "source_sha256": "a" * 64,
            "parameters": {"quality": 90},
        },
        "limitations_code": "ELA",
        "requires_human_verification": True,
    }


def test_valid_result_contract_is_accepted() -> None:
    result = validate_result(_valid_payload())
    assert result.provenance.source_sha256 == "a" * 64


def test_missing_provenance_is_rejected() -> None:
    payload = _valid_payload()
    payload.pop("provenance")
    with pytest.raises(ValidationError):
        validate_result(payload)


def test_missing_limitations_is_rejected() -> None:
    payload = _valid_payload()
    payload.pop("limitations_code")
    with pytest.raises(ValidationError):
        validate_result(payload)


def test_machine_confirmation_is_rejected() -> None:
    payload = _valid_payload()
    payload["requires_human_verification"] = False
    with pytest.raises(ValidationError):
        validate_result(payload)

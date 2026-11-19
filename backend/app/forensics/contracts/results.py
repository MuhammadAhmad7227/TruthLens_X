"""Versioned, fail-closed forensic result contract."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

RESULT_SCHEMA_VERSION = "1.0"


class Provenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    engine: str = Field(min_length=1, max_length=200)
    engine_version: str = Field(min_length=1, max_length=100)
    source_sha256: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        description="SHA-256 of the evidence bytes used for analysis.",
    )
    parameters: dict[str, Any] = Field(default_factory=dict)


class ForensicResultContract(BaseModel):
    """AR-1..AR-8 safe envelope accepted before result persistence."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default=RESULT_SCHEMA_VERSION)
    pipeline: str = Field(min_length=1, max_length=200)
    pipeline_version: str = Field(min_length=1, max_length=100)
    summary: str = Field(min_length=1, max_length=10000)
    indicators: list[dict[str, Any]] = Field(default_factory=list)
    provenance: Provenance
    limitations_code: str = Field(min_length=1, max_length=200)
    requires_human_verification: bool = True

    @field_validator("schema_version")
    @classmethod
    def schema_must_match(cls, value: str) -> str:
        if value != RESULT_SCHEMA_VERSION:
            raise ValueError(f"Unsupported result schema version: {value}")
        return value

    @field_validator("requires_human_verification")
    @classmethod
    def verification_is_mandatory(cls, value: bool) -> bool:
        if not value:
            raise ValueError("Forensic results always require human verification")
        return value


def validate_result(payload: Any) -> ForensicResultContract:
    """Reject a pipeline output that lacks provenance or limitations."""
    return ForensicResultContract.model_validate(payload)

"""Pydantic request/response contracts for authentication endpoints."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=1024)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: UUID
    mfa_required: bool = False


class MfaVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    challenge_token: str = Field(min_length=20)
    code: str = Field(pattern=r"^[0-9]{6}$")


class MfaEnrollResponse(BaseModel):
    secret: str
    provisioning_uri: str


class MfaCodeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(pattern=r"^[0-9]{6}$")


class PasswordChangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=12, max_length=1024)


class MfaDisableRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str = Field(min_length=1, max_length=1024)


class MeResponse(BaseModel):
    id: UUID
    email: str
    username: str | None
    full_name: str
    global_role: str
    roles: list[str]
    status: str
    mfa_enabled: bool
    mfa_required_by_policy: bool

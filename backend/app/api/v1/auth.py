"""Authentication/session HTTP endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, Request, Response, status

from app.api.v1.auth_deps import CurrentPrincipal
from app.api.v1.auth_schemas import (
    LoginRequest,
    LoginResponse,
    MeResponse,
    MfaCodeRequest,
    MfaDisableRequest,
    MfaEnrollResponse,
    MfaVerifyRequest,
    PasswordChangeRequest,
    UpdateMeRequest,
)
from app.api.v1.deps import SessionDep
from app.core.config import Settings, get_settings
from app.core.errors import MFARequiredError, UnauthenticatedError
from app.services import auth as auth_service

router = APIRouter(prefix="/auth", tags=["auth"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _set_refresh_cookie(response: Response, token: str, settings: Settings) -> None:
    response.set_cookie(
        "tlx_refresh",
        token,
        max_age=settings.refresh_token_ttl_seconds,
        httponly=settings.cookie_httponly,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path="/api/v1/auth",
    )


@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    session: SessionDep,
    settings: Annotated[Settings, Depends(get_settings)],
) -> LoginResponse:
    try:
        user, row, access, refresh = auth_service.login(
            session,
            settings,
            email=payload.email,
            password=payload.password,
            ip=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
            request_id=getattr(request.state, "request_id", None),
        )
    except MFARequiredError as exc:
        challenge = exc.challenge_token or ""
        response.headers["X-MFA-Challenge"] = challenge
        raise
    if user is None or row is None or access is None or refresh is None:
        raise RuntimeError("authentication service returned an incomplete login result")
    _set_refresh_cookie(response, refresh, settings)
    return LoginResponse(
        access_token=access,
        expires_in=settings.access_token_ttl_seconds,
        user_id=user.id,
    )


@router.post("/mfa/verify", response_model=LoginResponse)
def verify_mfa(
    payload: MfaVerifyRequest,
    request: Request,
    response: Response,
    session: SessionDep,
    settings: Annotated[Settings, Depends(get_settings)],
) -> LoginResponse:
    user, _row, access, refresh = auth_service.verify_mfa(
        session,
        settings,
        challenge_token=payload.challenge_token,
        code=payload.code,
        ip=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        request_id=getattr(request.state, "request_id", None),
    )
    _set_refresh_cookie(response, refresh, settings)
    return LoginResponse(access_token=access, expires_in=settings.access_token_ttl_seconds, user_id=user.id)


@router.post("/refresh", response_model=LoginResponse)
def refresh(
    request: Request,
    response: Response,
    session: SessionDep,
    settings: Annotated[Settings, Depends(get_settings)],
    refresh_token: str | None = Cookie(default=None, alias="tlx_refresh"),
) -> LoginResponse:
    if not refresh_token:
        raise UnauthenticatedError("Refresh cookie is missing")
    user, _row, access, new_refresh = auth_service.refresh(
        session,
        settings,
        raw_refresh_token=refresh_token,
        ip=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        request_id=getattr(request.state, "request_id", None),
    )
    _set_refresh_cookie(response, new_refresh, settings)
    return LoginResponse(access_token=access, expires_in=settings.access_token_ttl_seconds, user_id=user.id)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, principal: CurrentPrincipal, session: SessionDep, response: Response) -> Response:
    auth_service.logout(
        session,
        current_session=principal.session,
        user=principal.user,
        jti=str(principal.claims["jti"]),
        token_exp=int(principal.claims["exp"]),
        request_id=getattr(request.state, "request_id", None),
        ip=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    response.delete_cookie("tlx_refresh", path="/api/v1/auth")
    return response


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
def logout_all(request: Request, principal: CurrentPrincipal, session: SessionDep, response: Response) -> Response:
    auth_service.logout_all(
        session,
        user=principal.user,
        jti=str(principal.claims["jti"]),
        token_exp=int(principal.claims["exp"]),
        request_id=getattr(request.state, "request_id", None),
        ip=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    response.delete_cookie("tlx_refresh", path="/api/v1/auth")
    return response


@router.get("/me", response_model=MeResponse)
def me(principal: CurrentPrincipal) -> MeResponse:
    user = principal.user
    return MeResponse(
        id=user.id,
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        global_role=user.global_role.value,
        roles=auth_service.user_roles(user),
        status=user.status.value,
        mfa_enabled=user.mfa_enabled,
        mfa_required_by_policy=user.mfa_required_by_policy,
    )


@router.post("/password/change", status_code=status.HTTP_204_NO_CONTENT)
def password_change(
    payload: PasswordChangeRequest,
    request: Request,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> Response:
    auth_service.change_password(
        session,
        user=principal.user,
        current_password=payload.current_password,
        new_password=payload.new_password,
        request_id=getattr(request.state, "request_id", None),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/mfa/enrol", response_model=MfaEnrollResponse)
def mfa_enrol(request: Request, principal: CurrentPrincipal, session: SessionDep, settings: Annotated[Settings, Depends(get_settings)]) -> MfaEnrollResponse:
    secret, uri = auth_service.begin_mfa_enrolment(
        session, settings, user=principal.user, request_id=getattr(request.state, "request_id", None)
    )
    return MfaEnrollResponse(secret=secret, provisioning_uri=uri)


@router.post("/mfa/confirm", status_code=status.HTTP_204_NO_CONTENT)
def mfa_confirm(payload: MfaCodeRequest, request: Request, principal: CurrentPrincipal, session: SessionDep, settings: Annotated[Settings, get_settings]) -> Response:
    auth_service.confirm_mfa_enrolment(
        session, settings, user=principal.user, code=payload.code, request_id=getattr(request.state, "request_id", None)
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/mfa", status_code=status.HTTP_204_NO_CONTENT)
def mfa_disable(payload: MfaDisableRequest, request: Request, principal: CurrentPrincipal, session: SessionDep) -> Response:
    auth_service.disable_mfa(
        session, user=principal.user, password=payload.password, request_id=getattr(request.state, "request_id", None)
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.patch("/me", response_model=MeResponse)
def update_me(payload: UpdateMeRequest, request: Request, principal: CurrentPrincipal, session: SessionDep) -> MeResponse:
    auth_service.update_profile(
        session,
        user=principal.user,
        full_name=payload.full_name,
        request_id=getattr(request.state, "request_id", None),
    )
    return me(principal)

"""M4 API contract checks for case endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_case_routes_are_registered_and_case_scoped(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    expected = {
        "/api/v1/cases",
        "/api/v1/cases:by-number/{case_number}",
        "/api/v1/cases/{case_id}",
        "/api/v1/cases/{case_id}:transition",
        "/api/v1/cases/{case_id}/dashboard",
        "/api/v1/cases/{case_id}/members",
        "/api/v1/cases/{case_id}/members/{user_id}",
    }
    assert expected <= set(paths)
    assert "post" in paths["/api/v1/cases"]
    assert "patch" in paths["/api/v1/cases/{case_id}"]
    assert "post" in paths["/api/v1/cases/{case_id}:transition"]
    assert "get" in paths["/api/v1/cases/{case_id}/members"]


def test_case_write_schemas_forbid_unknown_fields(client: TestClient) -> None:
    schemas = client.get("/openapi.json").json()["components"]["schemas"]
    assert schemas["CaseCreateRequest"]["additionalProperties"] is False
    assert schemas["CaseUpdateRequest"]["additionalProperties"] is False
    assert schemas["CaseMemberCreateRequest"]["additionalProperties"] is False
    assert schemas["CaseMemberUpdateRequest"]["additionalProperties"] is False

from __future__ import annotations

from uuid import uuid4

import pytest

from app.forensics.pipelines.core import PipelineInput, run_pipeline
from app.forensics.pipelines.milestone_registry import PIPELINE_CATALOGUE
from app.release.verification import release_ready
from app.security.assurance import container_hardening_config
from app.services.admin_monitoring import validate_setting
from app.services.assistant import grounded_answer
from app.services.comparison import cosine, hamming_hex
from app.services.graph_timeline import stable_layout
from app.services.reports import manifest_hash


def test_every_catalogue_pipeline_has_an_adapter():
    for name in {p for values in PIPELINE_CATALOGUE.values() for p in values}:
        output = run_pipeline(PipelineInput(name, "a" * 64, b"fixture", {}))
        assert output.result.requires_human_verification is True
        assert output.result.provenance.source_sha256 == "a" * 64
        assert output.result.limitations_code


def test_comparison_math():
    assert hamming_hex("00ff", "00f0") == 1
    assert cosine([1.0, 0.0], [1.0, 0.0]) == pytest.approx(1.0)


def test_graph_layout_is_stable():
    ids = [uuid4(), uuid4()]
    assert stable_layout(ids, seed=7) == stable_layout(ids, seed=7)


def test_assistant_is_unsupported_without_retrieval():
    answer = grounded_answer("question", [])
    assert answer.unsupported is True
    assert answer.citations == ()


def test_report_manifest_is_deterministic():
    manifest = {"b": 2, "a": 1}
    assert manifest_hash(manifest) == manifest_hash({"a": 1, "b": 2})


def test_settings_are_allowlisted():
    assert validate_setting("external_ai_enabled", False) is False
    with pytest.raises(ValueError):
        validate_setting("secret_key", "value")


def test_hardening():
    config = container_hardening_config()
    assert config["non_root"] is True
    assert config["read_only_root"] is True


def test_release_gate():
    assert release_ready({"e2e": True, "backup": True})
    assert not release_ready({"e2e": True, "backup": False})
 TLX_TEST_DATABASE_URL: ***localhost:5432/truthlens_ci
 pythonLocation: /opt/hostedtoolcache/Python/3.11.18/x64
 PKG_CONFIG_PATH: /opt/hostedtoolcache/Python/3.11.18/x64/lib/pkgconfig
 Python_ROOT_DIR: /opt/hostedtoolcache/Python/3.11.18/x64
 Python2_ROOT_DIR: /opt/hostedtoolcache/Python/3.11.18/x64
 Python3_ROOT_DIR: /opt/hostedtoolcache/Python/3.11.18/x64
 LD_LIBRARY_PATH: /opt/hostedtoolcache/Python/3.11.18/x64/lib
 TLX_TEST_DATABASE_URL: ***localhost:5432/truthlens_ci
 pythonLocation: /opt/hostedtoolcache/Python/3.11.18/x64
 PKG_CONFIG_PATH: /opt/hostedtoolcache/Python/3.11.18/x64/lib/pkgconfig
 Python_ROOT_DIR: /opt/hostedtoolcache/Python/3.11.18/x64
 Python2_ROOT_DIR: /opt/hostedtoolcache/Python/3.11.18/x64
 Python3_ROOT_DIR: /opt/hostedtoolcache/Python/3.11.18/x64
 LD_LIBRARY_PATH: /opt/hostedtoolcache/Python/3.11.18/x64/lib

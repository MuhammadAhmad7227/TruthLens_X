"""Configuration validation: fail-closed behaviour and the ratified policy invariants.

Each test names the ADR or security rule it enforces, so a failure points at the decision that would
be violated rather than at an opaque assertion. A configuration rule with no test is a rule that will
quietly stop being enforced.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from app.core.config import ConfigurationError, Environment, Settings, _field_for


def _kwargs(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"tlx_env": Environment.DEVELOPMENT}
    base.update(overrides)
    return base


# ══════════════════════════════════════════════════════════════════════════════
# Fail closed on secrets
# ══════════════════════════════════════════════════════════════════════════════
class TestFailClosedInProduction:
    """SECURITY_ARCHITECTURE §5.3: a missing or placeholder secret must abort startup."""

    def test_missing_secret_key_is_refused(self, prod_settings: dict[str, Any]) -> None:
        prod_settings.pop("secret_key")
        with pytest.raises(ConfigurationError, match="SECRET_KEY is required"):
            Settings(**prod_settings)

    @pytest.mark.parametrize(
        "placeholder", ["", "changeme", "CHANGE_ME", "dev", "secret", "xxxxxxxx", "password", "   "]
    )
    def test_placeholder_secret_is_refused(
        self, prod_settings: dict[str, Any], placeholder: str
    ) -> None:
        prod_settings["secret_key"] = placeholder
        with pytest.raises(ConfigurationError, match="must not be a placeholder"):
            Settings(**prod_settings)

    @pytest.mark.parametrize("weak", ["a" * 48, "x" * 64, "0" * 32, "A" * 40])
    def test_single_repeated_character_secret_is_a_placeholder(
        self, prod_settings: dict[str, Any], weak: str
    ) -> None:
        """A low-entropy repeated-character secret is refused despite being long enough.

        Length is the check most implementations make; entropy is the property that actually matters.
        """
        prod_settings["secret_key"] = weak
        with pytest.raises(ConfigurationError, match="must not be a placeholder"):
            Settings(**prod_settings)

    def test_short_secret_is_refused(self, prod_settings: dict[str, Any]) -> None:
        prod_settings["signed_url_key"] = "tooshort-but-not-repeated"
        with pytest.raises(ConfigurationError, match="at least 32 characters"):
            Settings(**prod_settings)

    def test_missing_database_url_is_refused(self, prod_settings: dict[str, Any]) -> None:
        prod_settings["database_url"] = None
        with pytest.raises(ConfigurationError, match="DATABASE_URL must be set"):
            Settings(**prod_settings)

    def test_missing_redis_url_is_refused(self, prod_settings: dict[str, Any]) -> None:
        prod_settings["redis_url"] = None
        with pytest.raises(ConfigurationError, match="REDIS_URL must be set"):
            Settings(**prod_settings)

    def test_error_names_the_variable_but_never_echoes_the_value(
        self, prod_settings: dict[str, Any]
    ) -> None:
        """An error message reaches logs, consoles and issue trackers. It must not carry the secret."""
        prod_settings["secret_key"] = "hunter2-super-secret-value"
        with pytest.raises(ConfigurationError) as excinfo:
            Settings(**prod_settings)
        message = str(excinfo.value)
        assert "SECRET_KEY" in message, "the operator must be told which variable to fix"
        assert "hunter2-super-secret-value" not in message, "the value must never be echoed"

    def test_pem_key_is_not_rejected_for_being_long_enough(
        self, prod_settings: dict[str, Any]
    ) -> None:
        """A PEM block is under 32 chars of entropy by the naive measure but is a valid key."""
        settings = Settings(**prod_settings)
        assert settings.jwt_private_key is not None
        assert settings.jwt_private_key.startswith("-----BEGIN")


class TestProductionHardening:
    def test_debug_refused_in_production(self, prod_settings: dict[str, Any]) -> None:
        prod_settings["debug"] = True
        with pytest.raises(ConfigurationError, match="DEBUG=true is refused"):
            Settings(**prod_settings)

    def test_testing_refused_in_production(self, prod_settings: dict[str, Any]) -> None:
        prod_settings["testing"] = True
        with pytest.raises(ConfigurationError, match="TESTING=true is refused"):
            Settings(**prod_settings)

    def test_console_logs_refused_in_production(self, prod_settings: dict[str, Any]) -> None:
        prod_settings["log_format"] = "console"
        with pytest.raises(ConfigurationError, match="LOG_FORMAT=console is refused"):
            Settings(**prod_settings)

    def test_db_echo_refused_in_production(self, prod_settings: dict[str, Any]) -> None:
        prod_settings["db_echo"] = True
        with pytest.raises(ConfigurationError, match="DB_ECHO=true is refused"):
            Settings(**prod_settings)

    def test_preflight_required_in_production(self, prod_settings: dict[str, Any]) -> None:
        """ADR-0006 §5.4: the encrypted-volume preflight must block startup in production."""
        prod_settings["preflight_required"] = False
        with pytest.raises(ConfigurationError, match="PREFLIGHT_REQUIRED=false is refused"):
            Settings(**prod_settings)

    def test_valid_production_configuration_is_accepted(
        self, prod_settings: dict[str, Any]
    ) -> None:
        settings = Settings(**prod_settings)
        assert settings.tlx_env is Environment.PRODUCTION
        assert settings.ephemeral_secrets == [], "production must never generate secrets"
        assert settings.config_warnings  # retention unset still warns, which is correct

    def test_all_production_rules_fire_together(self, prod_settings: dict[str, Any]) -> None:
        """Every violation is reported at once, so an operator fixes them in one pass."""
        prod_settings.update(
            debug=True, db_echo=True, log_format="console", preflight_required=False
        )
        prod_settings.pop("secret_key")
        with pytest.raises(ConfigurationError) as excinfo:
            Settings(**prod_settings)
        message = str(excinfo.value)
        for fragment in ("DEBUG", "DB_ECHO", "LOG_FORMAT", "PREFLIGHT_REQUIRED", "SECRET_KEY"):
            assert fragment in message


class TestEphemeralSecretsOutsideProduction:
    """Dev/test generate throwaway secrets and SAY SO, rather than shipping a weak default."""

    def test_missing_secrets_are_generated_and_reported(self) -> None:
        settings = Settings(**_kwargs())
        assert set(settings.ephemeral_secrets) >= {
            "SECRET_KEY",
            "SIGNED_URL_KEY",
            "JWT_PRIVATE_KEY",
            "JWT_PUBLIC_KEY",
        }
        assert any("EPHEMERAL" in warning for warning in settings.config_warnings)
        assert settings.secret_key is not None
        assert len(settings.secret_key) > 40

    def test_generated_secrets_are_unique_per_instance(self) -> None:
        first = Settings(**_kwargs())
        second = Settings(**_kwargs())
        assert first.secret_key != second.secret_key

    def test_supplied_secrets_are_not_overwritten(self) -> None:
        settings = Settings(**_kwargs(secret_key="an-actually-supplied-value-0123456789"))
        assert settings.secret_key == "an-actually-supplied-value-0123456789"
        assert "SECRET_KEY" not in settings.ephemeral_secrets

    def test_staging_also_fails_closed(self, prod_settings: dict[str, Any]) -> None:
        """Staging runs on real infrastructure; a control only enforced in production is untested."""
        prod_settings["tlx_env"] = Environment.STAGING
        prod_settings.pop("secret_key")
        with pytest.raises(ConfigurationError, match="SECRET_KEY is required"):
            Settings(**prod_settings)

    def test_production_never_generates(self, prod_settings: dict[str, Any]) -> None:
        prod_settings.pop("signed_url_key")
        with pytest.raises(ConfigurationError):
            Settings(**prod_settings)


# ══════════════════════════════════════════════════════════════════════════════
# AI policy invariants — ADR-0007 / ADR-0021
# ══════════════════════════════════════════════════════════════════════════════
class TestAIPolicyInvariants:
    def test_external_provider_requires_the_master_gate(self) -> None:
        with pytest.raises(
            ConfigurationError, match="LLM_PROVIDER=external requires ENABLE_EXTERNAL_AI"
        ):
            Settings(**_kwargs(llm_provider="external", llm_external_api_key="sk-real-key-value"))

    def test_confirmation_cannot_be_disabled_in_production(
        self, prod_settings: dict[str, Any]
    ) -> None:
        prod_settings["llm_egress_confirmation_required"] = False
        with pytest.raises(
            ConfigurationError, match="LLM_EGRESS_CONFIRMATION_REQUIRED=false is refused"
        ):
            Settings(**prod_settings)

    def test_egress_flag_requires_the_master_gate(self) -> None:
        with pytest.raises(ConfigurationError, match="LLM_ALLOW_EXTERNAL_EGRESS=true requires"):
            Settings(**_kwargs(llm_allow_external_egress=True))

    def test_external_provider_requires_a_real_api_key(self) -> None:
        with pytest.raises(ConfigurationError, match="requires a real LLM_EXTERNAL_API_KEY"):
            Settings(
                **_kwargs(enable_external_ai=True, llm_provider="external", llm_external_api_key="")
            )

    def test_default_posture_disables_all_external_ai(self) -> None:
        settings = Settings(**_kwargs())
        assert settings.enable_external_ai is False
        assert settings.llm_provider == "local"
        assert settings.external_ai_effectively_enabled is False
        # ADR-0021: an empty allowlist means nothing may be transmitted even if AI is enabled.
        assert settings.external_ai_allowed_categories == ()

    def test_category_allowlist_parses_and_strips(self) -> None:
        settings = Settings(
            **_kwargs(
                enable_external_ai=True,
                llm_external_allowed_categories="finding_summary, ,transcript_excerpt ,",
            )
        )
        assert settings.external_ai_allowed_categories == ("finding_summary", "transcript_excerpt")

    def test_effectively_enabled_requires_all_switches_plus_a_key(self) -> None:
        settings = Settings(
            **_kwargs(
                enable_external_ai=True,
                llm_provider="external",
                llm_allow_external_egress=True,
                llm_external_api_key="sk-a-real-provider-key",
            )
        )
        assert settings.external_ai_effectively_enabled is True

    def test_dropping_the_egress_flag_disables_egress(self) -> None:
        """Two of the three switches set is not enough."""
        settings = Settings(
            **_kwargs(
                enable_external_ai=True,
                llm_provider="external",
                llm_allow_external_egress=False,
                llm_external_api_key="sk-a-real-provider-key",
            )
        )
        assert settings.external_ai_effectively_enabled is False

    def test_local_provider_never_reports_egress_enabled(self) -> None:
        """Even with the gate and the egress flag open, a local provider transmits nothing."""
        settings = Settings(
            **_kwargs(
                enable_external_ai=True,
                llm_provider="local",
                llm_allow_external_egress=True,
            )
        )
        assert settings.external_ai_effectively_enabled is False

    def test_grant_max_days_cannot_exceed_thirty(self) -> None:
        """ADR-0021: the 30-day bound is enforced here AND by a database CHECK."""
        with pytest.raises(ValidationError, match="less than or equal to 30"):
            Settings(**_kwargs(llm_external_grant_max_days=365))


# ══════════════════════════════════════════════════════════════════════════════
# Egress master switch — ADR-0012
# ══════════════════════════════════════════════════════════════════════════════
class TestEgressMasterSwitch:
    def test_online_geocoding_requires_the_master_switch(self) -> None:
        with pytest.raises(ConfigurationError, match="ENABLE_ONLINE_GEOCODING=true requires"):
            Settings(**_kwargs(enable_online_geocoding=True))

    def test_model_download_requires_the_master_switch(self) -> None:
        with pytest.raises(ConfigurationError, match="ALLOW_MODEL_DOWNLOAD=true requires"):
            Settings(**_kwargs(allow_model_download=True))

    def test_av_updates_require_av_scan(self) -> None:
        """ADR-0014: updating signatures for a scanner that is not running is pointless egress."""
        with pytest.raises(
            ConfigurationError, match="ENABLE_AV_UPDATES=true requires ENABLE_AV_SCAN"
        ):
            Settings(**_kwargs(enable_av_updates=True))

    def test_master_switch_permits_the_feature_switches(self) -> None:
        settings = Settings(
            **_kwargs(
                enable_external_enrichment=True,
                enable_online_geocoding=True,
                allow_model_download=True,
            )
        )
        assert settings.enable_online_geocoding is True
        assert settings.allow_model_download is True

    def test_no_egress_by_default(self) -> None:
        """The default posture must be provably closed — one read answers 'does this talk out?'."""
        settings = Settings(**_kwargs())
        assert settings.enable_external_enrichment is False
        assert settings.enable_online_geocoding is False
        assert settings.allow_model_download is False
        assert settings.enable_av_scan is False
        assert settings.enable_av_updates is False


# ══════════════════════════════════════════════════════════════════════════════
# ALPR — ADR-0013
# ══════════════════════════════════════════════════════════════════════════════
class TestAlprHardDisable:
    """No external vehicle-registry lookup exists, in ANY environment."""

    @pytest.mark.parametrize(
        "env", [Environment.DEVELOPMENT, Environment.TEST, Environment.STAGING]
    )
    def test_registry_lookup_is_refused_outside_production(self, env: Environment) -> None:
        with pytest.raises(ConfigurationError, match="ADR-0013 hard-disables"):
            Settings(**_kwargs(tlx_env=env, alpr_allow_registry_lookup=True))

    def test_registry_lookup_is_refused_in_production(self, prod_settings: dict[str, Any]) -> None:
        prod_settings["alpr_allow_registry_lookup"] = True
        with pytest.raises(ConfigurationError, match="ADR-0013 hard-disables"):
            Settings(**prod_settings)

    def test_jurisdiction_has_no_default(self) -> None:
        """Inferring jurisdiction from deployment geography is exactly the wrong assumption."""
        assert Settings(**_kwargs()).alpr_jurisdiction == ""


# ══════════════════════════════════════════════════════════════════════════════
# Encryption and storage — ADR-0006 / ADR-0011
# ══════════════════════════════════════════════════════════════════════════════
class TestEncryptionAndStorage:
    def test_envelope_encryption_is_refused_in_v1(self) -> None:
        """ADR-0006: accepting a value the code cannot honour would be a false security claim."""
        with pytest.raises(ConfigurationError, match="NOT IMPLEMENTED in v1"):
            Settings(**_kwargs(evidence_encryption="aes256gcm_envelope"))

    def test_encryption_disabled_is_the_only_accepted_value(self) -> None:
        assert Settings(**_kwargs()).evidence_encryption == "disabled"

    def test_s3_backend_is_refused_in_v1(self) -> None:
        """ADR-0011: no S3 code ships, so refuse rather than pretend the option exists."""
        with pytest.raises(ConfigurationError, match="not available in v1"):
            Settings(**_kwargs(storage_backend="s3"))

    def test_overlapping_storage_roots_are_refused(self, storage_roots: dict[str, Any]) -> None:
        """A derivatives purge must never be able to resolve into the originals tree."""
        storage_roots["derivatives_root"] = storage_roots["evidence_root"] / "derivatives"
        with pytest.raises(ConfigurationError, match="must not overlap"):
            Settings(**_kwargs(**storage_roots))

    def test_identical_storage_roots_are_refused(self, storage_roots: dict[str, Any]) -> None:
        storage_roots["intake_root"] = storage_roots["evidence_root"]
        with pytest.raises(ConfigurationError, match="must not be the same path"):
            Settings(**_kwargs(**storage_roots))

    def test_relative_storage_root_is_refused(self) -> None:
        with pytest.raises(ConfigurationError, match="must be an absolute path"):
            Settings(**_kwargs(evidence_root="relative/originals"))

    def test_disjoint_absolute_roots_are_accepted(self, storage_roots: dict[str, Any]) -> None:
        settings = Settings(**_kwargs(**storage_roots))
        assert settings.evidence_root.is_absolute()
        assert settings.derivatives_root.is_absolute()


# ══════════════════════════════════════════════════════════════════════════════
# Gazetteer and retention — ADR-0015 / ADR-0020
# ══════════════════════════════════════════════════════════════════════════════
class TestGazetteerAndRetention:
    def test_gazetteer_requires_attribution_when_enabled(self) -> None:
        """ADR-0015: the dataset licence is unverified (L-7), so attribution is mandatory."""
        with pytest.raises(ConfigurationError, match="requires GAZETTEER_ATTRIBUTION"):
            Settings(**_kwargs(gazetteer_enabled=True))

    def test_gazetteer_is_disabled_by_default(self) -> None:
        assert Settings(**_kwargs()).gazetteer_enabled is False

    def test_gazetteer_enabled_with_attribution_is_accepted(self) -> None:
        settings = Settings(
            **_kwargs(gazetteer_enabled=True, gazetteer_attribution="Data (c) example provider")
        )
        assert settings.gazetteer_enabled is True

    def test_retention_unset_is_allowed_and_reported(self) -> None:
        """ADR-0020: no default statutory period; unset means delete nothing."""
        settings = Settings(**_kwargs())
        assert settings.retention_statutory_days is None
        assert settings.retention_configured is False
        assert any("RETENTION_STATUTORY_DAYS" in w for w in settings.config_warnings)
        assert any("DELETE NOTHING" in w for w in settings.config_warnings)

    def test_retention_configured_clears_the_warning(self) -> None:
        settings = Settings(**_kwargs(retention_statutory_days=2555))
        assert settings.retention_configured is True
        assert not any("RETENTION_STATUTORY_DAYS" in w for w in settings.config_warnings)


# ══════════════════════════════════════════════════════════════════════════════
# Copyleft flags — ADR-0001
# ══════════════════════════════════════════════════════════════════════════════
class TestCopyleftFlagWarnings:
    @pytest.mark.parametrize(
        ("flag", "licence"),
        [
            ("enable_ultralytics", "AGPL-3.0"),
            ("enable_agpl_pymupdf", "AGPL-3.0"),
            ("enable_poppler", "GPL-2.0+"),
        ],
    )
    def test_enabling_a_copyleft_flag_warns(self, flag: str, licence: str) -> None:
        """A copyleft component is never activated silently."""
        settings = Settings(**_kwargs(**{flag: True}))
        assert any("copyleft" in w and licence in w for w in settings.config_warnings)

    def test_av_scan_warns_about_gpl(self) -> None:
        settings = Settings(**_kwargs(enable_external_enrichment=True, enable_av_scan=True))
        assert any("GPL-2.0" in w for w in settings.config_warnings)

    def test_all_copyleft_flags_default_to_false(self) -> None:
        settings = Settings(**_kwargs())
        assert settings.enable_ultralytics is False
        assert settings.enable_agpl_pymupdf is False
        assert settings.enable_poppler is False
        assert settings.enable_av_scan is False

    def test_exiftool_is_the_one_flag_that_defaults_true(self) -> None:
        """ADR-0003: subprocess-isolated, removable, with a pure-Python fallback."""
        assert Settings(**_kwargs()).enable_exiftool is True


# ══════════════════════════════════════════════════════════════════════════════
# Field validation
# ══════════════════════════════════════════════════════════════════════════════
class TestFieldValidation:
    @pytest.mark.parametrize("bad", ["trace", "verbose", ""])
    def test_invalid_log_level_is_refused(self, bad: str) -> None:
        with pytest.raises(ConfigurationError, match="LOG_LEVEL must be one of"):
            Settings(**_kwargs(log_level=bad))

    def test_log_level_is_normalised_to_uppercase(self) -> None:
        assert Settings(**_kwargs(log_level="warning")).log_level == "WARNING"

    def test_invalid_log_format_is_refused(self) -> None:
        with pytest.raises(ConfigurationError, match="LOG_FORMAT must be"):
            Settings(**_kwargs(log_format="syslog"))

    def test_timezone_must_be_utc(self) -> None:
        """Timestamps are evidence; a local timezone makes every recorded time ambiguous."""
        with pytest.raises(ConfigurationError, match="TZ must be UTC"):
            Settings(**_kwargs(timezone="Asia/Karachi"))

    def test_access_token_ttl_cannot_exceed_fifteen_minutes(self) -> None:
        with pytest.raises(ValidationError, match="less than or equal to 900"):
            Settings(**_kwargs(access_token_ttl_seconds=3600))

    def test_signed_url_ttl_cannot_exceed_fifteen_minutes(self) -> None:
        """ADR-0004: signed evidence URLs are short-lived by design."""
        with pytest.raises(ValidationError, match="less than or equal to 900"):
            Settings(**_kwargs(signed_url_ttl_seconds=5000))

    def test_temperature_defaults_to_deterministic(self) -> None:
        """An evidential context is not a creative one."""
        assert Settings(**_kwargs()).llm_temperature == 0.0

    def test_environment_enum_parses_and_reports_prod_like(self) -> None:
        assert Environment.STAGING.is_prod_like is True
        assert Environment.PRODUCTION.is_prod_like is True
        assert Environment.DEVELOPMENT.is_prod_like is False
        assert Environment.TEST.is_prod_like is False


# ══════════════════════════════════════════════════════════════════════════════
# Secret reporting
# ══════════════════════════════════════════════════════════════════════════════
class TestSecretReporting:
    def test_secret_names_set_returns_booleans_never_values(self) -> None:
        settings = Settings(
            **_kwargs(
                secret_key="a-real-value-0123456789abcdef",
                signed_url_key="b-real-value-0123456789abcdef",
            )
        )
        report = settings.secret_names_set()
        assert set(report) == {
            "SECRET_KEY",
            "SIGNED_URL_KEY",
            "JWT_PRIVATE_KEY",
            "JWT_PUBLIC_KEY",
            "ENCRYPTION_KEY",
        }
        assert all(isinstance(value, bool) for value in report.values())
        assert report["SECRET_KEY"] is True
        # The value must not appear anywhere in the report structure, however serialised.
        assert "a-real-value-0123456789abcdef" not in str(report)

    def test_unset_secret_reports_false(self) -> None:
        settings = Settings(**_kwargs(encryption_key=None))
        # encryption_key is ephemeral-eligible, so it is generated; use a placeholder instead
        assert settings.secret_names_set()["ENCRYPTION_KEY"] is True

    def test_alias_map_matches_env_example_names(self) -> None:
        """The documented variable name and the code must not drift apart."""
        assert _field_for("enable_agpl_pymupdf") == "ENABLE_AGPL_PYMuPDF"
        assert _field_for("tlx_env") == "TLX_ENV"
        assert _field_for("retention_statutory_days") == "RETENTION_STATUTORY_DAYS"


class TestWebRootIsolation:
    """`.env.example` asserts NGINX_DOC_ROOT never references EVIDENCE_MOUNT_POINT.

    This is the cheapest authorisation bypass available: a static file server rooted at the evidence
    tree serves every original to anyone who can reach the host — no session, no capability check,
    no signed URL (ADR-0004, SECURITY_ARCHITECTURE §5).
    """

    def test_the_documented_defaults_are_disjoint(self) -> None:
        settings = Settings(tlx_env=Environment.DEVELOPMENT)
        assert settings.nginx_doc_root == Path("/usr/share/nginx/html")
        assert settings.evidence_mount_point == Path("/srv/truthlens")
        assert not settings.nginx_doc_root.is_relative_to(settings.evidence_mount_point)

    @pytest.mark.parametrize(
        ("doc_root", "mount", "match"),
        [
            # The web root inside the evidence volume.
            ("/srv/truthlens/web", "/srv/truthlens", "must not be inside EVIDENCE_MOUNT_POINT"),
            # The evidence volume inside the web root — equally fatal, opposite direction.
            ("/srv", "/srv/truthlens", "must not be inside NGINX_DOC_ROOT"),
            # The two are the same directory.
            ("/srv/truthlens", "/srv/truthlens", "must not be inside NGINX_DOC_ROOT"),
            # A trailing-slash variant must not smuggle the same layout past the check.
            ("/srv/truthlens/", "/srv/truthlens/", "must not be inside NGINX_DOC_ROOT"),
        ],
    )
    def test_overlapping_roots_refuse_to_start(self, doc_root: str, mount: str, match: str) -> None:
        with pytest.raises(ConfigurationError, match=re.escape(match)):
            Settings(
                tlx_env=Environment.DEVELOPMENT,
                nginx_doc_root=Path(doc_root),
                evidence_mount_point=Path(mount),
            )

    def test_a_relative_doc_root_cannot_be_checked_and_is_refused(self) -> None:
        """A relative web root makes the isolation property undecidable, so it fails closed."""
        with pytest.raises(ConfigurationError, match="NGINX_DOC_ROOT must be an absolute path"):
            Settings(tlx_env=Environment.DEVELOPMENT, nginx_doc_root=Path("html"))

    def test_a_relative_mount_point_is_refused(self) -> None:
        with pytest.raises(
            ConfigurationError, match="EVIDENCE_MOUNT_POINT must be an absolute path"
        ):
            Settings(tlx_env=Environment.DEVELOPMENT, evidence_mount_point=Path("srv/truthlens"))

    def test_sibling_directories_under_a_common_parent_are_allowed(self) -> None:
        """The rule targets containment, not proximity — otherwise no layout would be legal."""
        settings = Settings(
            tlx_env=Environment.DEVELOPMENT,
            nginx_doc_root=Path("/opt/truthlens/web"),
            evidence_mount_point=Path("/opt/truthlens/evidence"),
        )
        assert settings.nginx_doc_root.parent == settings.evidence_mount_point.parent

    def test_the_rule_applies_in_production_too(self, prod_settings: dict[str, Any]) -> None:
        """A bypass that only fails in development would fail in exactly the wrong place."""
        prod_settings["nginx_doc_root"] = Path("/srv/truthlens/web")
        with pytest.raises(ConfigurationError, match="authorisation bypass"):
            Settings(**prod_settings)

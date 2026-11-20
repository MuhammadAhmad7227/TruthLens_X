"""M8 metadata extraction and normalized locations.

Revision ID: 0005
Revises: 0004
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "metadata_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("extractor", sa.Text(), nullable=False),
        sa.Column("extractor_version", sa.Text(), nullable=False),
        sa.Column("invocation_args", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("raw_tags", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("normalised", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("extraction_job_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("stripping_signals", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("source_sha256", sa.CHAR(length=64), nullable=False),
        sa.Column("extracted_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence_items.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["extraction_job_id"], ["analysis_jobs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "evidence_id",
            "extractor",
            "extractor_version",
            name="uq_metadata_records_evidence_extractor_version",
        ),
        sa.CheckConstraint("source_sha256 ~ '^[0-9a-f]{64}$'", name="metadata_source_sha256_is_lowercase_hex"),
    )
    op.create_index(
        "ix_metadata_records_evidence_extracted_at",
        "metadata_records",
        ["evidence_id", "extracted_at"],
    )

    op.create_table(
        "locations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("latitude", sa.Numeric(9, 6), nullable=False),
        sa.Column("longitude", sa.Numeric(9, 6), nullable=False),
        sa.Column("altitude_m", sa.Numeric(12, 3), nullable=True),
        sa.Column("uncertainty_m", sa.Numeric(12, 3), nullable=True),
        sa.Column("precision_digits", sa.Integer(), nullable=True),
        sa.Column("geohash", sa.Text(), nullable=True),
        sa.Column("gazetteer_match", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("source", sa.Text(), server_default=sa.text("'exif_gps'"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence_items.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint("latitude BETWEEN -90 AND 90", name="locations_latitude_range"),
        sa.CheckConstraint("longitude BETWEEN -180 AND 180", name="locations_longitude_range"),
        sa.CheckConstraint("uncertainty_m IS NULL OR uncertainty_m >= 0", name="locations_uncertainty_nonnegative"),
        sa.CheckConstraint("precision_digits IS NULL OR precision_digits BETWEEN 0 AND 10", name="locations_precision_range"),
    )
    op.create_index("ix_locations_evidence", "locations", ["evidence_id"])
    op.create_index("ix_locations_geohash", "locations", ["geohash"])


def downgrade() -> None:
    op.drop_index("ix_locations_geohash", table_name="locations")
    op.drop_index("ix_locations_evidence", table_name="locations")
    op.drop_table("locations")
    op.drop_index("ix_metadata_records_evidence_extracted_at", table_name="metadata_records")
    op.drop_table("metadata_records")

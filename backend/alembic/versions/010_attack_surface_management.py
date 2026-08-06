"""Add persistent ASM inventory, graph, changes, observations and exposures.

Revision ID: 010_attack_surface
Revises: 009_scan_vuln_history
"""

from alembic import op
import sqlalchemy as sa

revision = "010_attack_surface"
down_revision = "009_scan_vuln_history"
branch_labels = None
depends_on = None


def _rls(table: str, policy: str, org_column: str = "organization_id") -> None:
    op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
    op.execute(
        f'''
        CREATE POLICY {policy} ON "{table}"
        FOR ALL
        USING (
            current_setting('app.bypass_rls', true) = 'true'
            OR EXISTS (
                SELECT 1 FROM assets
                WHERE assets.id = "{table}".{org_column}
                AND assets.user_id = current_setting('app.current_user_id', true)
            )
        )
        WITH CHECK (
            current_setting('app.bypass_rls', true) = 'true'
            OR EXISTS (
                SELECT 1 FROM assets
                WHERE assets.id = "{table}".{org_column}
                AND assets.user_id = current_setting('app.current_user_id', true)
            )
        )
        '''
    )


def upgrade() -> None:
    op.create_table(
        "discovery_seeds",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("seed_type", sa.String(length=32), nullable=False),
        sa.Column("value", sa.String(length=512), nullable=False),
        sa.Column("is_primary", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("ownership_status", sa.String(length=32), nullable=False, server_default="confirmed"),
        sa.Column("confidence_score", sa.Float(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "seed_type", "value", name="uq_discovery_seed_value"),
    )
    op.create_index("idx_discovery_seeds_org", "discovery_seeds", ["organization_id"])
    op.create_index("idx_discovery_seeds_active", "discovery_seeds", ["organization_id", "is_active"])
    op.create_index(op.f("ix_discovery_seeds_created_at"), "discovery_seeds", ["created_at"])

    op.create_table(
        "discovered_assets",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("scope_domain_id", sa.String(length=36), nullable=True),
        sa.Column("asset_type", sa.String(length=40), nullable=False),
        sa.Column("value", sa.String(length=768), nullable=False),
        sa.Column("display_name", sa.String(length=768), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="new"),
        sa.Column("ownership_status", sa.String(length=32), nullable=False, server_default="high_confidence"),
        sa.Column("confidence_score", sa.Float(), nullable=False, server_default="0.9"),
        sa.Column("criticality", sa.String(length=24), nullable=False, server_default="normal"),
        sa.Column("internet_exposed", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("first_seen_scan_id", sa.String(length=36), nullable=True),
        sa.Column("last_seen_scan_id", sa.String(length=36), nullable=True),
        sa.Column("metadata_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("state_hash", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scope_domain_id"], ["domains.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["first_seen_scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["last_seen_scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "asset_type", "value", name="uq_discovered_asset_value"),
    )
    op.create_index("idx_discovered_assets_org", "discovered_assets", ["organization_id"])
    op.create_index("idx_discovered_assets_type", "discovered_assets", ["organization_id", "asset_type"])
    op.create_index("idx_discovered_assets_status", "discovered_assets", ["organization_id", "status"])
    op.create_index("idx_discovered_assets_last_seen", "discovered_assets", ["organization_id", "last_seen"])
    op.create_index("idx_discovered_assets_risk", "discovered_assets", ["organization_id", "risk_score"])
    op.create_index(op.f("ix_discovered_assets_created_at"), "discovered_assets", ["created_at"])

    op.create_table(
        "asset_relationships",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("source_asset_id", sa.String(length=36), nullable=False),
        sa.Column("target_asset_id", sa.String(length=36), nullable=False),
        sa.Column("relationship_type", sa.String(length=64), nullable=False),
        sa.Column("confidence_score", sa.Float(), nullable=False, server_default="1"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["source_asset_id"], ["discovered_assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_asset_id"], ["discovered_assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "source_asset_id", "target_asset_id", "relationship_type", name="uq_asset_relationship_edge"),
    )
    op.create_index("idx_asset_relationships_org", "asset_relationships", ["organization_id"])
    op.create_index("idx_asset_relationships_source", "asset_relationships", ["source_asset_id"])
    op.create_index("idx_asset_relationships_target", "asset_relationships", ["target_asset_id"])
    op.create_index(op.f("ix_asset_relationships_created_at"), "asset_relationships", ["created_at"])

    op.create_table(
        "asset_observations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("discovered_asset_id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state_hash", sa.String(length=64), nullable=False),
        sa.Column("snapshot_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["discovered_asset_id"], ["discovered_assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("discovered_asset_id", "scan_id", name="uq_asset_observation_scan"),
    )
    op.create_index("idx_asset_observations_org", "asset_observations", ["organization_id", "observed_at"])
    op.create_index("idx_asset_observations_asset", "asset_observations", ["discovered_asset_id", "observed_at"])
    op.create_index(op.f("ix_asset_observations_created_at"), "asset_observations", ["created_at"])

    op.create_table(
        "asset_changes",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("discovered_asset_id", sa.String(length=36), nullable=True),
        sa.Column("scan_id", sa.String(length=36), nullable=True),
        sa.Column("change_type", sa.String(length=48), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False, server_default="info"),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("details_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_acknowledged", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["discovered_asset_id"], ["discovered_assets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_asset_changes_org", "asset_changes", ["organization_id", "detected_at"])
    op.create_index("idx_asset_changes_asset", "asset_changes", ["discovered_asset_id", "detected_at"])
    op.create_index("idx_asset_changes_type", "asset_changes", ["organization_id", "change_type"])
    op.create_index(op.f("ix_asset_changes_created_at"), "asset_changes", ["created_at"])

    op.create_table(
        "exposures",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("discovered_asset_id", sa.String(length=36), nullable=True),
        sa.Column("scan_id", sa.String(length=36), nullable=True),
        sa.Column("source_vulnerability_id", sa.String(length=36), nullable=True),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("exposure_type", sa.String(length=48), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False, server_default="info"),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cve_id", sa.String(length=64), nullable=True),
        sa.Column("internet_exposed", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("exploitability", sa.String(length=32), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="open"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("details_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["discovered_asset_id"], ["discovered_assets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["source_vulnerability_id"], ["vulnerabilities.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "fingerprint", name="uq_exposure_fingerprint"),
    )
    op.create_index("idx_exposures_org", "exposures", ["organization_id"])
    op.create_index("idx_exposures_status", "exposures", ["organization_id", "status"])
    op.create_index("idx_exposures_severity", "exposures", ["organization_id", "severity"])
    op.create_index("idx_exposures_asset", "exposures", ["discovered_asset_id"])
    op.create_index(op.f("ix_exposures_created_at"), "exposures", ["created_at"])

    _rls("discovery_seeds", "discovery_seeds_policy")
    _rls("discovered_assets", "discovered_assets_policy")
    _rls("asset_relationships", "asset_relationships_policy")
    _rls("asset_observations", "asset_observations_policy")
    _rls("asset_changes", "asset_changes_policy")
    _rls("exposures", "exposures_policy")


def downgrade() -> None:
    for table, policy in [
        ("exposures", "exposures_policy"),
        ("asset_changes", "asset_changes_policy"),
        ("asset_observations", "asset_observations_policy"),
        ("asset_relationships", "asset_relationships_policy"),
        ("discovered_assets", "discovered_assets_policy"),
        ("discovery_seeds", "discovery_seeds_policy"),
    ]:
        op.execute(f'DROP POLICY IF EXISTS {policy} ON "{table}"')
        op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')

    op.drop_table("exposures")
    op.drop_table("asset_changes")
    op.drop_table("asset_observations")
    op.drop_table("asset_relationships")
    op.drop_table("discovered_assets")
    op.drop_table("discovery_seeds")

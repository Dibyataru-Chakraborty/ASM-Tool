"""Persistent Attack Surface Management inventory and change-tracking models."""

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)

from app.models.base import Base, TimestampMixin, get_uuid


class DiscoverySeed(Base, TimestampMixin):
    """A user-approved seed used to discover an organization's attack surface."""

    __tablename__ = "discovery_seeds"

    id = Column(String(36), primary_key=True, default=get_uuid)
    organization_id = Column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    seed_type = Column(String(32), nullable=False, default="domain")
    value = Column(String(512), nullable=False)
    is_primary = Column(Boolean, nullable=False, default=False)
    is_active = Column(Boolean, nullable=False, default=True)
    ownership_status = Column(String(32), nullable=False, default="confirmed")
    confidence_score = Column(Float, nullable=False, default=1.0)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "seed_type", "value", name="uq_discovery_seed_value"
        ),
        Index("idx_discovery_seeds_org", "organization_id"),
        Index("idx_discovery_seeds_active", "organization_id", "is_active"),
    )


class DiscoveredAsset(Base, TimestampMixin):
    """A persistent internet-facing asset in an organization's ASM inventory."""

    __tablename__ = "discovered_assets"

    id = Column(String(36), primary_key=True, default=get_uuid)
    organization_id = Column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    scope_domain_id = Column(
        String(36), ForeignKey("domains.id", ondelete="SET NULL"), nullable=True
    )
    asset_type = Column(String(40), nullable=False)
    value = Column(String(768), nullable=False)
    display_name = Column(String(768), nullable=True)

    # Lifecycle / ownership
    status = Column(String(32), nullable=False, default="new")
    ownership_status = Column(String(32), nullable=False, default="high_confidence")
    confidence_score = Column(Float, nullable=False, default=0.9)
    criticality = Column(String(24), nullable=False, default="normal")
    internet_exposed = Column(Boolean, nullable=False, default=True)

    # ASM risk and history
    risk_score = Column(Integer, nullable=False, default=0)
    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False)
    first_seen_scan_id = Column(
        String(36), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    last_seen_scan_id = Column(
        String(36), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    metadata_json = Column(Text, nullable=False, default="{}")
    state_hash = Column(String(64), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "asset_type", "value", name="uq_discovered_asset_value"
        ),
        Index("idx_discovered_assets_org", "organization_id"),
        Index("idx_discovered_assets_type", "organization_id", "asset_type"),
        Index("idx_discovered_assets_status", "organization_id", "status"),
        Index("idx_discovered_assets_last_seen", "organization_id", "last_seen"),
        Index("idx_discovered_assets_risk", "organization_id", "risk_score"),
    )


class AssetRelationship(Base, TimestampMixin):
    """A graph edge between two persistent attack-surface assets."""

    __tablename__ = "asset_relationships"

    id = Column(String(36), primary_key=True, default=get_uuid)
    organization_id = Column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    source_asset_id = Column(
        String(36), ForeignKey("discovered_assets.id", ondelete="CASCADE"), nullable=False
    )
    target_asset_id = Column(
        String(36), ForeignKey("discovered_assets.id", ondelete="CASCADE"), nullable=False
    )
    relationship_type = Column(String(64), nullable=False)
    confidence_score = Column(Float, nullable=False, default=1.0)
    is_active = Column(Boolean, nullable=False, default=True)
    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False)
    metadata_json = Column(Text, nullable=False, default="{}")

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "source_asset_id",
            "target_asset_id",
            "relationship_type",
            name="uq_asset_relationship_edge",
        ),
        Index("idx_asset_relationships_org", "organization_id"),
        Index("idx_asset_relationships_source", "source_asset_id"),
        Index("idx_asset_relationships_target", "target_asset_id"),
    )


class AssetObservation(Base, TimestampMixin):
    """Per-scan snapshot of an asset for historical comparison."""

    __tablename__ = "asset_observations"

    id = Column(String(36), primary_key=True, default=get_uuid)
    organization_id = Column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    discovered_asset_id = Column(
        String(36), ForeignKey("discovered_assets.id", ondelete="CASCADE"), nullable=False
    )
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    observed_at = Column(DateTime(timezone=True), nullable=False)
    state_hash = Column(String(64), nullable=False)
    snapshot_json = Column(Text, nullable=False, default="{}")

    __table_args__ = (
        UniqueConstraint(
            "discovered_asset_id", "scan_id", name="uq_asset_observation_scan"
        ),
        Index("idx_asset_observations_org", "organization_id", "observed_at"),
        Index("idx_asset_observations_asset", "discovered_asset_id", "observed_at"),
    )


class AssetChange(Base, TimestampMixin):
    """A material change detected between attack-surface observations."""

    __tablename__ = "asset_changes"

    id = Column(String(36), primary_key=True, default=get_uuid)
    organization_id = Column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    discovered_asset_id = Column(
        String(36), ForeignKey("discovered_assets.id", ondelete="SET NULL"), nullable=True
    )
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)
    change_type = Column(String(48), nullable=False)
    severity = Column(String(20), nullable=False, default="info")
    title = Column(String(255), nullable=False)
    details_json = Column(Text, nullable=False, default="{}")
    detected_at = Column(DateTime(timezone=True), nullable=False)
    is_acknowledged = Column(Boolean, nullable=False, default=False)

    __table_args__ = (
        Index("idx_asset_changes_org", "organization_id", "detected_at"),
        Index("idx_asset_changes_asset", "discovered_asset_id", "detected_at"),
        Index("idx_asset_changes_type", "organization_id", "change_type"),
    )


class Exposure(Base, TimestampMixin):
    """An exposure tied to an attack-surface asset, not just a scan result."""

    __tablename__ = "exposures"

    id = Column(String(36), primary_key=True, default=get_uuid)
    organization_id = Column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    discovered_asset_id = Column(
        String(36), ForeignKey("discovered_assets.id", ondelete="SET NULL"), nullable=True
    )
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)
    source_vulnerability_id = Column(
        String(36), ForeignKey("vulnerabilities.id", ondelete="SET NULL"), nullable=True
    )
    fingerprint = Column(String(64), nullable=False)
    exposure_type = Column(String(48), nullable=False)
    title = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False, default="info")
    risk_score = Column(Integer, nullable=False, default=0)
    cvss_score = Column(Float, nullable=True)
    cve_id = Column(String(64), nullable=True)
    internet_exposed = Column(Boolean, nullable=False, default=True)
    exploitability = Column(String(32), nullable=True)
    status = Column(String(32), nullable=False, default="open")
    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    details_json = Column(Text, nullable=False, default="{}")

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "fingerprint", name="uq_exposure_fingerprint"
        ),
        Index("idx_exposures_org", "organization_id"),
        Index("idx_exposures_status", "organization_id", "status"),
        Index("idx_exposures_severity", "organization_id", "severity"),
        Index("idx_exposures_asset", "discovered_asset_id"),
    )

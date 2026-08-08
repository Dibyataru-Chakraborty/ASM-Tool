"""Phases 2-10: All advanced features.

Revision ID: 002_phases_2_to_10
Revises: 001_initial
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = '002_phases_2_to_10'
down_revision = '001_initial'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade database schema for all phases."""
    
    # Phase 2: Ports table
    op.create_table(
        'ports',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('subdomain_id', sa.String(36), nullable=False),
        sa.Column('port_number', sa.Integer(), nullable=False),
        sa.Column('protocol', sa.String(10), nullable=False, server_default='TCP'),
        sa.Column('status', sa.String(20), nullable=False, server_default='open'),
        sa.Column('service_name', sa.String(100), nullable=True),
        sa.Column('last_checked', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['subdomain_id'], ['subdomains.id'], ondelete='CASCADE'),
        sa.UniqueConstraint('subdomain_id', 'port_number', name='idx_ports_subdomain_port'),
    )
    op.create_index('idx_ports_status', 'ports', ['status'])

    # Phase 2: Services table
    op.create_table(
        'services',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('port_id', sa.String(36), nullable=False),
        sa.Column('service_name', sa.String(100), nullable=False),
        sa.Column('version', sa.String(100), nullable=True),
        sa.Column('product', sa.String(255), nullable=True),
        sa.Column('os_type', sa.String(50), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'], ondelete='CASCADE'),
    )
    op.create_index('idx_services_port_id', 'services', ['port_id'])

    # Phase 2: Banners table
    op.create_table(
        'banners',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('service_id', sa.String(36), nullable=False),
        sa.Column('raw_banner', sa.Text(), nullable=False),
        sa.Column('parsed_version', sa.String(100), nullable=True),
        sa.Column('cpe', sa.String(255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['service_id'], ['services.id'], ondelete='CASCADE'),
    )
    op.create_index('idx_banners_service_id', 'banners', ['service_id'])

    # Phase 2: Technologies table
    op.create_table(
        'technologies',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('subdomain_id', sa.String(36), nullable=False),
        sa.Column('technology_name', sa.String(100), nullable=False),
        sa.Column('technology_type', sa.String(50), nullable=True),
        sa.Column('version', sa.String(100), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['subdomain_id'], ['subdomains.id'], ondelete='CASCADE'),
    )
    op.create_index('idx_technologies_subdomain', 'technologies', ['subdomain_id'])

    # Phase 2: OS Detections table
    op.create_table(
        'os_detections',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('subdomain_id', sa.String(36), nullable=False),
        sa.Column('os_name', sa.String(100), nullable=True),
        sa.Column('os_version', sa.String(100), nullable=True),
        sa.Column('os_family', sa.String(50), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0'),
        sa.Column('detection_method', sa.String(50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['subdomain_id'], ['subdomains.id'], ondelete='CASCADE'),
    )
    op.create_index('idx_os_subdomain', 'os_detections', ['subdomain_id'])

    # Phase 3: Vulnerabilities table
    op.create_table(
        'vulnerabilities',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('cve_id', sa.String(50), nullable=True),
        sa.Column('service_id', sa.String(36), nullable=True),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(20), nullable=True),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('cvss_vector', sa.String(255), nullable=True),
        sa.Column('published_date', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['service_id'], ['services.id'], ondelete='CASCADE'),
    )
    op.create_index('idx_vuln_cve', 'vulnerabilities', ['cve_id'])
    op.create_index('idx_vuln_service', 'vulnerabilities', ['service_id'])

    # Phase 4: Threat Intelligence table
    op.create_table(
        'threat_intelligence',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('indicator_type', sa.String(50), nullable=False),
        sa.Column('indicator_value', sa.String(255), nullable=False),
        sa.Column('source', sa.String(100), nullable=False),
        sa.Column('reputation_score', sa.Float(), nullable=True),
        sa.Column('is_malicious', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('last_checked', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_ti_indicator', 'threat_intelligence', ['indicator_type', 'indicator_value'])
    op.create_index('idx_ti_malicious', 'threat_intelligence', ['is_malicious'])

    # Phase 5: Secrets table
    op.create_table(
        'secrets',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('subdomain_id', sa.String(36), nullable=True),
        sa.Column('secret_type', sa.String(100), nullable=False),
        sa.Column('secret_location', sa.String(255), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('remediation_status', sa.String(50), nullable=False, server_default='pending'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['subdomain_id'], ['subdomains.id'], ondelete='CASCADE'),
    )
    op.create_index('idx_secrets_type', 'secrets', ['secret_type'])
    op.create_index('idx_secrets_active', 'secrets', ['is_active'])

    # Phase 6: Alerts table
    op.create_table(
        'alerts',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('asset_id', sa.String(36), nullable=False),
        sa.Column('alert_type', sa.String(100), nullable=False),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('is_resolved', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('notification_channels', sa.String(255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
    )
    op.create_index('idx_alerts_asset', 'alerts', ['asset_id'])
    op.create_index('idx_alerts_resolved', 'alerts', ['is_resolved'])

    # Phase 7: AI Insights table
    op.create_table(
        'ai_insights',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('asset_id', sa.String(36), nullable=False),
        sa.Column('insight_type', sa.String(100), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
    )
    op.create_index('idx_ai_asset', 'ai_insights', ['asset_id'])

    # Phase 8: Tenants table
    op.create_table(
        'tenants',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('slug', sa.String(100), nullable=False, unique=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('subscription_tier', sa.String(50), nullable=False, server_default='free'),
        sa.Column('api_quota_daily', sa.Integer(), nullable=False, server_default='10000'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_tenants_slug', 'tenants', ['slug'])
    op.add_column('users', sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id', ondelete='SET NULL'), nullable=True))
    op.add_column('assets', sa.Column('tenant_id', sa.String(36), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=True))

    # Phase 8: Audit Logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('user_id', sa.String(36), nullable=True),
        sa.Column('tenant_id', sa.String(36), nullable=True),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('resource_type', sa.String(50), nullable=False),
        sa.Column('resource_id', sa.String(36), nullable=True),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('ip_address', sa.String(50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
    )
    op.create_index('idx_audit_user', 'audit_logs', ['user_id'])
    op.create_index('idx_audit_action', 'audit_logs', ['action'])

    # Phase 9: Reports table
    op.create_table(
        'reports',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('asset_id', sa.String(36), nullable=False),
        sa.Column('report_type', sa.String(50), nullable=False),
        sa.Column('format', sa.String(20), nullable=False),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('file_path', sa.String(512), nullable=True),
        sa.Column('status', sa.String(50), nullable=False, server_default='generated'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
    )
    op.create_index('idx_reports_asset', 'reports', ['asset_id'])

    # Phase 10: Backups table
    op.create_table(
        'backups',
        sa.Column('id', sa.String(36), primary_key=True, default=sa.func.uuid()),
        sa.Column('backup_type', sa.String(50), nullable=False),
        sa.Column('status', sa.String(50), nullable=False, server_default='pending'),
        sa.Column('backup_path', sa.String(512), nullable=False),
        sa.Column('size_bytes', sa.Integer(), nullable=True),
        sa.Column('restore_point_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    """Downgrade database schema."""
    op.drop_column('users', 'tenant_id')
    op.drop_column('assets', 'tenant_id')
    op.drop_table('backups')
    op.drop_table('reports')
    op.drop_table('audit_logs')
    op.drop_table('tenants')
    op.drop_table('ai_insights')
    op.drop_table('alerts')
    op.drop_table('secrets')
    op.drop_table('threat_intelligence')
    op.drop_table('vulnerabilities')
    op.drop_table('os_detections')
    op.drop_table('technologies')
    op.drop_table('banners')
    op.drop_table('services')
    op.drop_table('ports')

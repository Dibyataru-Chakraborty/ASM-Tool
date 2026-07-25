"""Initial schema creation.

Revision ID: 001_initial
Revises: 
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '001_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade database schema."""
    
    # Create users table
    op.create_table(
        'users',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('password_hash', sa.String(255), nullable=False),
        sa.Column('full_name', sa.String(255), nullable=True),
        sa.Column('role', sa.String(50), nullable=False, server_default='analyst'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('is_verified', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('mfa_enabled', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('mfa_secret', sa.String(255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email'),
    )
    op.create_index('idx_users_email_active', 'users', ['email', 'is_active'])
    op.create_index('idx_users_role', 'users', ['role'])

    # Create assets table
    op.create_table(
        'assets',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('user_id', sa.String(36), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('asset_type', sa.String(50), nullable=False, server_default='domain'),
        sa.Column('status', sa.String(50), nullable=False, server_default='active'),
        sa.Column('risk_score', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    )
    op.create_index('idx_assets_user_status', 'assets', ['user_id', 'status'])
    op.create_index('idx_assets_risk_score', 'assets', ['risk_score'])

    # Create domains table
    op.create_table(
        'domains',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('asset_id', sa.String(36), nullable=False),
        sa.Column('domain', sa.String(255), nullable=False),
        sa.Column('tld', sa.String(10), nullable=True),
        sa.Column('registrar', sa.String(255), nullable=True),
        sa.Column('registrar_whois_server', sa.String(255), nullable=True),
        sa.Column('registrar_id', sa.String(255), nullable=True),
        sa.Column('whois_server', sa.String(255), nullable=True),
        sa.Column('created_date', sa.Date(), nullable=True),
        sa.Column('expiration_date', sa.Date(), nullable=True),
        sa.Column('updated_date', sa.Date(), nullable=True),
        sa.Column('admin_email', sa.String(255), nullable=True),
        sa.Column('admin_phone', sa.String(20), nullable=True),
        sa.Column('is_vulnerable', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('last_scanned', sa.DateTime(timezone=True), nullable=True),
        sa.Column('scan_status', sa.String(50), nullable=False, server_default='not_scanned'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.UniqueConstraint('asset_id', 'domain', name='idx_domains_asset_domain'),
    )
    op.create_index('idx_domains_tld', 'domains', ['tld'])
    op.create_index('idx_domains_expiration', 'domains', ['expiration_date'])

    # Create subdomains table
    op.create_table(
        'subdomains',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('domain_id', sa.String(36), nullable=False),
        sa.Column('subdomain', sa.String(255), nullable=False),
        sa.Column('ip_addresses', sa.Text(), nullable=True),
        sa.Column('is_responsive', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('response_status_code', sa.Integer(), nullable=True),
        sa.Column('response_time_ms', sa.Integer(), nullable=True),
        sa.Column('has_ssl', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('ssl_grade', sa.String(10), nullable=True),
        sa.Column('technologies', sa.Text(), nullable=True),
        sa.Column('last_checked', sa.DateTime(timezone=True), nullable=True),
        sa.Column('is_monitored', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], ondelete='CASCADE'),
        sa.UniqueConstraint('domain_id', 'subdomain', name='idx_subdomains_domain_subdomain'),
    )
    op.create_index('idx_subdomains_responsive', 'subdomains', ['is_responsive'])
    op.create_index('idx_subdomains_monitored', 'subdomains', ['is_monitored'])

    # Create dns_records table
    op.create_table(
        'dns_records',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('domain_id', sa.String(36), nullable=False),
        sa.Column('record_type', sa.String(10), nullable=False),
        sa.Column('record_value', sa.Text(), nullable=False),
        sa.Column('ttl', sa.Integer(), nullable=True),
        sa.Column('priority', sa.Integer(), nullable=True),
        sa.Column('weight', sa.Integer(), nullable=True),
        sa.Column('port', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], ondelete='CASCADE'),
    )
    op.create_index('idx_dns_records_domain_type', 'dns_records', ['domain_id', 'record_type'])

    # Create ssl_certificates table
    op.create_table(
        'ssl_certificates',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('domain_id', sa.String(36), nullable=False),
        sa.Column('subdomain_id', sa.String(36), nullable=True),
        sa.Column('certificate_subject', sa.String(255), nullable=False),
        sa.Column('certificate_subject_alt_names', sa.Text(), nullable=True),
        sa.Column('issuer', sa.String(255), nullable=False),
        sa.Column('valid_from', sa.DateTime(timezone=True), nullable=False),
        sa.Column('valid_to', sa.DateTime(timezone=True), nullable=False),
        sa.Column('fingerprint_sha256', sa.String(64), nullable=True),
        sa.Column('fingerprint_sha1', sa.String(40), nullable=True),
        sa.Column('is_valid', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('is_expired', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('is_self_signed', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('is_trusted', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('trust_error', sa.Text(), nullable=True),
        sa.Column('is_in_ct_logs', sa.Boolean(), nullable=True),
        sa.Column('ssl_grade', sa.String(10), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['subdomain_id'], ['subdomains.id'], ondelete='SET NULL'),
        sa.UniqueConstraint('fingerprint_sha256'),
    )
    op.create_index('idx_ssl_domain_id', 'ssl_certificates', ['domain_id'])
    op.create_index('idx_ssl_valid_to', 'ssl_certificates', ['valid_to'])
    op.create_index('idx_ssl_expired', 'ssl_certificates', ['is_expired'])

    # Create screenshots table
    op.create_table(
        'screenshots',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('subdomain_id', sa.String(36), nullable=False),
        sa.Column('url', sa.String(512), nullable=False),
        sa.Column('protocol', sa.String(10), nullable=True),
        sa.Column('port', sa.Integer(), nullable=True),
        sa.Column('file_path', sa.String(512), nullable=True),
        sa.Column('file_size', sa.Integer(), nullable=True),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('response_time_ms', sa.Integer(), nullable=True),
        sa.Column('title', sa.String(255), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('technologies', sa.Text(), nullable=True),
        sa.Column('is_valid', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('hash', sa.String(64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['subdomain_id'], ['subdomains.id'], ondelete='CASCADE'),
    )
    op.create_index('idx_screenshots_subdomain_id', 'screenshots', ['subdomain_id'])
    op.create_index('idx_screenshots_url', 'screenshots', ['url'])

    # Create scans table
    op.create_table(
        'scans',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('asset_id', sa.String(36), nullable=False),
        sa.Column('scan_type', sa.String(50), nullable=False),
        sa.Column('status', sa.String(50), nullable=False, server_default='pending'),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('discovered_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('vulnerable_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('celery_task_id', sa.String(255), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('retry_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('max_retries', sa.Integer(), nullable=False, server_default='3'),
        sa.Column('target_domain', sa.String(255), nullable=True),
        sa.Column('target_ip', sa.String(50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.UniqueConstraint('celery_task_id'),
    )
    op.create_index('idx_scans_asset_id', 'scans', ['asset_id'])
    op.create_index('idx_scans_status', 'scans', ['status'])
    op.create_index('idx_scans_type', 'scans', ['scan_type'])
    op.create_index('idx_scans_created_at', 'scans', ['created_at'])


def downgrade() -> None:
    """Downgrade database schema."""
    op.drop_table('scans')
    op.drop_table('screenshots')
    op.drop_table('ssl_certificates')
    op.drop_table('dns_records')
    op.drop_table('subdomains')
    op.drop_table('domains')
    op.drop_table('assets')
    op.drop_table('users')

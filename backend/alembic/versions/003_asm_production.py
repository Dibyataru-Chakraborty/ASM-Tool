"""ASM Production Tables Migration

Revision ID: 003_asm_production
Revises: 002_phases_2_to_10
Create Date: 2024-01-01
"""
from alembic import op
import sqlalchemy as sa

revision = '003_asm_production'
down_revision = '003_add_asset_target_tags'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('asm_assets',
        sa.Column('id',              sa.String(36),  primary_key=True),
        sa.Column('user_id',         sa.String(36),  sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name',            sa.String(255), nullable=False),
        sa.Column('target',          sa.String(512), nullable=False),
        sa.Column('asset_type',      sa.String(20),  nullable=False, server_default='domain'),
        sa.Column('description',     sa.Text,        nullable=True),
        sa.Column('tags',            sa.JSON,        nullable=True),
        sa.Column('is_active',       sa.Boolean,     server_default='true'),
        sa.Column('last_scanned_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('tenant_id',       sa.String(36),  sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=True),
        sa.Column('created_at',      sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at',      sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('idx_asm_assets_user',   'asm_assets', ['user_id'])
    op.create_index('idx_asm_assets_tenant', 'asm_assets', ['tenant_id'])
    op.create_index('idx_asm_assets_target', 'asm_assets', ['target'])

    op.create_table('scan_schedules',
        sa.Column('id',              sa.String(36), primary_key=True),
        sa.Column('asset_id',        sa.String(36), sa.ForeignKey('asm_assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('cron_expression', sa.String(100), nullable=False, server_default='0 2 * * *'),
        sa.Column('is_enabled',      sa.Boolean, server_default='true'),
        sa.Column('is_paused',       sa.Boolean, server_default='false'),
        sa.Column('next_run_at',     sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_run_at',     sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_run_status', sa.String(20),  nullable=True),
        sa.Column('run_count',       sa.Integer, server_default='0'),
        sa.Column('fail_count',      sa.Integer, server_default='0'),
        sa.Column('max_retries',     sa.Integer, server_default='2'),
        sa.Column('notify_on_completion', sa.Boolean, server_default='false'),
        sa.Column('notify_email',    sa.String(255), nullable=True),
        sa.Column('created_at',      sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at',      sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('idx_schedule_asset',   'scan_schedules', ['asset_id'])
    op.create_index('idx_schedule_enabled', 'scan_schedules', ['is_enabled'])
    op.create_index('idx_schedule_next',    'scan_schedules', ['next_run_at'])

    op.create_table('scan_jobs',
        sa.Column('id',               sa.String(36), primary_key=True),
        sa.Column('asset_id',         sa.String(36), sa.ForeignKey('asm_assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('schedule_id',      sa.String(36), sa.ForeignKey('scan_schedules.id', ondelete='SET NULL'), nullable=True),
        sa.Column('triggered_by',     sa.String(20), server_default='manual'),
        sa.Column('status',           sa.String(20), server_default='queued'),
        sa.Column('progress',         sa.Integer,    server_default='0'),
        sa.Column('current_tool',     sa.String(50), nullable=True),
        sa.Column('started_at',       sa.DateTime(timezone=True), nullable=True),
        sa.Column('finished_at',      sa.DateTime(timezone=True), nullable=True),
        sa.Column('duration_seconds', sa.Integer,    nullable=True),
        sa.Column('error_message',    sa.Text,       nullable=True),
        sa.Column('celery_task_id',   sa.String(255), nullable=True),
        sa.Column('created_at',       sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at',       sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('idx_scan_job_asset',  'scan_jobs', ['asset_id'])
    op.create_index('idx_scan_job_status', 'scan_jobs', ['status'])

    op.create_table('tool_executions',
        sa.Column('id',               sa.String(36), primary_key=True),
        sa.Column('scan_job_id',      sa.String(36), sa.ForeignKey('scan_jobs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('tool_name',        sa.String(50), nullable=False),
        sa.Column('order_index',      sa.Integer,    nullable=False),
        sa.Column('status',           sa.String(20), server_default='pending'),
        sa.Column('command',          sa.Text,       nullable=True),
        sa.Column('exit_code',        sa.Integer,    nullable=True),
        sa.Column('started_at',       sa.DateTime(timezone=True), nullable=True),
        sa.Column('finished_at',      sa.DateTime(timezone=True), nullable=True),
        sa.Column('duration_seconds', sa.Integer,    nullable=True),
        sa.Column('raw_output',       sa.Text,       nullable=True),
        sa.Column('error_output',     sa.Text,       nullable=True),
        sa.Column('parsed_output',    sa.JSON,       nullable=True),
        sa.Column('result_count',     sa.Integer,    server_default='0'),
        sa.Column('error_message',    sa.Text,       nullable=True),
        sa.Column('retry_count',      sa.Integer,    server_default='0'),
        sa.Column('created_at',       sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at',       sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('idx_tool_exec_job',    'tool_executions', ['scan_job_id'])
    op.create_index('idx_tool_exec_tool',   'tool_executions', ['tool_name'])
    op.create_index('idx_tool_exec_status', 'tool_executions', ['status'])

    op.create_table('vuln_findings',
        sa.Column('id',                 sa.String(36), primary_key=True),
        sa.Column('scan_job_id',        sa.String(36), sa.ForeignKey('scan_jobs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('tool_execution_id',  sa.String(36), sa.ForeignKey('tool_executions.id', ondelete='SET NULL'), nullable=True),
        sa.Column('asset_id',           sa.String(36), sa.ForeignKey('asm_assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('title',              sa.String(512), nullable=False),
        sa.Column('severity',           sa.String(20),  nullable=False, server_default='info'),
        sa.Column('cvss_score',         sa.Float,       nullable=True),
        sa.Column('cvss_vector',        sa.String(255), nullable=True),
        sa.Column('cve_id',             sa.String(50),  nullable=True),
        sa.Column('cwe_id',             sa.String(50),  nullable=True),
        sa.Column('template_id',        sa.String(255), nullable=True),
        sa.Column('url',                sa.Text,        nullable=True),
        sa.Column('host',               sa.String(255), nullable=True),
        sa.Column('port',               sa.Integer,     nullable=True),
        sa.Column('parameter',          sa.String(255), nullable=True),
        sa.Column('path',               sa.Text,        nullable=True),
        sa.Column('description',        sa.Text,        nullable=True),
        sa.Column('impact',             sa.Text,        nullable=True),
        sa.Column('recommendation',     sa.Text,        nullable=True),
        sa.Column('references',         sa.JSON,        nullable=True),
        sa.Column('tags',               sa.JSON,        nullable=True),
        sa.Column('http_request',       sa.Text,        nullable=True),
        sa.Column('http_response',      sa.Text,        nullable=True),
        sa.Column('proof_of_concept',   sa.Text,        nullable=True),
        sa.Column('raw_evidence',       sa.Text,        nullable=True),
        sa.Column('source_tool',        sa.String(50),  nullable=True),
        sa.Column('is_duplicate',       sa.Boolean,     server_default='false'),
        sa.Column('is_false_positive',  sa.Boolean,     server_default='false'),
        sa.Column('created_at',         sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at',         sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('idx_vuln_scan',     'vuln_findings', ['scan_job_id'])
    op.create_index('idx_vuln_asset',    'vuln_findings', ['asset_id'])
    op.create_index('idx_vuln_severity', 'vuln_findings', ['severity'])
    op.create_index('idx_vuln_findings_cve', 'vuln_findings', ['cve_id'])

    op.create_table('vuln_screenshots',
        sa.Column('id',        sa.String(36), primary_key=True),
        sa.Column('vuln_id',   sa.String(36), sa.ForeignKey('vuln_findings.id', ondelete='CASCADE'), nullable=False),
        sa.Column('url',       sa.Text,       nullable=True),
        sa.Column('file_path', sa.String(512), nullable=True),
        sa.Column('file_size', sa.Integer,    nullable=True),
        sa.Column('width',     sa.Integer,    nullable=True),
        sa.Column('height',    sa.Integer,    nullable=True),
        sa.Column('taken_at',  sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table('scan_reports',
        sa.Column('id',                sa.String(36), primary_key=True),
        sa.Column('scan_job_id',       sa.String(36), sa.ForeignKey('scan_jobs.id', ondelete='CASCADE'), nullable=False, unique=True),
        sa.Column('asset_id',          sa.String(36), sa.ForeignKey('asm_assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('total_vulns',       sa.Integer, server_default='0'),
        sa.Column('critical_count',    sa.Integer, server_default='0'),
        sa.Column('high_count',        sa.Integer, server_default='0'),
        sa.Column('medium_count',      sa.Integer, server_default='0'),
        sa.Column('low_count',         sa.Integer, server_default='0'),
        sa.Column('info_count',        sa.Integer, server_default='0'),
        sa.Column('executive_summary', sa.Text,    nullable=True),
        sa.Column('technical_summary', sa.Text,    nullable=True),
        sa.Column('attack_surface',    sa.JSON,    nullable=True),
        sa.Column('open_ports',        sa.JSON,    nullable=True),
        sa.Column('technologies',      sa.JSON,    nullable=True),
        sa.Column('subdomains_found',  sa.JSON,    nullable=True),
        sa.Column('recommendations',   sa.Text,    nullable=True),
        sa.Column('risk_score',        sa.Float,   nullable=True),
        sa.Column('risk_rating',       sa.String(20), nullable=True),
        sa.Column('markdown_report',   sa.Text,    nullable=True),
        sa.Column('html_report',       sa.Text,    nullable=True),
        sa.Column('json_report',       sa.JSON,    nullable=True),
        sa.Column('pdf_path',          sa.String(512), nullable=True),
        sa.Column('generated_at',      sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at',        sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at',        sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('idx_report_scan',  'scan_reports', ['scan_job_id'])
    op.create_index('idx_report_asset', 'scan_reports', ['asset_id'])

    op.create_table('scan_logs',
        sa.Column('id',          sa.String(36), primary_key=True),
        sa.Column('scan_job_id', sa.String(36), sa.ForeignKey('scan_jobs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('level',       sa.String(10), server_default='info'),
        sa.Column('message',     sa.Text,       nullable=False),
        sa.Column('tool',        sa.String(50), nullable=True),
        sa.Column('logged_at',   sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('idx_log_scan', 'scan_logs', ['scan_job_id'])
    op.create_index('idx_log_time', 'scan_logs', ['logged_at'])


def downgrade():
    for t in ['scan_logs','scan_reports','vuln_screenshots','vuln_findings',
              'tool_executions','scan_jobs','scan_schedules','asm_assets']:
        op.drop_table(t)

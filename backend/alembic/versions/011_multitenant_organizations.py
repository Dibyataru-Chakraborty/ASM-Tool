"""Introduce real multi-tenant organizations, membership roles and tenant RLS.

Revision ID: 011_multitenant
Revises: 010_attack_surface
"""
from alembic import op
import sqlalchemy as sa
revision="011_multitenant"; down_revision="010_attack_surface"; branch_labels=None; depends_on=None

ASM_TABLES=["discovery_seeds","discovered_assets","asset_relationships","asset_observations","asset_changes","exposures"]

def upgrade():
    op.create_table("organizations",
        sa.Column("id",sa.String(36),primary_key=True),sa.Column("code",sa.String(64),nullable=False,unique=True),
        sa.Column("name",sa.String(255),nullable=False),sa.Column("description",sa.Text()),sa.Column("status",sa.String(32),nullable=False,server_default="active"),
        sa.Column("created_by_user_id",sa.String(36),sa.ForeignKey("users.id",ondelete="SET NULL")),
        sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False),sa.Column("updated_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False))
    op.create_index("ix_organizations_code","organizations",["code"],unique=True); op.create_index("ix_organizations_name","organizations",["name"]); op.create_index("ix_organizations_status","organizations",["status"])
    op.add_column("users",sa.Column("platform_role",sa.String(32),nullable=False,server_default="member")); op.create_index("idx_users_platform_role","users",["platform_role"])
    # Existing legacy admins become platform Super Admins so upgrades do not lock out the owner.
    op.execute("UPDATE users SET platform_role='super_admin' WHERE role='admin'")
    # Existing enhanced-build Asset rows represented organizations. Preserve IDs so all ASM inventory references remain valid.
    op.execute("""INSERT INTO organizations(id,code,name,description,status,created_by_user_id,created_at,updated_at)
        SELECT id, 'ORG-' || upper(substr(replace(id,'-',''),1,12)), name, description,
               CASE WHEN status='archived' THEN 'disabled' ELSE 'active' END, user_id, created_at, updated_at FROM assets""")
    op.create_table("organization_memberships",
        sa.Column("id",sa.String(36),primary_key=True),sa.Column("organization_id",sa.String(36),sa.ForeignKey("organizations.id",ondelete="CASCADE"),nullable=False),
        sa.Column("user_id",sa.String(36),sa.ForeignKey("users.id",ondelete="CASCADE"),nullable=False),sa.Column("role",sa.String(32),nullable=False,server_default="user"),
        sa.Column("status",sa.String(32),nullable=False,server_default="active"),sa.Column("created_by_user_id",sa.String(36),sa.ForeignKey("users.id",ondelete="SET NULL")),
        sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False),sa.Column("updated_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False),
        sa.UniqueConstraint("organization_id","user_id",name="uq_organization_membership"))
    op.create_index("idx_memberships_org_role","organization_memberships",["organization_id","role","status"]); op.create_index("idx_memberships_user","organization_memberships",["user_id","status"])
    op.execute("CREATE UNIQUE INDEX uq_org_single_active_admin ON organization_memberships (organization_id) WHERE role='admin' AND status='active'")
    # Legacy non-super-admin owners become tenant Admins of the corresponding legacy organization.
    op.execute("""INSERT INTO organization_memberships(id,organization_id,user_id,role,status,created_by_user_id,created_at,updated_at)
        SELECT md5(a.id || ':' || a.user_id), a.id, a.user_id, 'admin', 'active', a.user_id, now(), now()
        FROM assets a JOIN users u ON u.id=a.user_id WHERE u.platform_role <> 'super_admin' ON CONFLICT DO NOTHING""")
    op.create_table("organization_audit_logs",
        sa.Column("id",sa.String(36),primary_key=True),sa.Column("organization_id",sa.String(36),sa.ForeignKey("organizations.id",ondelete="SET NULL")),
        sa.Column("actor_user_id",sa.String(36),sa.ForeignKey("users.id",ondelete="SET NULL")),sa.Column("action",sa.String(120),nullable=False),
        sa.Column("resource_type",sa.String(80)),sa.Column("resource_id",sa.String(64)),sa.Column("details_json",sa.Text(),nullable=False,server_default="{}"),
        sa.Column("created_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False),sa.Column("updated_at",sa.DateTime(timezone=True),server_default=sa.func.now(),nullable=False))
    op.create_index("idx_org_audit_org_created","organization_audit_logs",["organization_id","created_at"]); op.create_index("idx_org_audit_actor_created","organization_audit_logs",["actor_user_id","created_at"])

    # Core target/domain/job records get direct tenant FKs.
    op.add_column("assets",sa.Column("organization_id",sa.String(36),nullable=True)); op.execute("UPDATE assets SET organization_id=id")
    op.create_foreign_key("fk_assets_organization","assets","organizations",["organization_id"],["id"],ondelete="CASCADE"); op.alter_column("assets","organization_id",nullable=False); op.create_index("idx_assets_org_status","assets",["organization_id","status"])
    op.alter_column("assets","user_id",nullable=True)
    op.add_column("domains",sa.Column("organization_id",sa.String(36),nullable=True)); op.execute("UPDATE domains d SET organization_id=a.organization_id FROM assets a WHERE a.id=d.asset_id")
    op.create_foreign_key("fk_domains_organization","domains","organizations",["organization_id"],["id"],ondelete="CASCADE"); op.alter_column("domains","organization_id",nullable=False); op.create_index("idx_domains_org_domain","domains",["organization_id","domain"])
    op.add_column("scans",sa.Column("organization_id",sa.String(36),nullable=True)); op.execute("UPDATE scans s SET organization_id=a.organization_id FROM assets a WHERE a.id=s.asset_id")
    op.create_foreign_key("fk_scans_organization","scans","organizations",["organization_id"],["id"],ondelete="CASCADE"); op.alter_column("scans","organization_id",nullable=False); op.create_index("idx_scans_organization_id","scans",["organization_id"])
    op.add_column("scan_schedules",sa.Column("organization_id",sa.String(36),nullable=True)); op.execute("UPDATE scan_schedules s SET organization_id=a.organization_id FROM assets a WHERE a.id=s.asset_id")
    op.create_foreign_key("fk_scan_schedules_organization","scan_schedules","organizations",["organization_id"],["id"],ondelete="CASCADE"); op.alter_column("scan_schedules","organization_id",nullable=False); op.create_index("idx_scan_schedules_org","scan_schedules",["organization_id"])

    # Re-point enhanced ASM inventory FK from legacy assets to real organizations; IDs are preserved.
    for table in ASM_TABLES:
        op.drop_constraint(f"{table}_organization_id_fkey",table,type_="foreignkey")
        op.create_foreign_key(f"fk_{table}_organization",table,"organizations",["organization_id"],["id"],ondelete="CASCADE")

    # Replace old per-user RLS with tenant RLS. Super Admin uses app.bypass_rls=true; members use app.current_org_id.
    old={"users":["user_policy","user_insert_policy"],"assets":["asset_policy"],"domains":["domain_policy"],"subdomains":["subdomain_policy"],"dns_records":["dns_record_policy"],
         "ssl_certificates":["ssl_certificate_policy"],"screenshots":["screenshot_policy"],"scans":["scan_policy"],"ports":["port_policy"],"services":["service_policy"],"vulnerabilities":["vulnerability_policy"],
         "discovery_seeds":["discovery_seeds_policy"],"discovered_assets":["discovered_assets_policy"],"asset_relationships":["asset_relationships_policy"],"asset_observations":["asset_observations_policy"],"asset_changes":["asset_changes_policy"],"exposures":["exposures_policy"]}
    for table,policies in old.items():
        for p in policies: op.execute(f'DROP POLICY IF EXISTS {p} ON "{table}"')
    # Direct tenant tables.
    direct=["organizations","organization_memberships","organization_audit_logs","assets","domains","scans","scan_schedules"]+ASM_TABLES
    for table in direct:
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'); op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
        col="id" if table=="organizations" else "organization_id"
        op.execute(f"""CREATE POLICY tenant_{table}_policy ON "{table}" FOR ALL USING (
            current_setting('app.bypass_rls',true)='true' OR "{table}".{col}=current_setting('app.current_org_id',true))
            WITH CHECK (current_setting('app.bypass_rls',true)='true' OR "{table}".{col}=current_setting('app.current_org_id',true))""")
    # Users visible to self, Super Admin, or members of the selected tenant.
    op.execute("ALTER TABLE users ENABLE ROW LEVEL SECURITY"); op.execute("ALTER TABLE users FORCE ROW LEVEL SECURITY")
    op.execute("""CREATE POLICY tenant_users_select_policy ON users FOR SELECT USING (
        current_setting('app.bypass_rls',true)='true' OR id=current_setting('app.current_user_id',true) OR EXISTS(
            SELECT 1 FROM organization_memberships m WHERE m.user_id=users.id AND m.organization_id=current_setting('app.current_org_id',true)))""")
    op.execute("""CREATE POLICY tenant_users_update_policy ON users FOR UPDATE USING (
        current_setting('app.bypass_rls',true)='true' OR id=current_setting('app.current_user_id',true) OR EXISTS(
            SELECT 1 FROM organization_memberships m WHERE m.user_id=users.id AND m.organization_id=current_setting('app.current_org_id',true)))
        WITH CHECK (current_setting('app.bypass_rls',true)='true' OR id=current_setting('app.current_user_id',true) OR EXISTS(
            SELECT 1 FROM organization_memberships m WHERE m.user_id=users.id AND m.organization_id=current_setting('app.current_org_id',true)))""")
    op.execute("""CREATE POLICY tenant_users_insert_policy ON users FOR INSERT WITH CHECK (
        current_setting('app.bypass_rls',true)='true' OR current_setting('app.current_org_id',true) <> '')""")
    # Legacy child records continue to inherit the tenant boundary through parent relationships.
    inherited={
      "subdomains":"EXISTS (SELECT 1 FROM domains d WHERE d.id=subdomains.domain_id AND d.organization_id=current_setting('app.current_org_id',true))",
      "dns_records":"EXISTS (SELECT 1 FROM domains d WHERE d.id=dns_records.domain_id AND d.organization_id=current_setting('app.current_org_id',true))",
      "ssl_certificates":"EXISTS (SELECT 1 FROM domains d WHERE d.id=ssl_certificates.domain_id AND d.organization_id=current_setting('app.current_org_id',true))",
      "screenshots":"EXISTS (SELECT 1 FROM subdomains s JOIN domains d ON d.id=s.domain_id WHERE s.id=screenshots.subdomain_id AND d.organization_id=current_setting('app.current_org_id',true))",
      "ports":"EXISTS (SELECT 1 FROM subdomains s JOIN domains d ON d.id=s.domain_id WHERE s.id=ports.subdomain_id AND d.organization_id=current_setting('app.current_org_id',true))",
      "services":"EXISTS (SELECT 1 FROM ports p JOIN subdomains s ON s.id=p.subdomain_id JOIN domains d ON d.id=s.domain_id WHERE p.id=services.port_id AND d.organization_id=current_setting('app.current_org_id',true))",
      "vulnerabilities":"EXISTS (SELECT 1 FROM services sv JOIN ports p ON p.id=sv.port_id JOIN subdomains s ON s.id=p.subdomain_id JOIN domains d ON d.id=s.domain_id WHERE sv.id=vulnerabilities.service_id AND d.organization_id=current_setting('app.current_org_id',true))"}
    for table,predicate in inherited.items():
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'); op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
        op.execute(f"""CREATE POLICY tenant_{table}_policy ON "{table}" FOR ALL USING (current_setting('app.bypass_rls',true)='true' OR {predicate}) WITH CHECK (current_setting('app.bypass_rls',true)='true' OR {predicate})""")

def downgrade():
    raise RuntimeError("Downgrade from multi-tenant architecture is intentionally unsupported; restore a database backup instead.")

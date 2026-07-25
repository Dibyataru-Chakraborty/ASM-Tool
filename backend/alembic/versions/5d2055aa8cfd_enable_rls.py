"""enable_rls

Revision ID: 5d2055aa8cfd
Revises: 002_phases_2_to_10
Create Date: 2026-07-22 09:18:11.221422

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5d2055aa8cfd'
down_revision = '002_phases_2_to_10'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Enable RLS on tables
    tables = [
        "users", "assets", "domains", "subdomains", "dns_records", 
        "ssl_certificates", "screenshots", "scans", "ports", 
        "services", "vulnerabilities"
    ]
    for t in tables:
        op.execute(f"ALTER TABLE \"{t}\" ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE \"{t}\" FORCE ROW LEVEL SECURITY")
        
    # Create policies
    
    # 1. users
    op.execute("""
        CREATE POLICY user_policy ON users
            FOR ALL
            USING (
                current_setting('app.bypass_rls', true) = 'true'
                OR id = current_setting('app.current_user_id', true)
            )
    """)
    op.execute("""
        CREATE POLICY user_insert_policy ON users
            FOR INSERT
            WITH CHECK (true)
    """)

    # 2. assets
    op.execute("""
        CREATE POLICY asset_policy ON assets
            FOR ALL
            USING (
                current_setting('app.bypass_rls', true) = 'true'
                OR user_id = current_setting('app.current_user_id', true)
            )
    """)

    # 3. domains
    op.execute("""
        CREATE POLICY domain_policy ON domains
            FOR ALL
            USING (
                current_setting('app.bypass_rls', true) = 'true'
                OR EXISTS (
                    SELECT 1 FROM assets WHERE assets.id = domains.asset_id 
                    AND assets.user_id = current_setting('app.current_user_id', true)
                )
            )
    """)

    # 4. subdomains
    op.execute("""
        CREATE POLICY subdomain_policy ON subdomains
            FOR ALL
            USING (
                current_setting('app.bypass_rls', true) = 'true'
                OR EXISTS (
                    SELECT 1 FROM domains 
                    JOIN assets ON assets.id = domains.asset_id
                    WHERE domains.id = subdomains.domain_id 
                    AND assets.user_id = current_setting('app.current_user_id', true)
                )
            )
    """)

    # 5. dns_records
    op.execute("""
        CREATE POLICY dns_record_policy ON dns_records
            FOR ALL
            USING (
                current_setting('app.bypass_rls', true) = 'true'
                OR EXISTS (
                    SELECT 1 FROM domains 
                    JOIN assets ON assets.id = domains.asset_id
                    WHERE domains.id = dns_records.domain_id 
                    AND assets.user_id = current_setting('app.current_user_id', true)
                )
            )
    """)

    # 6. ssl_certificates
    op.execute("""
        CREATE POLICY ssl_certificate_policy ON ssl_certificates
            FOR ALL
            USING (
                current_setting('app.bypass_rls', true) = 'true'
                OR EXISTS (
                    SELECT 1 FROM domains 
                    JOIN assets ON assets.id = domains.asset_id
                    WHERE domains.id = ssl_certificates.domain_id 
                    AND assets.user_id = current_setting('app.current_user_id', true)
                )
            )
    """)

    # 7. screenshots
    op.execute("""
        CREATE POLICY screenshot_policy ON screenshots
            FOR ALL
            USING (
                current_setting('app.bypass_rls', true) = 'true'
                OR EXISTS (
                    SELECT 1 FROM subdomains 
                    JOIN domains ON domains.id = subdomains.domain_id
                    JOIN assets ON assets.id = domains.asset_id
                    WHERE subdomains.id = screenshots.subdomain_id 
                    AND assets.user_id = current_setting('app.current_user_id', true)
                )
            )
    """)

    # 8. scans
    op.execute("""
        CREATE POLICY scan_policy ON scans
            FOR ALL
            USING (
                current_setting('app.bypass_rls', true) = 'true'
                OR EXISTS (
                    SELECT 1 FROM assets WHERE assets.id = scans.asset_id 
                    AND assets.user_id = current_setting('app.current_user_id', true)
                )
            )
    """)

    # 9. ports
    op.execute("""
        CREATE POLICY port_policy ON ports
            FOR ALL
            USING (
                current_setting('app.bypass_rls', true) = 'true'
                OR EXISTS (
                    SELECT 1 FROM subdomains 
                    JOIN domains ON domains.id = subdomains.domain_id
                    JOIN assets ON assets.id = domains.asset_id
                    WHERE subdomains.id = ports.subdomain_id 
                    AND assets.user_id = current_setting('app.current_user_id', true)
                )
            )
    """)

    # 10. services
    op.execute("""
        CREATE POLICY service_policy ON services
            FOR ALL
            USING (
                current_setting('app.bypass_rls', true) = 'true'
                OR EXISTS (
                    SELECT 1 FROM ports 
                    JOIN subdomains ON subdomains.id = ports.subdomain_id
                    JOIN domains ON domains.id = subdomains.domain_id
                    JOIN assets ON assets.id = domains.asset_id
                    WHERE ports.id = services.port_id 
                    AND assets.user_id = current_setting('app.current_user_id', true)
                )
            )
    """)

    # 11. vulnerabilities
    op.execute("""
        CREATE POLICY vulnerability_policy ON vulnerabilities
            FOR ALL
            USING (
                current_setting('app.bypass_rls', true) = 'true'
                OR EXISTS (
                    SELECT 1 FROM services
                    JOIN ports ON ports.id = services.port_id
                    JOIN subdomains ON subdomains.id = ports.subdomain_id
                    JOIN domains ON domains.id = subdomains.domain_id
                    JOIN assets ON assets.id = domains.asset_id
                    WHERE services.id = vulnerabilities.service_id 
                    AND assets.user_id = current_setting('app.current_user_id', true)
                )
            )
    """)


def downgrade() -> None:
    tables_policies = [
        ("users", "user_policy"),
        ("users", "user_insert_policy"),
        ("assets", "asset_policy"),
        ("domains", "domain_policy"),
        ("subdomains", "subdomain_policy"),
        ("dns_records", "dns_record_policy"),
        ("ssl_certificates", "ssl_certificate_policy"),
        ("screenshots", "screenshot_policy"),
        ("scans", "scan_policy"),
        ("ports", "port_policy"),
        ("services", "service_policy"),
        ("vulnerabilities", "vulnerability_policy"),
    ]
    for t, p in tables_policies:
        op.execute(f"DROP POLICY IF EXISTS {p} ON \"{t}\"")
    
    tables = [
        "users", "assets", "domains", "subdomains", "dns_records", 
        "ssl_certificates", "screenshots", "scans", "ports", 
        "services", "vulnerabilities"
    ]
    for t in tables:
        op.execute(f"ALTER TABLE \"{t}\" DISABLE ROW LEVEL SECURITY")

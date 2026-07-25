from sqlalchemy import create_engine, text
from app.config import settings

engine = create_engine(settings.database_url)

with engine.connect() as conn:
    conn.execute(text("SET app.bypass_rls = 'true'"))
    
    scans = conn.execute(text("SELECT id, asset_id, status, scan_type FROM scans")).fetchall()
    print("Scans:")
    for s in scans:
        print(f"- ID: {s[0]}, Asset ID: {s[1]}, Status: {s[2]}, Type: {s[3]}")
        
    domains = conn.execute(text("SELECT id, asset_id, domain, scan_status FROM domains")).fetchall()
    print("\nDomains:")
    for d in domains:
        print(f"- ID: {d[0]}, Asset ID: {d[1]}, Domain: {d[2]}, Status: {d[3]}")
        
    subdomains = conn.execute(text("SELECT id, subdomain, is_responsive FROM subdomains")).fetchall()
    print("\nSubdomains:")
    for sd in subdomains:
        print(f"- ID: {sd[0]}, Subdomain: {sd[1]}, Responsive: {sd[2]}")
        
    vulns = conn.execute(text("SELECT id, title, severity FROM vulnerabilities")).fetchall()
    print("\nVulnerabilities:")
    for v in vulns:
        print(f"- ID: {v[0]}, Title: {v[1]}, Severity: {v[2]}")
        
    screenshots = conn.execute(text("SELECT id, url, protocol FROM screenshots")).fetchall()
    print("\nScreenshots:")
    for ss in screenshots:
        print(f"- ID: {ss[0]}, URL: {ss[1]}, Protocol: {ss[2]}")

    # Check if RLS is blocking the vulnerabilities query
    conn.execute(text("SET app.bypass_rls = 'false'"))
    conn.execute(text("SET app.current_user_id = '5eed1485-c7ba-4b1d-b3e2-b3bf74bf47be'"))
    
    print("\nQuerying vulnerabilities with RLS active:")
    rls_vulns = conn.execute(text("""
        SELECT v.id, v.title 
        FROM vulnerabilities v
        JOIN services s ON s.id = v.service_id
        JOIN ports p ON p.id = s.port_id
        JOIN subdomains sd ON sd.id = p.subdomain_id
        JOIN domains d ON d.id = sd.domain_id
        JOIN assets a ON a.id = d.asset_id
        WHERE a.user_id = '5eed1485-c7ba-4b1d-b3e2-b3bf74bf47be'
    """)).fetchall()
    print(f"Found {len(rls_vulns)} vulnerabilities under RLS.")


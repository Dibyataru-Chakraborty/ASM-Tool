# ASM Enhancement Notes

This build keeps the existing reconnaissance and vulnerability-assessment pipeline, but changes its role: completed discovery cycles now feed a persistent Attack Surface Management (ASM) inventory instead of acting only as point-in-time scan results.

## What was added

- Organization-centric onboarding with approved discovery seeds.
- Persistent attack-surface inventory for domains, subdomains, IPs, services, certificates, and investigation candidates.
- First Seen / Last Seen timestamps and lifecycle states (`new`, `active`, `changed`, `inactive`, `historical`).
- Asset relationship graph, including domain → subdomain → IP/service and host → certificate relationships.
- Candidate-domain discovery from certificate SANs. Out-of-scope candidates are **not scanned automatically**; they remain `requires_investigation` until an analyst confirms them.
- Analyst confirmation promotes a candidate to an approved discovery seed/domain for future monitoring.
- Change detection between monitoring cycles: new, changed, reappeared, removed assets, new exposures, resolved exposures, and remediation-state changes.
- Exposure management that treats scanner vulnerabilities as one exposure source alongside sensitive internet-facing services and certificate issues.
- ASM risk score enriched with internet exposure and user-defined business criticality.
- Business criticality and ownership/confidence controls on each inventory asset.
- Exposure remediation states: Open, In progress, Accepted risk, False positive, Resolved.
- Continuous Monitoring UI using the existing persistent scheduler. Scheduled recon cycles automatically update the ASM inventory and change history.
- ASM dashboard, inventory, asset detail/history, relationship map, change timeline, exposure/remediation view, and Organizations & Discovery Seeds workflow.
- Existing completed scans are backfilled into the new persistent inventory on application startup when an organization has no ASM inventory yet.

## Main new backend components

- `backend/app/models/attack_surface.py`
- `backend/app/services/attack_surface_service.py`
- `backend/app/api/v1/attack_surface.py`
- `backend/alembic/versions/010_attack_surface_management.py`

The migration creates:

- `discovery_seeds`
- `discovered_assets`
- `asset_relationships`
- `asset_observations`
- `asset_changes`
- `exposures`

## Main new frontend views

- `/dashboard` — Attack Surface Overview
- `/assets` — Organizations & Discovery Seeds
- `/attack-surface` — Persistent Inventory
- `/attack-surface/[id]` — Asset context, relationships, exposures and history
- `/asset-map` — Relationship Map
- `/changes` — Attack Surface Changes
- `/exposures` — Exposures & Remediation
- `/scheduler` — Continuous Monitoring

## Upgrade / run

Before changing a production database, take a database backup.

### Docker Compose

The existing backend command already runs Alembic automatically:

```bash
docker compose up --build
```

It executes `alembic upgrade head` before starting the API, so migration `010_attack_surface` is applied automatically.

### Local backend

```bash
cd backend
alembic upgrade head
uvicorn app.main:app --reload
```

### Recommended demo flow

1. Open **Organizations** and create an organization using its primary company domain.
2. Add any other approved domain/IP/CIDR/ASN seeds you know.
3. Open **Discovery Engine** and run discovery against an approved domain.
4. Open **Attack Surface** to show persistent inventory with First Seen, Last Seen, lifecycle, ownership, criticality and ASM risk.
5. Open **Asset Map** to show relationships.
6. Open **Exposures & Remediation** to show vulnerabilities plus service/certificate exposure context.
7. Enable **Continuous Monitoring** for the organization.
8. On later discovery cycles, demonstrate **Changes**: new, changed, removed/reappeared assets and resolved/new exposures.
9. If a certificate reveals an outside candidate domain, show it as **Requires Investigation**. Confirm it only when ownership/scope is verified; confirmation adds it as an approved discovery seed for future monitoring.

## Scope behavior

This build deliberately does not automatically scan inferred outside domains. Passive correlation may surface them as candidates, but active expansion requires analyst confirmation. This preserves authorized scope while still demonstrating unknown-asset discovery and attribution.

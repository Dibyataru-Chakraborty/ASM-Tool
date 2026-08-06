# Multi-Tenant ASM Architecture

## Exact role flow

```text
SUPER_ADMIN
  -> creates/manages every Organization
  -> creates/replaces that Organization's ADMIN
  -> can enter any Organization workspace

ADMIN
  -> belongs to one Organization
  -> sees/manages only that Organization
  -> adds approved company domains/discovery seeds
  -> runs discovery and continuous monitoring
  -> manages organization ASM data
  -> creates/disables USER accounts only

USER
  -> belongs to the same Organization as its Admin
  -> sees only that Organization
  -> views attack-surface inventory, changes, exposures, vulnerabilities and reports
  -> can analyze/work with report data
  -> cannot create Organizations, Admins, domains, scans or schedules
```

## Tenant boundary

`organizations.id` is the tenant foreign key. It is **not** a Super Admin user ID.

`organization_memberships` maps normal platform accounts to a customer tenant and stores the tenant role (`admin` or `user`). Super Admin is a platform-level role and does not need an organization membership.

Tenant-owned records carry `organization_id`, including targets/assets, domains, scans, schedules, discovery seeds, discovered assets, relationships, observations, changes and exposures. Existing lower-level scan records inherit the tenant boundary through their parent Domain/Asset and PostgreSQL RLS.

Normal Admin/User requests never choose their organization. The backend derives it from the signed-in membership. `X-Organization-ID` is ignored for normal tenant members. Only a signed Super Admin JWT may use `X-Organization-ID` to enter a selected tenant workspace.

## First startup

Copy `backend/.env.example` to `backend/.env` and set at minimum:

```env
BOOTSTRAP_SUPER_ADMIN_EMAIL=your-platform-owner@example.com
BOOTSTRAP_SUPER_ADMIN_PASSWORD=Use-A-Strong-Password!123
BOOTSTRAP_SUPER_ADMIN_NAME=Platform Super Admin
```

The backend creates this account once if it does not already exist.

## Customer onboarding workflow

1. Super Admin logs in and lands on `/super-admin`.
2. Super Admin creates **Organization + initial Admin**.
3. The Organization Admin logs in and is automatically bound to that tenant.
4. Admin adds company domains and approved discovery seeds.
5. Admin runs discovery/continuous monitoring.
6. Results are persisted under that organization's `organization_id`.
7. Admin creates normal Users from **Users**. The API always creates role `USER`; the browser cannot request Admin/Super Admin.
8. Users work with inventory, exposures, vulnerabilities and reports without tenant-management permissions.
9. Super Admin can return to the platform console, replace an organization's Admin, disable/enable the organization, or open any tenant workspace.

## Backend authorization rules

| Operation | Super Admin | Organization Admin | User |
|---|---:|---:|---:|
| Create/disable Organization | Yes | No | No |
| Assign/change Organization Admin | Yes | No | No |
| Open any Organization | Yes | Own only | Own only |
| Create/disable normal Users | Yes, when inside tenant | Yes | No |
| Add company domain/seed | Yes, when inside tenant | Yes | No |
| Start/cancel/delete discovery | Yes, when inside tenant | Yes | No |
| Configure continuous monitoring | Yes, when inside tenant | Yes | No |
| View ASM inventory/changes/exposures | Yes | Yes | Yes |
| View/analyze vulnerabilities/reports | Yes | Yes | Yes |
| Change tenant Admin | Yes | No | No |

## PostgreSQL RLS

Migration `011_multitenant_organizations.py` replaces the older per-user policies with organization-aware Row-Level Security.

The application stores RLS context on the SQLAlchemy Session. An `after_begin` hook applies it with PostgreSQL `set_config(..., true)`, making it transaction-local. This has two benefits:

- pooled database connections do not retain another tenant's identity;
- after a rollback, the next transaction automatically receives the same authenticated tenant context again.

Normal members get `app.current_org_id=<membership organization>`. The Super Admin platform console uses the privileged bypass; when Super Admin opens a tenant workspace, bypass is disabled again and RLS is scoped to that selected organization.

## Upgrade note

Before applying migration 011 to an existing database, take a PostgreSQL backup. The migration intentionally has no automatic downgrade because converting from a per-user/single-tenant structure to a tenant-owned model is not safely reversible without restoring a backup.

Legacy accounts with the old global `admin` role are promoted to platform Super Admin during the upgrade to avoid locking out the existing owner. Existing enhanced-build organization/asset IDs are preserved when creating tenant records so historical ASM references remain connected. Review and assign the desired customer Admins from the Super Admin console after upgrade.

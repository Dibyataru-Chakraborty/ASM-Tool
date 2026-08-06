# Multi-Tenant ASM Implementation Notes

## Run the upgraded project

1. Back up the current PostgreSQL database.
2. Keep your existing `backend/.env`, then add the three `BOOTSTRAP_SUPER_ADMIN_*` variables shown in `.env.example`.
3. Rebuild the stack:

```powershell
docker compose down
docker compose up --build
```

The backend container already runs `alembic upgrade head`; the new head is `011_multitenant`.

## First acceptance test

Create two tenants to prove isolation:

- ORG-A -> Admin A -> User A
- ORG-B -> Admin B -> User B

Then verify:

1. Admin A adds `a.example` and can see only ORG-A data.
2. Admin B adds `b.example` and can see only ORG-B data.
3. User A can view/analyze ORG-A reports but cannot open Users/Discovery/Monitoring management actions.
4. Admin A cannot create an Admin or Super Admin; `/organization/users` always creates role USER.
5. Changing query-string IDs or adding `X-Organization-ID` as Admin A does not switch tenants.
6. Super Admin can open both workspaces from `/super-admin`.
7. Super Admin can replace Admin A; Admin A cannot replace itself with another Admin.
8. Disable ORG-B and confirm its members can no longer authenticate into an active tenant workspace.

## Main implementation files

Backend:
- `backend/app/models/organization.py`
- `backend/app/dependencies.py`
- `backend/app/utils/database.py`
- `backend/app/services/organization_service.py`
- `backend/app/services/auth_service.py`
- `backend/app/api/v1/organizations.py`
- `backend/alembic/versions/011_multitenant_organizations.py`

Frontend:
- `frontend/app/super-admin/page.tsx`
- `frontend/app/organization/users/page.tsx`
- `frontend/components/layout/Sidebar.tsx`
- `frontend/lib/auth.tsx`
- `frontend/lib/api.ts`
- `frontend/app/assets/page.tsx`
- `frontend/app/attack-surface/page.tsx`
- `frontend/app/asset-map/page.tsx`

## Important design rule

Never authorize a normal tenant request using `organization_id` supplied by the browser. The tenant comes from the authenticated membership/JWT and is reinforced by PostgreSQL RLS. Super Admin is the only role allowed to explicitly choose a tenant.

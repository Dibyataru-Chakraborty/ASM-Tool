'use client'

import { FormEvent, useEffect, useState } from 'react'
import AppLayout from '@/components/layout/AppLayout'
import asm from '@/lib/api'
import { AuthProvider, useAuth } from '@/lib/auth'

import {
  Building2,
  Users,
  ShieldAlert,
  Plus,
  ExternalLink,
  UserCog,
  Power,
  RefreshCw,
  X,
  Loader2,
  CheckCircle2,
} from 'lucide-react'


type OrganizationForm = {
  name: string
  description: string
  admin_name: string
  admin_email: string
  admin_password: string
}


const EMPTY_FORM: OrganizationForm = {
  name: '',
  description: '',
  admin_name: '',
  admin_email: '',
  admin_password: '',
}


/* =========================================================
   CHANGE ORGANIZATION ADMIN MODAL
   ========================================================= */

function AdminModal({
  org,
  onClose,
  onSaved,
}: {
  org: any
  onClose: () => void
  onSaved: () => void
}) {
  const [form, setForm] = useState({
    email: org.admin?.email || '',
    password: '',
    full_name: org.admin?.full_name || '',
  })

  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)

  const submit = async (e: FormEvent) => {
    e.preventDefault()

    setSaving(true)
    setError('')

    try {
      await asm.assignOrganizationAdmin(org.id, {
        email: form.email.trim(),
        full_name: form.full_name.trim() || undefined,
        password: form.password || undefined,
      })

      onSaved()
      onClose()
    } catch (err: any) {
      setError(
        err?.response?.data?.detail ||
          'Could not change organization Admin'
      )
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">

      <div
        className="absolute inset-0 bg-black/60"
        onClick={onClose}
      />

      <div className="card relative w-full max-w-md p-5">

        <div className="mb-4 flex items-center justify-between">

          <div>
            <h3 className="font-semibold text-gray-100">
              Change Admin · {org.name}
            </h3>

            <p className="mt-1 text-xs text-gray-500">
              Only Super Admin can assign an organization Admin.
            </p>
          </div>

          <button
            type="button"
            onClick={onClose}
          >
            <X className="h-4 w-4 text-gray-500" />
          </button>

        </div>


        {error && (
          <div className="mb-3 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-400">
            {error}
          </div>
        )}


        <form
          onSubmit={submit}
          autoComplete="off"
          className="space-y-3"
        >

          <div>
            <label className="mb-1 block text-xs text-gray-400">
              Admin Full Name
            </label>

            <input
              className="input"
              value={form.full_name}
              placeholder="John Smith"
              onChange={(e) =>
                setForm({
                  ...form,
                  full_name: e.target.value,
                })
              }
            />
          </div>


          <div>
            <label className="mb-1 block text-xs text-gray-400">
              Admin Email
            </label>

            <input
              className="input"
              type="email"
              required
              autoComplete="off"
              value={form.email}
              placeholder="admin@company.com"
              onChange={(e) =>
                setForm({
                  ...form,
                  email: e.target.value,
                })
              }
            />
          </div>


          <div>
            <label className="mb-1 block text-xs text-gray-400">
              New Password
            </label>

            <input
              className="input"
              type="password"
              autoComplete="new-password"
              value={form.password}
              placeholder="Required only for a new Admin"
              onChange={(e) =>
                setForm({
                  ...form,
                  password: e.target.value,
                })
              }
            />
          </div>


          <p className="text-xs text-gray-500">
            If the email is new, a password is required.
            Minimum 12 characters.
          </p>


          <div className="flex gap-2 pt-2">

            <button
              type="button"
              className="btn-gray flex-1"
              onClick={onClose}
            >
              Cancel
            </button>

            <button
              type="submit"
              className="btn-primary flex-1"
              disabled={saving}
            >
              {saving ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Saving...
                </>
              ) : (
                <>
                  <UserCog className="h-4 w-4" />
                  Assign Admin
                </>
              )}
            </button>

          </div>

        </form>

      </div>
    </div>
  )
}


/* =========================================================
   SUPER ADMIN PAGE
   ========================================================= */

function SuperAdminContent() {

  const {
    user,
    selectOrganization,
  } = useAuth()


  const [data, setData] = useState<any>(null)

  const [form, setForm] =
    useState<OrganizationForm>(EMPTY_FORM)

  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const [creating, setCreating] = useState(false)

  const [adminOrg, setAdminOrg] =
    useState<any>(null)

  const [working, setWorking] =
    useState<string | null>(null)


  /* =====================================================
     LOAD ORGANIZATIONS
     ===================================================== */

  const load = async () => {

    try {

      setError('')

      const result =
        await asm.getSuperAdminOverview()

      setData(result)

    } catch (err: any) {

      setError(
        err?.response?.data?.detail ||
          'Failed to load platform data'
      )

    }

  }


  useEffect(() => {

    if (
      user?.platform_role === 'super_admin'
    ) {
      load()
    }

  }, [user])


  /* =====================================================
     CREATE ORGANIZATION + ADMIN
     ===================================================== */

  const createOrganization = async (
    e: FormEvent<HTMLFormElement>
  ) => {

    e.preventDefault()

    setError('')
    setSuccess('')


    /* ---------- basic validation ---------- */

    if (!form.name.trim()) {

      setError(
        'Organization name is required.'
      )

      return
    }


    if (!form.admin_name.trim()) {

      setError(
        'Admin full name is required.'
      )

      return
    }


    if (!form.admin_email.trim()) {

      setError(
        'Admin email is required.'
      )

      return
    }


    if (form.admin_password.length < 12) {

      setError(
        'Admin password must contain at least 12 characters.'
      )

      return
    }


    setCreating(true)


    try {

      /* =============================================
         THIS REQUEST CREATES BOTH:
         
         1. Organization
         2. Admin User
         3. Organization Membership
         
         ============================================= */

      const result =
        await asm.createOrganization({

          name: form.name.trim(),

          description:
            form.description.trim() || null,

          admin_name:
            form.admin_name.trim(),

          admin_email:
            form.admin_email
              .trim()
              .toLowerCase(),

          admin_password:
            form.admin_password,

        })


      setSuccess(
        `Organization "${result.name}" and its Admin were created successfully.`
      )


      /* Clear Admin password immediately */

      setForm(EMPTY_FORM)


      /* Refresh organization list */

      await load()


    } catch (err: any) {

      console.error(
        'Organization creation failed:',
        err
      )


      const detail =
        err?.response?.data?.detail


      if (Array.isArray(detail)) {

        setError(
          detail
            .map(
              (item: any) =>
                item.msg || 'Validation error'
            )
            .join(', ')
        )

      } else {

        setError(
          detail ||
            'Could not create organization and Admin.'
        )

      }

    } finally {

      setCreating(false)

    }

  }


  /* =====================================================
     ENABLE / DISABLE ORGANIZATION
     ===================================================== */

  const toggleOrganization =
    async (org: any) => {

      setWorking(org.id)

      setError('')

      try {

        await asm.updateOrganization(
          org.id,
          {
            status:
              org.status === 'active'
                ? 'disabled'
                : 'active',
          }
        )

        await load()

      } catch (err: any) {

        setError(
          err?.response?.data?.detail ||
            'Could not update organization'
        )

      } finally {

        setWorking(null)

      }

    }


  /* =====================================================
     ACCESS CONTROL
     ===================================================== */

  if (
    user &&
    user.platform_role !== 'super_admin'
  ) {

    return (
      <AppLayout>

        <div className="card p-8 text-center">

          <ShieldAlert className="mx-auto h-8 w-8 text-red-400" />

          <h2 className="mt-3 font-semibold">
            Super Admin access required
          </h2>

          <p className="mt-1 text-sm text-gray-500">
            Organization Admins and Users
            cannot access the platform console.
          </p>

        </div>

      </AppLayout>
    )

  }


  return (

    <AppLayout>

      <div className="space-y-5">


        {/* =================================================
            PAGE HEADER
            ================================================= */}

        <div className="flex items-start justify-between">

          <div>

            <h2 className="text-xl font-semibold text-gray-100">
              Super Admin Console
            </h2>

            <p className="text-sm text-gray-500">
              Create customer organizations,
              assign their Admin accounts,
              and manage every tenant.
            </p>

          </div>


          <button
            type="button"
            className="btn-gray inline-flex items-center gap-2"
            onClick={load}
          >

            <RefreshCw className="h-4 w-4" />

            Refresh

          </button>

        </div>



        {/* =================================================
            STATISTICS
            ================================================= */}

        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">

          <div className="panel p-4">

            <Building2 className="h-5 w-5 text-blue-400" />

            <p className="mt-2 text-2xl font-semibold">
              {data?.organizations || 0}
            </p>

            <p className="text-xs text-gray-500">
              Organizations
            </p>

          </div>


          <div className="panel p-4">

            <Building2 className="h-5 w-5 text-blue-400" />

            <p className="mt-2 text-2xl font-semibold">
              {data?.active_organizations || 0}
            </p>

            <p className="text-xs text-gray-500">
              Active Organizations
            </p>

          </div>


          <div className="panel p-4">

            <Users className="h-5 w-5 text-blue-400" />

            <p className="mt-2 text-2xl font-semibold">
              {data?.total_users || 0}
            </p>

            <p className="text-xs text-gray-500">
              Tenant Users
            </p>

          </div>


          <div className="panel p-4">

            <ShieldAlert className="h-5 w-5 text-blue-400" />

            <p className="mt-2 text-2xl font-semibold">
              {data?.critical_exposures || 0}
            </p>

            <p className="text-xs text-gray-500">
              Critical Exposures
            </p>

          </div>

        </div>



        {/* =================================================
            SUCCESS / ERROR
            ================================================= */}

        {success && (

          <div className="flex items-center gap-2 rounded-lg border border-green-500/30 bg-green-500/10 p-3 text-sm text-green-400">

            <CheckCircle2 className="h-4 w-4" />

            {success}

          </div>

        )}


        {error && (

          <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-400">

            {error}

          </div>

        )}



        {/* =================================================
            CONTENT
            ================================================= */}

        <div className="grid gap-5 xl:grid-cols-[1fr_390px]">


          {/* =============================================
              ORGANIZATION LIST
              ============================================= */}

          <div className="panel overflow-hidden">

            <div className="border-b border-[#21262d] p-4">

              <h3 className="font-semibold">
                Customer Organizations
              </h3>

              <p className="text-xs text-gray-500">
                Each organization is an isolated tenant
                with its own Admin, Users and ASM data.
              </p>

            </div>


            <div className="divide-y divide-[#21262d]">


              {data?.items?.length ? (

                data.items.map((org: any) => (

                  <div
                    key={org.id}
                    className="p-4"
                  >

                    <div className="flex flex-col gap-3 lg:flex-row lg:items-center">


                      <div className="min-w-0 flex-1">

                        <div className="flex items-center gap-2">

                          <p className="font-medium text-gray-200">
                            {org.name}
                          </p>


                          <span
                            className={`rounded px-2 py-0.5 text-[10px] uppercase ${
                              org.status === 'active'
                                ? 'bg-green-500/10 text-green-400'
                                : 'bg-gray-500/10 text-gray-500'
                            }`}
                          >
                            {org.status}
                          </span>

                        </div>


                        <p className="mt-1 text-xs text-gray-500">

                          {org.code}

                          {' · '}

                          Admin:{' '}

                          {org.admin?.email ||
                            'Not assigned'}

                        </p>


                        <p className="mt-1 text-xs text-gray-600">

                          {org.user_count} member(s)

                          {' · '}

                          {org.asset_count} ASM assets

                          {' · '}

                          {org.critical_exposures}{' '}
                          critical exposures

                        </p>

                      </div>



                      <div className="flex flex-wrap gap-2">


                        <button
                          type="button"
                          className="btn-secondary"
                          onClick={() =>
                            setAdminOrg(org)
                          }
                        >

                          <UserCog className="h-4 w-4" />

                          Admin

                        </button>



                        <button
                          type="button"
                          className="btn-secondary"
                          disabled={
                            working === org.id
                          }
                          onClick={() =>
                            toggleOrganization(org)
                          }
                        >

                          <Power className="h-4 w-4" />

                          {org.status === 'active'
                            ? 'Disable'
                            : 'Enable'}

                        </button>



                        <button
                          type="button"
                          className="btn-primary"
                          disabled={
                            org.status !== 'active'
                          }
                          onClick={() =>
                            selectOrganization(
                              org.id
                            )
                          }
                        >

                          <ExternalLink className="h-4 w-4" />

                          Open Workspace

                        </button>


                      </div>

                    </div>

                  </div>

                ))

              ) : (

                <div className="p-10 text-center text-sm text-gray-500">

                  No organizations yet.

                </div>

              )}

            </div>

          </div>



          {/* =============================================
              CREATE ORGANIZATION + ADMIN
              ============================================= */}

          <form
            onSubmit={createOrganization}
            autoComplete="off"
            className="panel space-y-4 p-5"
          >


            <div>

              <h3 className="flex items-center gap-2 font-semibold">

                <Plus className="h-4 w-4 text-blue-400" />

                Create Organization

              </h3>


              <p className="mt-1 text-xs text-gray-500">

                Create the company tenant and its
                initial Admin account together.

              </p>

            </div>



            {/* Organization Name */}

            <div>

              <label className="mb-1 block text-xs font-medium text-gray-400">

                Organization Name *

              </label>


              <input
                className="input"
                type="text"
                required
                value={form.name}
                placeholder="ABC Pvt Ltd"
                onChange={(e) =>
                  setForm({
                    ...form,
                    name: e.target.value,
                  })
                }
              />

            </div>



            {/* Description */}

            <div>

              <label className="mb-1 block text-xs font-medium text-gray-400">

                Description

              </label>


              <textarea
                className="input h-20 resize-none"
                value={form.description}
                placeholder="Customer organization"
                onChange={(e) =>
                  setForm({
                    ...form,
                    description:
                      e.target.value,
                  })
                }
              />

            </div>



            <div className="border-t border-[#21262d] pt-4">

              <p className="text-xs font-semibold uppercase tracking-wide text-blue-400">

                Organization Admin

              </p>

            </div>



            {/* Admin Name */}

            <div>

              <label className="mb-1 block text-xs font-medium text-gray-400">

                Admin Full Name *

              </label>


              <input
                className="input"
                type="text"
                required
                autoComplete="off"
                value={form.admin_name}
                placeholder="John Smith"
                onChange={(e) =>
                  setForm({
                    ...form,
                    admin_name:
                      e.target.value,
                  })
                }
              />

            </div>



            {/* Admin Email */}

            <div>

              <label className="mb-1 block text-xs font-medium text-gray-400">

                Admin Login Email *

              </label>


              <input
                className="input"
                type="email"
                name="new-tenant-admin-email"
                required
                autoComplete="off"
                value={form.admin_email}
                placeholder="admin@company.com"
                onChange={(e) =>
                  setForm({
                    ...form,
                    admin_email:
                      e.target.value,
                  })
                }
              />

            </div>



            {/* Admin Password */}

            <div>

              <label className="mb-1 block text-xs font-medium text-gray-400">

                Admin Temporary Password *

              </label>


              <input
                className="input"
                type="password"
                name="new-tenant-admin-password"
                required
                minLength={12}
                autoComplete="new-password"
                value={form.admin_password}
                placeholder="Minimum 12 characters"
                onChange={(e) =>
                  setForm({
                    ...form,
                    admin_password:
                      e.target.value,
                  })
                }
              />


              <p className="mt-1 text-xs text-gray-500">

                This password will be used by the
                company's Admin to log in.

              </p>

            </div>



            {/* CREATE BUTTON */}

            <button
              type="submit"
              disabled={creating}
              className="btn-primary mt-3 w-full"
            >

              {creating ? (

                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Creating...
                </>

              ) : (

                <>
                  <Plus className="h-4 w-4" />
                  Create Organization + Admin
                </>

              )}

            </button>


          </form>

        </div>



        {/* =================================================
            ADMIN CHANGE MODAL
            ================================================= */}

        {adminOrg && (

          <AdminModal
            org={adminOrg}
            onClose={() =>
              setAdminOrg(null)
            }
            onSaved={load}
          />

        )}


      </div>

    </AppLayout>

  )
}



export default function SuperAdminPage() {

  return (

    <AuthProvider>

      <SuperAdminContent />

    </AuthProvider>

  )

}
'use client'
import Link from 'next/link'
export default function Register(){return <main className="min-h-screen flex items-center justify-center bg-[#0d1117]"><div className="panel max-w-md p-6 text-center"><h1 className="text-xl font-semibold">Account provisioning</h1><p className="mt-3 text-sm text-gray-400">Public registration is disabled. Platform Super Admin creates each organization and its Admin. Organization Admin creates the Users for that company.</p><Link className="btn-primary mt-5 inline-flex" href="/login">Back to Login</Link></div></main>}

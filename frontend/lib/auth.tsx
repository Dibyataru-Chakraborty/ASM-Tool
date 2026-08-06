'use client'
import { createContext,useContext,useEffect,useState,ReactNode } from 'react'
import { useRouter } from 'next/navigation'
import api from './api'
import type { User } from '@/types'
interface AuthContextType { user:User|null; loading:boolean; login:(e:string,p:string)=>Promise<void>; logout:()=>Promise<void>; isAuthenticated:boolean; selectOrganization:(id:string)=>void; exitOrganization:()=>void; refreshUser:()=>Promise<void> }
const AuthContext=createContext<AuthContextType>({user:null,loading:true,login:async()=>{},logout:async()=>{},isAuthenticated:false,selectOrganization:()=>{},exitOrganization:()=>{},refreshUser:async()=>{}})
export function AuthProvider({children}:{children:ReactNode}){
 const [user,setUser]=useState<User|null>(null); const [loading,setLoading]=useState(true); const router=useRouter()
 const refreshUser=async()=>{ const me=await api.getMe(); setUser(me) }
 useEffect(()=>{ const token=localStorage.getItem('access_token'); if(token){refreshUser().catch(()=>{localStorage.removeItem('access_token');localStorage.removeItem('active_organization_id')}).finally(()=>setLoading(false))}else setLoading(false)},[])
 const login=async(email:string,password:string)=>{ const result=await api.login({email,password}); if(result.platform_role!=='super_admin') localStorage.removeItem('active_organization_id'); await refreshUser(); router.push(result.platform_role==='super_admin'?'/super-admin':'/dashboard') }
 const logout=async()=>{try{await api.logout()}catch{} localStorage.removeItem('access_token');localStorage.removeItem('active_organization_id');setUser(null);router.push('/login')}
 const selectOrganization=(id:string)=>{localStorage.setItem('active_organization_id',id);window.location.href='/dashboard'}
 const exitOrganization=()=>{localStorage.removeItem('active_organization_id');window.location.href='/super-admin'}
 return <AuthContext.Provider value={{user,loading,login,logout,isAuthenticated:!!user,selectOrganization,exitOrganization,refreshUser}}>{children}</AuthContext.Provider>
}
export const useAuth=()=>useContext(AuthContext)

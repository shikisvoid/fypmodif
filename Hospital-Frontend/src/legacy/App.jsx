import React, { useState, useEffect } from 'react'
import { Shield, User, Lock, Calendar, FileText, Users, Activity, Settings, LogOut, CheckCircle, XCircle } from 'lucide-react'
import { login as authLogin, verifyMfa, fetchPatients, fetchAppointments, fetchMe, setTokens, clearTokens, fetchAdminMfaSecret } from '../auth'
import { ROLE_PERMISSIONS } from '../data'

const App = () => {
  const [authStage, setAuthStage] = useState('login') // login, mfa, authenticated
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [mfaCode, setMfaCode] = useState('')
  const [currentUser, setCurrentUser] = useState(null)
  // tokens are stored in localStorage via auth helpers
  const [error, setError] = useState('')
  const [activeTab, setActiveTab] = useState('dashboard')
  const [loginAttemptsLeft, setLoginAttemptsLeft] = useState(3)
  const [adminSecretResult, setAdminSecretResult] = useState(null)
  const [adminEmail, setAdminEmail] = useState('')
  const [adminLoading, setAdminLoading] = useState(false)
  const [adminError, setAdminError] = useState('')
  const [patients, setPatients] = useState([])
  const [appointments, setAppointments] = useState([])

  useEffect(() => {
    if (currentUser) {
      // subscribe to permission changes in a real app; here we re-read permissions from ROLE_PERMISSIONS
      setCurrentUser(prev => ({ ...prev, permissions: ROLE_PERMISSIONS[prev.role] }))
    }
  }, [currentUser])

  useEffect(() => {
    // Load profile + patients/appointments when authenticated
    if (authStage === 'authenticated') {
      fetchMe().then(r => { if (r?.success) setCurrentUser(r.user) })
      fetchPatients().then(r => { if (r?.success) setPatients(r.patients) })
      fetchAppointments().then(r => { if (r?.success) setAppointments(r.appointments) })
    }
  }, [authStage])

  const handleLogin = async (e) => {
    e && e.preventDefault()
    setError('')
  // clear any previous admin results
  setAdminSecretResult(null)

  const res = await authLogin(email.trim().toLowerCase(), password)
    if (!res.success) {
      setError(res.error || 'Login failed')
      // Attempt to infer remaining attempts from message
      if (res.error && res.error.toLowerCase().includes('locked')) {
        setError(`${res.error}`)
      }
      return
    }

    if (res.mfaRequired) {
      setAuthStage('mfa')
    } else {
      // persist tokens and continue
      setTokens({ token: res.token, refreshToken: res.refreshToken })
      setCurrentUser(res.user)
      setAuthStage('authenticated')
    }
  }

  const handleMfaVerify = async (e) => {
    e && e.preventDefault()
    setError('')
    const res = await verifyMfa(email.trim().toLowerCase(), mfaCode.trim())
    if (!res.success) {
      setError(res.error || 'MFA verification failed')
      return
    }
    setTokens({ token: res.token, refreshToken: res.refreshToken })
    setCurrentUser(res.user)
    setAuthStage('authenticated')
  }

  const handleLogout = () => {
    // revoke refresh token on backend
    const refresh = localStorage.getItem('hp_refresh_token')
    if (refresh) fetch('/api/logout', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ refreshToken: refresh }) }).catch(()=>{})
    clearTokens()
    setCurrentUser(null)
    setAuthStage('login')
    setEmail('')
    setPassword('')
    setMfaCode('')
    setError('')
    setActiveTab('dashboard')
    setAdminSecretResult(null)
  }

  const hasPermission = (permission) => {
    return currentUser?.permissions?.[permission] || false
  }

  // (rest of the file preserved in legacy copy)

  return null
}

export default App

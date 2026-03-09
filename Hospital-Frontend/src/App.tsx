import React, { useState, useEffect } from 'react'
import { Shield, User, Lock, Calendar, FileText, Users, Activity, Settings, LogOut, CheckCircle, XCircle, Plus, Eye, Edit, Clock, RefreshCw } from 'lucide-react'
import { login as authLogin, verifyMfa, fetchPatients, fetchAppointments, fetchMe, setTokens, clearTokens, fetchAdminMfaSecret, createPatient, updatePatient, deletePatient, createAppointment, updateAppointment, deleteAppointment, fetchDoctorDashboard, fetchReceptionistDashboard, fetchNurseDashboard, fetchAccountantDashboard, fetchNotifications } from './auth'
import { ROLE_PERMISSIONS } from './data'
import Sidebar from './components/Sidebar'
import Topbar from './components/Topbar'
import Card from './components/Card'
import Table from './components/Table'
import Button from './components/Button'
import Modal from './components/Modal'
import FileEncryption from './components/FileEncryption'
import LabTests from './components/LabTests'
import BillingNew from './components/BillingNew'
import Pharmacy from './components/Pharmacy'
import AdminDashboard from './components/AdminDashboard'
import AuditLogs from './components/AuditLogs'
import Prescriptions from './components/Prescriptions'
import LabBilling from './components/LabBilling'

const App = () => {
  const [authStage, setAuthStage] = useState('login') // login, mfa, authenticated
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [mfaCode, setMfaCode] = useState('')
  const [currentUser, setCurrentUser] = useState<any | null>(null)
  // tokens are stored in localStorage via auth helpers
  const [error, setError] = useState('')
  const [activeTab, setActiveTab] = useState('dashboard')
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [loginAttemptsLeft, setLoginAttemptsLeft] = useState(3)
  const [adminSecretResult, setAdminSecretResult] = useState<string | null>(null)
  const [adminEmail, setAdminEmail] = useState('')
  const [adminLoading, setAdminLoading] = useState(false)
  const [adminError, setAdminError] = useState('')
  const [patients, setPatients] = useState<any[]>([])
  const [appointments, setAppointments] = useState<any[]>([])

  // Dynamic dashboard states
  const [doctorDashboard, setDoctorDashboard] = useState<any>(null)
  const [receptionistDashboard, setReceptionistDashboard] = useState<any>(null)
  const [nurseDashboard, setNurseDashboard] = useState<any>(null)
  const [accountantDashboard, setAccountantDashboard] = useState<any>(null)
  const [notifications, setNotifications] = useState<any[]>([])
  const [dashboardLoading, setDashboardLoading] = useState(false)

  // Dialog states for Patients
  const [showAddPatient, setShowAddPatient] = useState(false)
  const [showViewPatient, setShowViewPatient] = useState(false)
  const [showEditPatient, setShowEditPatient] = useState(false)
  const [selectedPatient, setSelectedPatient] = useState<any | null>(null)

  // Dialog states for Appointments
  const [showScheduleAppointment, setShowScheduleAppointment] = useState(false)
  const [showViewAppointment, setShowViewAppointment] = useState(false)
  const [showRescheduleAppointment, setShowRescheduleAppointment] = useState(false)
  const [selectedAppointment, setSelectedAppointment] = useState<any | null>(null)

  // Form state for new patient
  const [newPatient, setNewPatient] = useState({
    name: '', age: '', condition: '', phone: '', email: '', address: '', insurance: '', gender: ''
  })

  // Form state for new appointment
  const [newAppointment, setNewAppointment] = useState({
    patientId: '', doctorName: '', date: '', time: '', reason: '', type: 'Checkup'
  })

  useEffect(() => {
    if (currentUser && currentUser.role) {
      // subscribe to permission changes in a real app; here we re-read permissions from ROLE_PERMISSIONS
      const role = currentUser.role as keyof typeof ROLE_PERMISSIONS
      setCurrentUser((prev: any) => ({ ...prev, permissions: ROLE_PERMISSIONS[role] }))
    }
  }, [currentUser])

  // Load role-specific dashboard data
  const loadDashboardData = async (role: string) => {
    setDashboardLoading(true)
    try {
      if (role === 'doctor') {
        const res = await fetchDoctorDashboard()
        if (res?.success) setDoctorDashboard(res.data)
      } else if (role === 'receptionist') {
        const res = await fetchReceptionistDashboard()
        if (res?.success) setReceptionistDashboard(res.data)
      } else if (role === 'nurse') {
        const res = await fetchNurseDashboard()
        if (res?.success) setNurseDashboard(res.data)
      } else if (role === 'accountant') {
        const res = await fetchAccountantDashboard()
        if (res?.success) setAccountantDashboard(res.data)
      }
      // Load notifications for all roles
      const notifRes = await fetchNotifications()
      if (notifRes?.success) setNotifications(notifRes.data || [])
    } catch (err) {
      console.error('Failed to load dashboard data:', err)
    } finally {
      setDashboardLoading(false)
    }
  }

  useEffect(() => {
    // Load profile + patients/appointments when authenticated
    if (authStage === 'authenticated') {
      fetchMe().then(r => {
        if (r?.success) {
          setCurrentUser(r.user)
          // Load role-specific dashboard
          loadDashboardData(r.user.role)
        }
      })
      fetchPatients().then(r => { if (r?.success) setPatients(r.patients) })
      fetchAppointments().then(r => { if (r?.success) setAppointments(r.appointments) })
    }
  }, [authStage])

  const handleLogin = async (e?: React.FormEvent) => {
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

  const handleMfaVerify = async (e?: React.FormEvent) => {
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

  const hasPermission = (permission: string) => {
    return currentUser?.permissions?.[permission] || false
  }

  const renderLogin = () => (
    <div className="min-h-screen flex items-center justify-center p-4 app-shell">
      <Card className="w-full max-w-md p-8 border border-blue-500/20">
        <div className="flex justify-center mb-6">
          <div className="logo bg-gradient-to-br from-blue-500 to-blue-600 shadow-lg">
            <Shield className="text-white" size={28} />
          </div>
        </div>
        <h2 className="text-3xl font-bold text-center mb-2">Hospital Portal</h2>
        <p className="text-center muted mb-8">Multi-Factor Authentication enabled for security</p>

        {error && (
          <div className="bg-red-500/20 border border-red-500/50 text-red-300 px-4 py-3 rounded-lg mb-4 text-sm">
            <strong>Error:</strong> {error}
          </div>
        )}

        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label className="block text-sm font-semibold mb-2 muted">Email Address</label>
            <div className="relative">
              <User className="absolute left-3 top-3 text-white/60" size={18} />
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full pl-10 pr-4 py-2.5 bg-white/5 border border-white/10 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
                placeholder="admin@hospital.com"
                required
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-semibold mb-2 muted">Password</label>
            <div className="relative">
              <Lock className="absolute left-3 top-3 text-white/60" size={18} />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && handleLogin(e)}
                className="w-full pl-10 pr-4 py-2.5 bg-white/5 border border-white/10 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
                placeholder="••••••••"
                required
              />
            </div>
          </div>

          <Button 
            type="submit"
            variant="primary"
            className="w-full py-2.5 text-base font-semibold mt-6"
          >
            Sign In
          </Button>
        </form>

        <div className="mt-6 pt-6 border-t border-white/10">
          <p className="text-xs muted text-center mb-2">Demo credentials available upon request</p>
        </div>
      </Card>
    </div>
  )

  const renderMfa = () => (
    <div className="min-h-screen flex items-center justify-center p-4 app-shell">
      <Card className="w-full max-w-md p-8 border border-green-500/20">
        <div className="flex justify-center mb-6">
          <div className="logo bg-gradient-to-br from-green-500 to-green-600 shadow-lg">
            <Shield className="text-white" size={24} />
          </div>
        </div>
        <h2 className="text-3xl font-bold text-center mb-2">Verify Your Identity</h2>
        <p className="text-center muted mb-8">Enter the 6-digit code from your authenticator app</p>

        {error && (
          <div className="bg-red-500/20 border border-red-500/50 text-red-300 px-4 py-3 rounded-lg mb-4 text-sm">
            <strong>Error:</strong> {error}
          </div>
        )}

        <form onSubmit={handleMfaVerify} className="space-y-4">
          <div>
            <input
              type="text"
              value={mfaCode}
              onChange={(e) => setMfaCode(e.target.value.replace(/[^\d]/g, '').slice(0, 6))}
              onKeyPress={(e) => e.key === 'Enter' && handleMfaVerify(e)}
              className="w-full px-4 py-3 bg-white/5 border-2 border-white/10 rounded-lg text-center text-4xl tracking-widest font-mono focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent transition"
              placeholder="000000"
              maxLength={6}
              inputMode="numeric"
              autoComplete="one-time-code"
              required
            />
          </div>

          <Button 
            type="submit"
            variant="primary"
            className="w-full py-2.5 text-base font-semibold mt-6"
          >
            Verify Code
          </Button>
        </form>

        <button 
          onClick={() => setAuthStage('login')}
          className="w-full mt-4 py-2 text-muted hover:text-white/90 text-sm font-medium transition"
        >
          Back to Login
        </button>
      </Card>
    </div>
  )

  const renderDashboard = () => {
    const role = currentUser?.role || 'guest'

    // Admin Dashboard
    if (role === 'admin') {
      return (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <Card className="border-l-4 border-blue-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">Total Patients</p>
                  <p className="stat-number">247</p>
                  <p className="text-xs text-green-400 mt-1">↑ 12% this month</p>
                </div>
                <Users className="text-blue-500" size={40} />
              </div>
            </Card>
            <Card className="border-l-4 border-green-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">Active Staff</p>
                  <p className="stat-number">45</p>
                  <p className="text-xs text-green-400 mt-1">8 online now</p>
                </div>
                <Activity className="text-green-500" size={40} />
              </div>
            </Card>
            <Card className="border-l-4 border-purple-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">Appointments</p>
                  <p className="stat-number">156</p>
                  <p className="text-xs text-yellow-400 mt-1">12 today</p>
                </div>
                <Calendar className="text-purple-500" size={40} />
              </div>
            </Card>
            <Card className="border-l-4 border-orange-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">System Health</p>
                  <p className="stat-number">99.8%</p>
                  <p className="text-xs text-green-400 mt-1">All systems OK</p>
                </div>
                <Shield className="text-orange-500" size={40} />
              </div>
            </Card>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card title="Department Overview" subtitle="Staff distribution across departments">
              <div className="space-y-3">
                {[{ dept: 'Cardiology', staff: 12, patients: 45 }, { dept: 'Neurology', staff: 8, patients: 32 }, { dept: 'Orthopedics', staff: 10, patients: 56 }].map(d => (
                  <div key={d.dept} className="flex items-center justify-between p-3 bg-white/5 rounded">
                    <div>
                      <p className="font-medium">{d.dept}</p>
                      <p className="text-xs muted">{d.staff} doctors, {d.patients} patients</p>
                    </div>
                    <div className="text-right">
                      <div className="w-24 h-2 bg-white/10 rounded-full overflow-hidden">
                        <div className="h-full bg-blue-500" style={{ width: `${(d.patients / 60) * 100}%` }}></div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </Card>

            <Card title="Recent Activity" subtitle="Latest system events">
              <div className="space-y-2">
                {[{ msg: 'New patient registered', time: '2 min ago', type: 'info' }, { msg: 'Appointment scheduled', time: '15 min ago', type: 'success' }, { msg: 'Report generated', time: '1 hour ago', type: 'info' }, { msg: 'Staff login', time: '2 hours ago', type: 'success' }].map((act, i) => (
                  <div key={i} className="flex items-center gap-3 p-2">
                    <div className={`w-2 h-2 rounded-full ${act.type === 'success' ? 'bg-green-500' : 'bg-blue-500'}`}></div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm truncate">{act.msg}</p>
                      <p className="text-xs muted">{act.time}</p>
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        </div>
      )
    }

    // Doctor Dashboard - Dynamic
    if (role === 'doctor') {
      const stats = doctorDashboard || {}
      return (
        <div className="space-y-6">
          <div className="flex justify-between items-center">
            <h2 className="text-xl font-bold text-white">Doctor Dashboard</h2>
            <Button variant="ghost" onClick={() => loadDashboardData('doctor')} disabled={dashboardLoading}>
              <RefreshCw size={16} className={`mr-2 ${dashboardLoading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <Card className="border-l-4 border-blue-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">My Patients</p>
                  <p className="stat-number">{stats.my_patients || 0}</p>
                  <p className="text-xs text-green-400 mt-1">Total assigned</p>
                </div>
                <Users className="text-blue-500" size={40} />
              </div>
            </Card>
            <Card className="border-l-4 border-green-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">Today's Appointments</p>
                  <p className="stat-number">{stats.todays_appointments || 0}</p>
                  <p className="text-xs text-yellow-400 mt-1">{stats.completed_today || 0} completed</p>
                </div>
                <Calendar className="text-green-500" size={40} />
              </div>
            </Card>
            <Card className="border-l-4 border-purple-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">Pending Appointments</p>
                  <p className="stat-number">{stats.pending_appointments || 0}</p>
                  <p className="text-xs text-orange-400 mt-1">Awaiting response</p>
                </div>
                <FileText className="text-purple-500" size={40} />
              </div>
            </Card>
            <Card className="border-l-4 border-orange-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">Pending Lab Results</p>
                  <p className="stat-number">{stats.pending_lab_results || 0}</p>
                  <p className="text-xs text-green-400 mt-1">Awaiting results</p>
                </div>
                <Activity className="text-orange-500" size={40} />
              </div>
            </Card>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card title="Patient Status Summary" subtitle="Overview of your appointments">
              <div className="space-y-3">
                {[
                  { status: 'Completed', count: stats.patient_status?.completed || 0, color: 'green' },
                  { status: 'In Progress', count: stats.patient_status?.in_progress || 0, color: 'blue' },
                  { status: 'Pending', count: stats.patient_status?.pending || 0, color: 'yellow' }
                ].map(s => (
                  <div key={s.status} className="flex items-center justify-between p-3 bg-white/5 rounded">
                    <div className="flex items-center gap-3">
                      <div className={`w-3 h-3 rounded-full bg-${s.color}-500`}></div>
                      <span className="font-medium">{s.status}</span>
                    </div>
                    <span className="text-lg font-semibold">{s.count}</span>
                  </div>
                ))}
              </div>
            </Card>

            <Card title="Upcoming Schedule" subtitle="Next 5 appointments">
              <div className="space-y-2">
                {(stats.upcoming_appointments || []).length === 0 ? (
                  <p className="text-gray-400 text-sm">No upcoming appointments</p>
                ) : (
                  stats.upcoming_appointments.map((apt: any, i: number) => (
                    <div key={i} className="flex items-center justify-between p-3 bg-white/5 rounded hover:bg-white/10 transition">
                      <div>
                        <p className="font-medium text-sm">{apt.patient}</p>
                        <p className="text-xs muted">{apt.type}</p>
                      </div>
                      <div className="text-right">
                        <span className="text-sm text-blue-400">{apt.time}</span>
                        <p className="text-xs text-gray-500">{apt.date}</p>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </Card>
          </div>
        </div>
      )
    }

    // Reception Dashboard - Dynamic
    if (role === 'receptionist') {
      const stats = receptionistDashboard || {}
      const statusBreakdown = stats.status_breakdown || {}
      return (
        <div className="space-y-6">
          <div className="flex justify-between items-center">
            <h2 className="text-xl font-bold text-white">Receptionist Dashboard</h2>
            <Button variant="ghost" onClick={() => loadDashboardData('receptionist')} disabled={dashboardLoading}>
              <RefreshCw size={16} className={`mr-2 ${dashboardLoading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <Card className="border-l-4 border-blue-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">Today's Patients</p>
                  <p className="stat-number">{stats.todays_patients || 0}</p>
                  <p className="text-xs text-green-400 mt-1">{stats.checked_in || 0} checked in</p>
                </div>
                <Users className="text-blue-500" size={40} />
              </div>
            </Card>
            <Card className="border-l-4 border-green-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">Pending Bills</p>
                  <p className="stat-number">{stats.pending_bills || 0}</p>
                  <p className="text-xs text-yellow-400 mt-1">Awaiting payment</p>
                </div>
                <Calendar className="text-green-500" size={40} />
              </div>
            </Card>
            <Card className="border-l-4 border-purple-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">Appointments</p>
                  <p className="stat-number">{stats.todays_appointments || 0}</p>
                  <p className="text-xs text-green-400 mt-1">Today</p>
                </div>
                <FileText className="text-purple-500" size={40} />
              </div>
            </Card>
            <Card className="border-l-4 border-orange-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">Cancellations</p>
                  <p className="stat-number">{stats.cancellations_today || 0}</p>
                  <p className="text-xs text-orange-400 mt-1">Today</p>
                </div>
                <Activity className="text-orange-500" size={40} />
              </div>
            </Card>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card title="Check-in Status" subtitle="Patient flow today">
              <div className="space-y-3">
                {[
                  { status: 'Checked In', count: statusBreakdown.checked_in || 0, color: 'green' },
                  { status: 'In Consultation', count: statusBreakdown.in_consultation || 0, color: 'blue' },
                  { status: 'Waiting', count: statusBreakdown.waiting || 0, color: 'yellow' },
                  { status: 'Completed', count: statusBreakdown.completed || 0, color: 'gray' }
                ].map(s => (
                  <div key={s.status} className="flex items-center justify-between p-3 bg-white/5 rounded">
                    <span className="font-medium">{s.status}</span>
                    <span className="text-lg font-semibold">{s.count}</span>
                  </div>
                ))}
              </div>
            </Card>

            <Card title="Appointment Queue" subtitle="Next 5 check-ins">
              <div className="space-y-2">
                {(stats.appointment_queue || []).length === 0 ? (
                  <p className="text-gray-400 text-sm">No appointments in queue</p>
                ) : (
                  stats.appointment_queue.map((apt: any, i: number) => (
                    <div key={i} className="flex items-center justify-between p-3 bg-white/5 rounded hover:bg-white/10 transition">
                      <div>
                        <p className="font-medium text-sm">{apt.patient}</p>
                        <p className="text-xs muted">{apt.doctor}</p>
                      </div>
                      <span className="text-sm text-green-400">{apt.time}</span>
                    </div>
                  ))
                )}
              </div>
            </Card>
          </div>
        </div>
      )
    }

    // Nurse Dashboard - Dynamic (No appointments/billing access)
    if (role === 'nurse') {
      const stats = nurseDashboard || {}
      return (
        <div className="space-y-6">
          <div className="flex justify-between items-center">
            <h2 className="text-xl font-bold text-white">Nurse Dashboard</h2>
            <Button variant="ghost" onClick={() => loadDashboardData('nurse')} disabled={dashboardLoading}>
              <RefreshCw size={16} className={`mr-2 ${dashboardLoading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <Card className="border-l-4 border-blue-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">Patients to Monitor</p>
                  <p className="stat-number">{stats.patients_to_monitor || 0}</p>
                  <p className="text-xs text-green-400 mt-1">Today</p>
                </div>
                <Users className="text-blue-500" size={40} />
              </div>
            </Card>
            <Card className="border-l-4 border-green-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">Vitals Pending</p>
                  <p className="stat-number">{stats.vitals_pending || 0}</p>
                  <p className="text-xs text-yellow-400 mt-1">Need recording</p>
                </div>
                <Activity className="text-green-500" size={40} />
              </div>
            </Card>
            <Card className="border-l-4 border-purple-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">Medications Due</p>
                  <p className="stat-number">{stats.medications_due || 0}</p>
                  <p className="text-xs text-orange-400 mt-1">Active prescriptions</p>
                </div>
                <FileText className="text-purple-500" size={40} />
              </div>
            </Card>
            <Card className="border-l-4 border-orange-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">Critical Alerts</p>
                  <p className="stat-number">{stats.critical_alerts || 0}</p>
                  <p className="text-xs text-green-400 mt-1">{stats.critical_alerts === 0 ? 'All stable' : 'Requires attention'}</p>
                </div>
                <Shield className="text-orange-500" size={40} />
              </div>
            </Card>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card title="Patient List" subtitle="Today's patients to monitor">
              <div className="space-y-2 max-h-[300px] overflow-y-auto">
                {(stats.patient_list || []).length === 0 ? (
                  <p className="text-gray-400 text-sm">No patients scheduled today</p>
                ) : (
                  stats.patient_list.map((p: any, i: number) => (
                    <div key={i} className="flex items-center justify-between p-3 bg-white/5 rounded hover:bg-white/10 transition">
                      <div>
                        <p className="font-medium text-sm">{p.name}</p>
                        <p className="text-xs muted">Scheduled: {p.time}</p>
                      </div>
                      <span className={`text-xs px-2 py-1 rounded ${
                        p.status === 'Completed' ? 'bg-green-500/20 text-green-400' :
                        p.status === 'in_progress' ? 'bg-blue-500/20 text-blue-400' :
                        'bg-yellow-500/20 text-yellow-400'
                      }`}>{p.status}</span>
                    </div>
                  ))
                )}
              </div>
            </Card>

            <Card title="Quick Actions" subtitle="Common nurse tasks">
              <div className="space-y-2">
                <Button variant="ghost" className="w-full justify-start" onClick={() => setActiveTab('patients')}>
                  <Users size={16} className="mr-2" /> View Patient Records
                </Button>
                <Button variant="ghost" className="w-full justify-start" onClick={() => setActiveTab('files')}>
                  <FileText size={16} className="mr-2" /> Access Medical Files
                </Button>
                <Button variant="ghost" className="w-full justify-start" onClick={() => setActiveTab('lab-tests')}>
                  <Activity size={16} className="mr-2" /> View Lab Results
                </Button>
              </div>
            </Card>
          </div>
        </div>
      )
    }

    // Lab Technician Dashboard
    if (role === 'lab_technician') {
      return (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <Card className="border-l-4 border-blue-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">Pending Tests</p>
                  <p className="stat-number">15</p>
                  <p className="text-xs text-yellow-400 mt-1">Awaiting collection</p>
                </div>
                <FileText className="text-blue-500" size={40} />
              </div>
            </Card>
            <Card className="border-l-4 border-green-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">Samples Collected</p>
                  <p className="stat-number">8</p>
                  <p className="text-xs text-green-400 mt-1">In processing</p>
                </div>
                <Activity className="text-green-500" size={40} />
              </div>
            </Card>
            <Card className="border-l-4 border-purple-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">Completed Today</p>
                  <p className="stat-number">12</p>
                  <p className="text-xs text-green-400 mt-1">Results sent</p>
                </div>
                <CheckCircle className="text-purple-500" size={40} />
              </div>
            </Card>
            <Card className="border-l-4 border-orange-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">Urgent Tests</p>
                  <p className="stat-number">3</p>
                  <p className="text-xs text-red-400 mt-1">Priority</p>
                </div>
                <Shield className="text-orange-500" size={40} />
              </div>
            </Card>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card title="Test Queue" subtitle="Tests awaiting processing">
              <div className="space-y-2">
                {[{ test: 'Blood Panel - CBC', patient: 'J*** D***', priority: 'Urgent', time: '9:00 AM' }, { test: 'Lipid Profile', patient: 'A*** B***', priority: 'Normal', time: '10:30 AM' }, { test: 'Urinalysis', patient: 'C*** D***', priority: 'Normal', time: '11:00 AM' }, { test: 'HbA1c', patient: 'M*** W***', priority: 'Urgent', time: '11:30 AM' }].map((t, i) => (
                  <div key={i} className="flex items-center justify-between p-3 bg-white/5 rounded hover:bg-white/10 transition">
                    <div>
                      <p className="font-medium text-sm">{t.test}</p>
                      <p className="text-xs muted">Patient: {t.patient}</p>
                    </div>
                    <div className="text-right">
                      <span className={`text-xs px-2 py-1 rounded ${t.priority === 'Urgent' ? 'bg-red-500/20 text-red-400' : 'bg-blue-500/20 text-blue-400'}`}>{t.priority}</span>
                      <p className="text-xs muted mt-1">{t.time}</p>
                    </div>
                  </div>
                ))}
              </div>
            </Card>

            <Card title="Recent Results" subtitle="Completed tests">
              <div className="space-y-2">
                {[{ test: 'Liver Function', status: 'Normal', time: '8:30 AM' }, { test: 'Thyroid Panel', status: 'Abnormal', time: '8:00 AM' }, { test: 'Complete Blood Count', status: 'Normal', time: '7:30 AM' }].map((r, i) => (
                  <div key={i} className="flex items-center justify-between p-3 bg-white/5 rounded">
                    <div>
                      <p className="font-medium text-sm">{r.test}</p>
                      <p className="text-xs muted">Completed: {r.time}</p>
                    </div>
                    <span className={`text-xs px-2 py-1 rounded ${r.status === 'Normal' ? 'bg-green-500/20 text-green-400' : 'bg-orange-500/20 text-orange-400'}`}>{r.status}</span>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        </div>
      )
    }

    // Pharmacist Dashboard
    if (role === 'pharmacist') {
      return (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <Card className="border-l-4 border-blue-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">Pending Prescriptions</p>
                  <p className="stat-number">18</p>
                  <p className="text-xs text-yellow-400 mt-1">To dispense</p>
                </div>
                <FileText className="text-blue-500" size={40} />
              </div>
            </Card>
            <Card className="border-l-4 border-green-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">Dispensed Today</p>
                  <p className="stat-number">42</p>
                  <p className="text-xs text-green-400 mt-1">Completed</p>
                </div>
                <CheckCircle className="text-green-500" size={40} />
              </div>
            </Card>
            <Card className="border-l-4 border-purple-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">Low Stock Items</p>
                  <p className="stat-number">5</p>
                  <p className="text-xs text-orange-400 mt-1">Reorder needed</p>
                </div>
                <Activity className="text-purple-500" size={40} />
              </div>
            </Card>
            <Card className="border-l-4 border-orange-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">Expiring Soon</p>
                  <p className="stat-number">8</p>
                  <p className="text-xs text-red-400 mt-1">Within 30 days</p>
                </div>
                <Shield className="text-orange-500" size={40} />
              </div>
            </Card>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card title="Prescription Queue" subtitle="Awaiting dispensing">
              <div className="space-y-2">
                {[{ medicine: 'Metformin 500mg', dosage: '2x daily', doctor: 'Dr. Smith', status: 'Ready' }, { medicine: 'Lisinopril 10mg', dosage: '1x daily', doctor: 'Dr. Johnson', status: 'Pending' }, { medicine: 'Atorvastatin 20mg', dosage: '1x daily', doctor: 'Dr. Brown', status: 'Pending' }].map((p, i) => (
                  <div key={i} className="flex items-center justify-between p-3 bg-white/5 rounded hover:bg-white/10 transition">
                    <div>
                      <p className="font-medium text-sm">{p.medicine}</p>
                      <p className="text-xs muted">{p.dosage} • {p.doctor}</p>
                    </div>
                    <span className={`text-xs px-2 py-1 rounded ${p.status === 'Ready' ? 'bg-green-500/20 text-green-400' : 'bg-yellow-500/20 text-yellow-400'}`}>{p.status}</span>
                  </div>
                ))}
              </div>
            </Card>

            <Card title="Inventory Alerts" subtitle="Stock management">
              <div className="space-y-2">
                {[{ item: 'Amoxicillin 500mg', stock: 15, reorder: 50, status: 'Low' }, { item: 'Insulin Regular', stock: 8, reorder: 20, status: 'Critical' }, { item: 'Paracetamol 500mg', stock: 200, reorder: 100, status: 'OK' }].map((inv, i) => (
                  <div key={i} className="flex items-center justify-between p-3 bg-white/5 rounded">
                    <div>
                      <p className="font-medium text-sm">{inv.item}</p>
                      <p className="text-xs muted">Stock: {inv.stock} | Reorder level: {inv.reorder}</p>
                    </div>
                    <span className={`text-xs px-2 py-1 rounded ${inv.status === 'OK' ? 'bg-green-500/20 text-green-400' : inv.status === 'Low' ? 'bg-yellow-500/20 text-yellow-400' : 'bg-red-500/20 text-red-400'}`}>{inv.status}</span>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        </div>
      )
    }

    // Accountant Dashboard - Dynamic (No patient access, view-only billing)
    if (role === 'accountant') {
      const stats = accountantDashboard || {}
      const breakdown = stats.revenue_breakdown || {}
      return (
        <div className="space-y-6">
          <div className="flex justify-between items-center">
            <h2 className="text-xl font-bold text-white">Accountant Dashboard</h2>
            <Button variant="ghost" onClick={() => loadDashboardData('accountant')} disabled={dashboardLoading}>
              <RefreshCw size={16} className={`mr-2 ${dashboardLoading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <Card className="border-l-4 border-blue-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">Outstanding Bills</p>
                  <p className="stat-number">{stats.outstanding_bills || 0}</p>
                  <p className="text-xs text-yellow-400 mt-1">Awaiting payment</p>
                </div>
                <FileText className="text-blue-500" size={40} />
              </div>
            </Card>
            <Card className="border-l-4 border-green-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">Today's Collections</p>
                  <p className="stat-number">${(stats.todays_collections || 0).toLocaleString()}</p>
                  <p className="text-xs text-green-400 mt-1">Collected today</p>
                </div>
                <Activity className="text-green-500" size={40} />
              </div>
            </Card>
            <Card className="border-l-4 border-purple-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">Total Revenue</p>
                  <p className="stat-number">${(stats.total_revenue || 0).toLocaleString()}</p>
                  <p className="text-xs text-green-400 mt-1">All time</p>
                </div>
                <Shield className="text-purple-500" size={40} />
              </div>
            </Card>
            <Card className="border-l-4 border-orange-500">
              <div className="flex items-center justify-between">
                <div>
                  <p className="muted text-sm">Pending Payments</p>
                  <p className="stat-number">${(stats.pending_payments || 0).toLocaleString()}</p>
                  <p className="text-xs text-red-400 mt-1">Outstanding</p>
                </div>
                <Calendar className="text-orange-500" size={40} />
              </div>
            </Card>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card title="Revenue Breakdown" subtitle="By category">
              <div className="space-y-3">
                {[
                  { category: 'Doctor Fees', amount: breakdown.doctor_fees || 0, color: 'blue' },
                  { category: 'Lab Fees', amount: breakdown.lab_fees || 0, color: 'green' },
                  { category: 'Pharmacy Fees', amount: breakdown.pharmacy_fees || 0, color: 'purple' }
                ].map(s => (
                  <div key={s.category} className="flex items-center justify-between p-3 bg-white/5 rounded">
                    <div className="flex items-center gap-3">
                      <div className={`w-3 h-3 rounded-full bg-${s.color}-500`}></div>
                      <span className="font-medium">{s.category}</span>
                    </div>
                    <span className="text-lg font-semibold text-green-400">${s.amount.toLocaleString()}</span>
                  </div>
                ))}
              </div>
            </Card>

            <Card title="Monthly Trend" subtitle="Last 6 months revenue">
              <div className="space-y-2">
                {(stats.monthly_trend || []).length === 0 ? (
                  <p className="text-gray-400 text-sm">No revenue data available</p>
                ) : (
                  stats.monthly_trend.map((m: any, i: number) => (
                    <div key={i} className="flex items-center justify-between p-3 bg-white/5 rounded">
                      <span className="font-medium">{m.month}</span>
                      <span className="text-lg font-semibold text-blue-400">${parseFloat(m.revenue || 0).toLocaleString()}</span>
                    </div>
                  ))
                )}
              </div>
            </Card>
          </div>

          <Card className="bg-yellow-500/5 border border-yellow-500/20">
            <p className="text-xs text-yellow-400">
              <strong>Note:</strong> As an accountant, you have view-only access to billing records. Patient personal information is not accessible for privacy compliance.
            </p>
          </Card>
        </div>
      )
    }

    // Default/Patient Dashboard
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <Card className="border-l-4 border-blue-500">
            <div className="flex items-center justify-between">
              <div>
                <p className="muted text-sm">My Appointments</p>
                <p className="stat-number">3</p>
                <p className="text-xs text-green-400 mt-1">Next: Dec 1</p>
              </div>
              <Calendar className="text-blue-500" size={40} />
            </div>
          </Card>
          <Card className="border-l-4 border-green-500">
            <div className="flex items-center justify-between">
              <div>
                <p className="muted text-sm">Medical Records</p>
                <p className="stat-number">12</p>
                <p className="text-xs text-green-400 mt-1">Up to date</p>
              </div>
              <FileText className="text-green-500" size={40} />
            </div>
          </Card>
          <Card className="border-l-4 border-purple-500">
            <div className="flex items-center justify-between">
              <div>
                <p className="muted text-sm">Prescriptions</p>
                <p className="stat-number">2</p>
                <p className="text-xs text-orange-400 mt-1">Active</p>
              </div>
              <Activity className="text-purple-500" size={40} />
            </div>
          </Card>
          <Card className="border-l-4 border-orange-500">
            <div className="flex items-center justify-between">
              <div>
                <p className="muted text-sm">Messages</p>
                <p className="stat-number">0</p>
                <p className="text-xs text-green-400 mt-1">All read</p>
              </div>
              <Users className="text-orange-500" size={40} />
            </div>
          </Card>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card title="Upcoming Appointments" subtitle="Your scheduled visits">
            <div className="space-y-2">
              {[{ doctor: 'Dr. Smith (Cardiology)', date: 'Dec 1, 2024', time: '10:00 AM' }, { doctor: 'Dr. Johnson (Neurology)', date: 'Dec 15, 2024', time: '2:00 PM' }, { doctor: 'Dr. Brown (Orthopedics)', date: 'Jan 5, 2025', time: '9:30 AM' }].map((apt, i) => (
                <div key={i} className="flex items-center justify-between p-3 bg-white/5 rounded hover:bg-white/10 transition">
                  <div>
                    <p className="font-medium text-sm">{apt.doctor}</p>
                    <p className="text-xs muted">{apt.date} at {apt.time}</p>
                  </div>
                  <span className="text-xs px-2 py-1 bg-blue-500/20 text-blue-400 rounded">Confirmed</span>
                </div>
              ))}
            </div>
          </Card>

          <Card title="Health Summary" subtitle="Your current health status">
            <div className="space-y-3">
              {[{ metric: 'Blood Pressure', value: '120/80 mmHg', status: 'Normal' }, { metric: 'Heart Rate', value: '72 bpm', status: 'Normal' }, { metric: 'Weight', value: '72 kg', status: 'Stable' }].map(m => (
                <div key={m.metric} className="flex items-center justify-between p-3 bg-white/5 rounded">
                  <div>
                    <p className="font-medium text-sm">{m.metric}</p>
                    <p className="text-xs muted">{m.value}</p>
                  </div>
                  <span className="text-xs px-2 py-1 bg-green-500/20 text-green-400 rounded">{m.status}</span>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>
    )
  }

  // ===== PATIENT DIALOGS =====
  const renderAddPatientDialog = () => (
    <Modal isOpen={showAddPatient} onClose={() => setShowAddPatient(false)} title="Add New Patient" size="lg">
      <form onSubmit={async (e) => {
        e.preventDefault()
        if (!newPatient.name || !newPatient.age || !newPatient.phone) {
          setError('Please fill all required fields')
          return
        }
        
        // Call backend API to create patient
        const res = await createPatient(newPatient)
        if (!res.success) {
          setError(res.error || 'Failed to add patient')
          return
        }
        
        // Add to frontend state
        const patient = {
          id: res.data?.id || Date.now(),
          name: newPatient.name,
          age: newPatient.age,
          condition: newPatient.condition,
          lastVisit: new Date().toISOString().split('T')[0],
          createdAt: new Date().toISOString(),
          ...res.data
        }
        setPatients([...patients, patient])
        setNewPatient({ name: '', age: '', condition: '', phone: '', email: '', address: '', insurance: '', gender: '' })
        setShowAddPatient(false)
        setError('')
      }} className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium mb-1">Full Name *</label>
            <input type="text" value={newPatient.name} onChange={(e) => setNewPatient({ ...newPatient, name: e.target.value })} className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded focus:outline-none focus:ring-2 focus:ring-blue-500" placeholder="John Doe" />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Age *</label>
            <input type="number" value={newPatient.age} onChange={(e) => setNewPatient({ ...newPatient, age: e.target.value })} className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded focus:outline-none focus:ring-2 focus:ring-blue-500" placeholder="25" />
          </div>
        </div>
        <div>
          <label className="block text-sm font-medium mb-1">Primary Condition</label>
          <input type="text" value={newPatient.condition} onChange={(e) => setNewPatient({ ...newPatient, condition: e.target.value })} className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded focus:outline-none focus:ring-2 focus:ring-blue-500" placeholder="Hypertension" />
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium mb-1">Phone *</label>
            <input type="tel" value={newPatient.phone} onChange={(e) => setNewPatient({ ...newPatient, phone: e.target.value })} className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded focus:outline-none focus:ring-2 focus:ring-blue-500" placeholder="+1 555 0100" />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Email</label>
            <input type="email" value={newPatient.email} onChange={(e) => setNewPatient({ ...newPatient, email: e.target.value })} className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded focus:outline-none focus:ring-2 focus:ring-blue-500" placeholder="john@example.com" />
          </div>
        </div>
        <div>
          <label className="block text-sm font-medium mb-1">Address</label>
          <input type="text" value={newPatient.address} onChange={(e) => setNewPatient({ ...newPatient, address: e.target.value })} className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded focus:outline-none focus:ring-2 focus:ring-blue-500" placeholder="123 Main St, City" />
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium mb-1">Insurance ID</label>
            <input type="text" value={newPatient.insurance} onChange={(e) => setNewPatient({ ...newPatient, insurance: e.target.value })} className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded focus:outline-none focus:ring-2 focus:ring-blue-500" placeholder="INS123456" />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Gender</label>
            <select value={newPatient.gender} onChange={(e) => setNewPatient({ ...newPatient, gender: e.target.value })} className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded focus:outline-none focus:ring-2 focus:ring-blue-500">
              <option value="">Select Gender</option>
              <option value="Male">Male</option>
              <option value="Female">Female</option>
              <option value="Other">Other</option>
            </select>
          </div>
        </div>
        <div className="flex gap-3 justify-end pt-4">
          <Button type="button" variant="ghost" onClick={() => setShowAddPatient(false)}>Cancel</Button>
          <Button type="submit" variant="primary">Add Patient</Button>
        </div>
      </form>
    </Modal>
  )

  // Helper function to format insurance display
  const formatInsurance = (insurance: any) => {
    if (!insurance) return 'Not provided'
    if (typeof insurance === 'string') return insurance
    if (typeof insurance === 'object') {
      if (insurance.provider && insurance.policy_id) {
        return `${insurance.provider} (${insurance.policy_id})`
      }
      if (insurance.provider) return insurance.provider
      if (insurance.id) return insurance.id
      if (insurance.policy_id) return insurance.policy_id
    }
    return 'Not provided'
  }

  const renderViewPatientDialog = () => selectedPatient && (
    <Modal isOpen={showViewPatient} onClose={() => setShowViewPatient(false)} title={`Patient Report: ${selectedPatient.name}`} size="lg">
      <div className="space-y-6">
        <div className="grid grid-cols-2 gap-4">
          <Card className="p-4">
            <p className="text-xs muted mb-1">Full Name</p>
            <p className="font-semibold">{selectedPatient.name}</p>
          </Card>
          <Card className="p-4">
            <p className="text-xs muted mb-1">Age</p>
            <p className="font-semibold">{selectedPatient.age} years old</p>
          </Card>
        </div>
        <Card className="p-4">
          <p className="text-xs muted mb-1">Primary Condition</p>
          <p className="font-semibold text-yellow-400">{selectedPatient.condition || 'Regular Checkup'}</p>
        </Card>
        <div className="grid grid-cols-2 gap-4">
          <Card className="p-4">
            <p className="text-xs muted mb-1">Contact</p>
            <p className="text-sm">{selectedPatient.phone || 'No phone'}</p>
            <p className="text-sm">{selectedPatient.email || 'No email'}</p>
          </Card>
          <Card className="p-4">
            <p className="text-xs muted mb-1">Insurance</p>
            <p className="font-semibold text-blue-400">{formatInsurance(selectedPatient.insurance)}</p>
          </Card>
        </div>
        <Card className="p-4">
          <p className="text-xs muted mb-1">Address</p>
          <p className="text-sm">{selectedPatient.address || 'Not provided'}</p>
        </Card>
        <Card className="p-4">
          <p className="text-xs muted mb-2">Last Visit</p>
          <p className="text-sm">{selectedPatient.lastVisit || 'N/A'}</p>
        </Card>
        <Card className="p-4">
          <p className="text-xs muted mb-2">Gender</p>
          <p className="text-sm">{selectedPatient.gender || 'Not specified'}</p>
        </Card>
        <div className="flex gap-3 justify-end pt-4">
          <Button variant="primary" onClick={() => setShowViewPatient(false)}>Close</Button>
        </div>
      </div>
    </Modal>
  )

  const renderEditPatientDialog = () => selectedPatient && (
    <Modal isOpen={showEditPatient} onClose={() => setShowEditPatient(false)} title={`Edit Patient: ${selectedPatient.name}`} size="lg">
      <form onSubmit={async (e) => {
        e.preventDefault()
        const res = await updatePatient(selectedPatient.id, selectedPatient)
        if (!res.success) {
          setError(res.error || 'Failed to update patient')
          return
        }
        const updatedPatients = patients.map(p => p.id === selectedPatient.id ? { ...selectedPatient } : p)
        setPatients(updatedPatients)
        setShowEditPatient(false)
        setSelectedPatient(null)
      }} className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium mb-1">Full Name</label>
            <input type="text" value={selectedPatient.name} onChange={(e) => setSelectedPatient({ ...selectedPatient, name: e.target.value })} disabled={!hasPermission('canEditPatients')} className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50" />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Age</label>
            <input type="number" value={selectedPatient.age} onChange={(e) => setSelectedPatient({ ...selectedPatient, age: e.target.value })} disabled={!hasPermission('canEditPatients')} className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50" />
          </div>
        </div>
        <div>
          <label className="block text-sm font-medium mb-1">Primary Condition</label>
          <input type="text" value={selectedPatient.condition} onChange={(e) => setSelectedPatient({ ...selectedPatient, condition: e.target.value })} disabled={!hasPermission('canEditPatients')} className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50" />
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium mb-1">Phone</label>
            <input type="tel" value={selectedPatient.phone} onChange={(e) => setSelectedPatient({ ...selectedPatient, phone: e.target.value })} disabled={!hasPermission('canEditPatients')} className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50" />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Email</label>
            <input type="email" value={selectedPatient.email} onChange={(e) => setSelectedPatient({ ...selectedPatient, email: e.target.value })} disabled={!hasPermission('canEditPatients')} className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50" />
          </div>
        </div>
        <div>
          <label className="block text-sm font-medium mb-1">Address</label>
          <input type="text" value={selectedPatient.address} onChange={(e) => setSelectedPatient({ ...selectedPatient, address: e.target.value })} disabled={!hasPermission('canEditPatients')} className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50" />
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium mb-1">Insurance ID</label>
            <input type="text" value={selectedPatient.insurance} onChange={(e) => setSelectedPatient({ ...selectedPatient, insurance: e.target.value })} disabled={!hasPermission('canEditPatients')} className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50" />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Gender</label>
            <select value={selectedPatient.gender || ''} onChange={(e) => setSelectedPatient({ ...selectedPatient, gender: e.target.value })} disabled={!hasPermission('canEditPatients')} className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50">
              <option value="">Select Gender</option>
              <option value="Male">Male</option>
              <option value="Female">Female</option>
              <option value="Other">Other</option>
            </select>
          </div>
        </div>
        <div className="flex gap-3 justify-end pt-4">
          <Button type="button" variant="ghost" onClick={() => { setShowEditPatient(false); setSelectedPatient(null) }}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={!hasPermission('canEditPatients')}>Save Changes</Button>
        </div>
      </form>
    </Modal>
  )

  // ===== APPOINTMENT DIALOGS =====
  const renderScheduleAppointmentDialog = () => (
    <Modal isOpen={showScheduleAppointment} onClose={() => setShowScheduleAppointment(false)} title="Schedule New Appointment" size="lg">
      <form onSubmit={async (e) => {
        e.preventDefault()
        if (!newAppointment.patientId || !newAppointment.doctorName || !newAppointment.date || !newAppointment.time) {
          setError('Please fill all required fields')
          return
        }
        
        const res = await createAppointment({
          ...newAppointment,
          patientId: parseInt(newAppointment.patientId),
          appointmentType: newAppointment.type
        })
        
        if (!res.success) {
          setError(res.error || 'Failed to schedule appointment')
          return
        }
        
        const apt = {
          id: res.data?.id || Date.now(),
          ...newAppointment,
          status: 'Scheduled',
          patient: patients.find(p => p.id === parseInt(newAppointment.patientId))?.name || newAppointment.patientId,
          doctor: newAppointment.doctorName,
          ...res.data
        }
        setAppointments([...appointments, apt])
        setNewAppointment({ patientId: '', doctorName: '', date: '', time: '', reason: '', type: 'Checkup' })
        setShowScheduleAppointment(false)
        setError('')
      }} className="space-y-4">
        <div>
          <label className="block text-sm font-medium mb-1">Select Patient *</label>
          <select value={newAppointment.patientId} onChange={(e) => setNewAppointment({ ...newAppointment, patientId: e.target.value })} className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded focus:outline-none focus:ring-2 focus:ring-blue-500">
            <option value="">Choose a patient...</option>
            {patients.map(p => <option key={p.id} value={p.id}>{p.name} ({p.age}y)</option>)}
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium mb-1">Doctor Name *</label>
          <input type="text" value={newAppointment.doctorName} onChange={(e) => setNewAppointment({ ...newAppointment, doctorName: e.target.value })} className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded focus:outline-none focus:ring-2 focus:ring-blue-500" placeholder="Dr. Jane Smith" />
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium mb-1">Date *</label>
            <input type="date" value={newAppointment.date} onChange={(e) => setNewAppointment({ ...newAppointment, date: e.target.value })} className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded focus:outline-none focus:ring-2 focus:ring-blue-500" />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Time *</label>
            <input type="time" value={newAppointment.time} onChange={(e) => setNewAppointment({ ...newAppointment, time: e.target.value })} className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded focus:outline-none focus:ring-2 focus:ring-blue-500" />
          </div>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium mb-1">Appointment Type</label>
            <select value={newAppointment.type} onChange={(e) => setNewAppointment({ ...newAppointment, type: e.target.value })} className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded focus:outline-none focus:ring-2 focus:ring-blue-500">
              <option>Checkup</option>
              <option>Follow-up</option>
              <option>Emergency</option>
              <option>Consultation</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Reason</label>
            <input type="text" value={newAppointment.reason} onChange={(e) => setNewAppointment({ ...newAppointment, reason: e.target.value })} className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded focus:outline-none focus:ring-2 focus:ring-blue-500" placeholder="Annual checkup" />
          </div>
        </div>
        <div className="flex gap-3 justify-end pt-4">
          <Button type="button" variant="ghost" onClick={() => setShowScheduleAppointment(false)}>Cancel</Button>
          <Button type="submit" variant="primary">Schedule</Button>
        </div>
      </form>
    </Modal>
  )

  const renderViewAppointmentDialog = () => selectedAppointment && (
    <Modal isOpen={showViewAppointment} onClose={() => setShowViewAppointment(false)} title="Appointment Details" size="lg">
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <Card className="p-4">
            <p className="text-xs muted mb-1">Patient</p>
            <p className="font-semibold">{selectedAppointment.patient}</p>
          </Card>
          <Card className="p-4">
            <p className="text-xs muted mb-1">Doctor</p>
            <p className="font-semibold">{selectedAppointment.doctor}</p>
          </Card>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <Card className="p-4">
            <p className="text-xs muted mb-1">Date & Time</p>
            <p className="font-semibold">{selectedAppointment.date} at {selectedAppointment.time}</p>
          </Card>
          <Card className="p-4">
            <p className="text-xs muted mb-1">Type</p>
            <p className="font-semibold text-blue-400">{selectedAppointment.type}</p>
          </Card>
        </div>
        <Card className="p-4">
          <p className="text-xs muted mb-1">Reason</p>
          <p className="text-sm">{selectedAppointment.reason || 'N/A'}</p>
        </Card>
        <Card className="p-4">
          <p className="text-xs muted mb-1">Status</p>
          <span className={`px-2 py-1 rounded text-xs font-semibold ${selectedAppointment.status === 'Scheduled' ? 'bg-blue-500/20 text-blue-400' : 'bg-green-500/20 text-green-400'}`}>{selectedAppointment.status}</span>
        </Card>
        <div className="flex gap-3 justify-end pt-4">
          <Button variant="primary" onClick={() => setShowViewAppointment(false)}>Close</Button>
        </div>
      </div>
    </Modal>
  )

  const renderRescheduleAppointmentDialog = () => selectedAppointment && (
    <Modal isOpen={showRescheduleAppointment} onClose={() => setShowRescheduleAppointment(false)} title="Reschedule Appointment" size="md">
      <form onSubmit={async (e) => {
        e.preventDefault()
        const res = await updateAppointment(selectedAppointment.id, {
          ...selectedAppointment,
          patientId: selectedAppointment.patient_id,
          doctorId: selectedAppointment.doctor_id,
          appointmentType: selectedAppointment.appointment_type
        })
        
        if (!res.success) {
          setError(res.error || 'Failed to reschedule appointment')
          return
        }
        
        const updatedAppointments = appointments.map(a => a.id === selectedAppointment.id ? { ...selectedAppointment } : a)
        setAppointments(updatedAppointments)
        setShowRescheduleAppointment(false)
        setSelectedAppointment(null)
      }} className="space-y-4">
        <div>
          <label className="block text-sm font-medium mb-1">New Date *</label>
          <input type="date" value={selectedAppointment.date} onChange={(e) => setSelectedAppointment({ ...selectedAppointment, date: e.target.value })} className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded focus:outline-none focus:ring-2 focus:ring-blue-500" />
        </div>
        <div>
          <label className="block text-sm font-medium mb-1">New Time *</label>
          <input type="time" value={selectedAppointment.time} onChange={(e) => setSelectedAppointment({ ...selectedAppointment, time: e.target.value })} className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded focus:outline-none focus:ring-2 focus:ring-blue-500" />
        </div>
        <div>
          <label className="block text-sm font-medium mb-1">Reason for Reschedule</label>
          <input type="text" value={selectedAppointment.reason} onChange={(e) => setSelectedAppointment({ ...selectedAppointment, reason: e.target.value })} className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded focus:outline-none focus:ring-2 focus:ring-blue-500" placeholder="Optional notes" />
        </div>
        <div className="flex gap-3 justify-end pt-4">
          <Button type="button" variant="ghost" onClick={() => { setShowRescheduleAppointment(false); setSelectedAppointment(null) }}>Cancel</Button>
          <Button type="submit" variant="primary">Reschedule</Button>
        </div>
      </form>
    </Modal>
  )

  const renderPatients = () => (
    <>
      {renderAddPatientDialog()}
      {renderViewPatientDialog()}
      {renderEditPatientDialog()}
      <Card className="overflow-hidden">
        <div className="px-6 py-4 border-b border-white/6 flex justify-between items-center">
          <h3 className="text-lg font-semibold">Patient Records</h3>
          {hasPermission('canEditPatients') && (
            <Button variant="primary" onClick={() => setShowAddPatient(true)}><Plus size={16} className="mr-2" />Add Patient</Button>
          )}
        </div>
        <Table>
          <thead className="bg-white/3">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-semibold uppercase">Name</th>
              <th className="px-6 py-3 text-left text-xs font-semibold uppercase">Age</th>
              <th className="px-6 py-3 text-left text-xs font-semibold uppercase">Condition</th>
              <th className="px-6 py-3 text-left text-xs font-semibold uppercase">Last Visit</th>
              <th className="px-6 py-3 text-left text-xs font-semibold uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/6">
            {patients.map(patient => (
              <tr key={patient.id} className="hover:bg-white/2">
                <td className="px-6 py-4 text-sm">{patient.name}</td>
                <td className="px-6 py-4 text-sm">{patient.age}</td>
                <td className="px-6 py-4 text-sm">{patient.condition}</td>
                <td className="px-6 py-4 text-sm">{patient.lastVisit}</td>
                <td className="px-6 py-4 text-sm flex gap-2">
                  <Button variant="ghost" size="sm" onClick={() => { setSelectedPatient(patient); setShowViewPatient(true); }}><Eye size={16} className="mr-1" />View</Button>
                  {hasPermission('canEditPatients') && (
                    <Button variant="ghost" size="sm" onClick={() => { setSelectedPatient(patient); setShowEditPatient(true); }}><Edit size={16} className="mr-1" />Edit</Button>
                  )}
                  {hasPermission('canDeletePatients') && (
                    <Button variant="danger" size="sm" onClick={async () => { 
                      if (confirm('Are you sure you want to delete this patient?')) {
                        const res = await deletePatient(patient.id)
                        if (res.success) {
                          setPatients(patients.filter(p => p.id !== patient.id))
                        } else {
                          setError(res.error || 'Failed to delete patient')
                        }
                      }
                    }}>Delete</Button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Card>
    </>
  )

  // Handle appointment status update (accept/reject)
  const handleAppointmentStatusUpdate = async (apt: any, newStatus: string) => {
    const res = await updateAppointment(apt.id, {
      ...apt,
      patientId: apt.patient_id,
      doctorId: apt.doctor_id,
      appointmentType: apt.appointment_type || apt.type,
      status: newStatus
    })
    if (res.success) {
      setAppointments(appointments.map(a => a.id === apt.id ? { ...a, status: newStatus } : a))
    } else {
      setError(res.error || `Failed to ${newStatus.toLowerCase()} appointment`)
    }
  }

  const renderAppointments = () => {
    const isDoctor = currentUser?.role === 'doctor'

    return (
    <>
      {renderScheduleAppointmentDialog()}
      {renderViewAppointmentDialog()}
      {renderRescheduleAppointmentDialog()}
      <Card className="overflow-hidden">
        <div className="px-6 py-4 border-b border-white/6 flex justify-between items-center">
          <h3 className="text-lg font-semibold">{isDoctor ? 'My Appointments' : 'Appointments'}</h3>
          {hasPermission('canManageAppointments') && (
            <Button variant="primary" onClick={() => setShowScheduleAppointment(true)}><Clock size={16} className="mr-2" />Schedule New</Button>
          )}
        </div>
        <Table>
          <thead className="bg-white/3">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-semibold uppercase">Patient</th>
              <th className="px-6 py-3 text-left text-xs font-semibold uppercase">Doctor</th>
              <th className="px-6 py-3 text-left text-xs font-semibold uppercase">Date</th>
              <th className="px-6 py-3 text-left text-xs font-semibold uppercase">Time</th>
              <th className="px-6 py-3 text-left text-xs font-semibold uppercase">Status</th>
              <th className="px-6 py-3 text-left text-xs font-semibold uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/6">
            {appointments.map(apt => (
              <tr key={apt.id} className="hover:bg-white/2">
                <td className="px-6 py-4 text-sm">{apt.patient}</td>
                <td className="px-6 py-4 text-sm">{apt.doctor}</td>
                <td className="px-6 py-4 text-sm">{apt.date}</td>
                <td className="px-6 py-4 text-sm">{apt.time}</td>
                <td className="px-6 py-4 text-sm">
                  <span className={`px-2 py-1 rounded text-xs font-semibold ${
                    apt.status === 'Scheduled' || apt.status === 'pending' ? 'bg-yellow-500/20 text-yellow-400' :
                    apt.status === 'Accepted' || apt.status === 'confirmed' ? 'bg-green-500/20 text-green-400' :
                    apt.status === 'Rejected' || apt.status === 'cancelled' ? 'bg-red-500/20 text-red-400' :
                    apt.status === 'Completed' ? 'bg-blue-500/20 text-blue-400' :
                    'bg-gray-500/20 text-gray-400'
                  }`}>
                    {apt.status}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm flex gap-2 flex-wrap">
                  <Button variant="ghost" size="sm" onClick={() => { setSelectedAppointment(apt); setShowViewAppointment(true); }}><Eye size={16} className="mr-1" />View</Button>

                  {/* Doctor-specific actions: Accept/Reject for pending appointments */}
                  {isDoctor && (apt.status === 'Scheduled' || apt.status === 'pending') && (
                    <>
                      <Button
                        variant="primary"
                        size="sm"
                        onClick={() => handleAppointmentStatusUpdate(apt, 'Accepted')}
                        className="bg-green-600 hover:bg-green-700"
                      >
                        <CheckCircle size={16} className="mr-1" />Accept
                      </Button>
                      <Button
                        variant="danger"
                        size="sm"
                        onClick={() => handleAppointmentStatusUpdate(apt, 'Rejected')}
                      >
                        <XCircle size={16} className="mr-1" />Reject
                      </Button>
                    </>
                  )}

                  {/* Reschedule option for doctors and receptionists */}
                  {(isDoctor || hasPermission('canManageAppointments')) && apt.status !== 'Rejected' && apt.status !== 'Completed' && (
                    <Button variant="ghost" size="sm" onClick={() => { setSelectedAppointment(apt); setShowRescheduleAppointment(true); }}><Clock size={16} className="mr-1" />Reschedule</Button>
                  )}

                  {/* Mark as completed for doctors */}
                  {isDoctor && (apt.status === 'Accepted' || apt.status === 'confirmed') && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleAppointmentStatusUpdate(apt, 'Completed')}
                      className="text-blue-400"
                    >
                      <CheckCircle size={16} className="mr-1" />Complete
                    </Button>
                  )}

                  {/* Delete option for receptionists/admins */}
                  {hasPermission('canManageAppointments') && !isDoctor && (
                    <Button variant="danger" size="sm" onClick={async () => {
                      if (confirm('Are you sure you want to delete this appointment?')) {
                        const res = await deleteAppointment(apt.id)
                        if (res.success) {
                          setAppointments(appointments.filter(a => a.id !== apt.id))
                        } else {
                          setError(res.error || 'Failed to delete appointment')
                        }
                      }
                    }}>Delete</Button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Card>
    </>
  )}

  const renderPortal = () => (
    <div className="min-h-screen flex app-shell">
      <Sidebar 
        currentUser={currentUser} 
        activeTab={activeTab} 
        setActiveTab={setActiveTab} 
        hasPermission={hasPermission} 
        onLogout={handleLogout}
        isOpen={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
      />

      <main className="flex-1 flex flex-col">
        <Topbar 
          title={activeTab.charAt(0).toUpperCase() + activeTab.slice(1)} 
          currentUser={currentUser}
          onToggleSidebar={() => setSidebarOpen(!sidebarOpen)}
          sidebarOpen={sidebarOpen}
        />

        <div className="p-6 max-w-7xl mx-auto flex-1">
          {activeTab === 'dashboard' && renderDashboard()}
          {activeTab === 'patients' && renderPatients()}
          {activeTab === 'appointments' && renderAppointments()}
          {activeTab === 'files' && (
            <FileEncryption
              userEmail={currentUser?.email || ''}
              userName={currentUser?.name || ''}
              userRole={currentUser?.role || ''}
              hasViewPermission={hasPermission('canViewPatients')}
              hasDownloadPermission={hasPermission('canDownloadFiles') || currentUser?.role === 'doctor'}
            />
          )}
          {activeTab === 'lab-tests' && (
            <LabTests
              userEmail={currentUser?.email || ''}
              userName={currentUser?.name || ''}
              userRole={currentUser?.role || ''}
              hasViewPermission={hasPermission('canViewPatients')}
            />
          )}
          {activeTab === 'prescriptions' && (
            <Prescriptions
              userRole={currentUser?.role || ''}
              userName={currentUser?.name || ''}
            />
          )}
          {activeTab === 'billing' && (
            <BillingNew
              userEmail={currentUser?.email || ''}
              userName={currentUser?.name || ''}
              userRole={currentUser?.role || ''}
              hasViewPermission={hasPermission('canViewBilling')}
            />
          )}
          {activeTab === 'pharmacy' && (
            <Pharmacy
              userEmail={currentUser?.email || ''}
              userName={currentUser?.name || ''}
              userRole={currentUser?.role || ''}
              hasViewPermission={hasPermission('canViewPatients')}
            />
          )}
          {activeTab === 'admin-dashboard' && (
            <AdminDashboard
              userEmail={currentUser?.email || ''}
              userName={currentUser?.name || ''}
              userRole={currentUser?.role || ''}
              hasViewPermission={true}
            />
          )}
          {activeTab === 'audit-logs' && (
            <AuditLogs userRole={currentUser?.role || ''} />
          )}
          {activeTab === 'lab-billing' && (
            <LabBilling
              userEmail={currentUser?.email || ''}
              userName={currentUser?.name || ''}
              userRole={currentUser?.role || ''}
            />
          )}
          {activeTab === 'admin' && renderAdmin()}
        </div>
      </main>
    </div>
  )

  async function doFetchAdminSecret() {
    setAdminError('')
    setAdminSecretResult(null)
    setAdminLoading(true)
    try {
      const r = await fetchAdminMfaSecret(adminEmail.trim().toLowerCase())
      if (r?.success) setAdminSecretResult(r.secret)
      else setAdminError(r.error || 'Failed')
    } catch (err) {
      setAdminError('Network error')
    }
    setAdminLoading(false)
  }

  function renderAdmin() {
    return (
      <Card>
        <h3 className="text-lg font-semibold mb-4">Admin: Provision MFA Secret</h3>
        <div className="flex items-center space-x-2 mb-4">
          <input value={adminEmail} onChange={e => setAdminEmail(e.target.value)} className="px-3 py-2 bg-transparent border border-white/6 rounded w-80" placeholder="user@hospital.com" />
          <Button onClick={doFetchAdminSecret} className="bg-blue-600 text-white">{adminLoading ? 'Loading...' : 'Get Secret'}</Button>
        </div>
        {adminError && <div className="text-red-400 mb-2">{adminError}</div>}
        {adminSecretResult && <div className="text-sm">Base32 secret: <strong className="text-green-400">{adminSecretResult}</strong></div>}
      </Card>
    )
  }

  if (authStage === 'login') return renderLogin()
  if (authStage === 'mfa') return renderMfa()
  return renderPortal()
}

export default App

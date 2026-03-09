import React from 'react'
import { Users, User, Calendar, Settings, Shield, LogOut, Home, X, Lock, Pill, DollarSign, TestTube, BarChart3, Activity, FileText, Receipt } from 'lucide-react'

type Props = {
  currentUser: any
  activeTab: string
  setActiveTab: (s: string) => void
  hasPermission: (p: string) => boolean
  onLogout: () => void
  isOpen?: boolean
  onClose?: () => void
}

export default function Sidebar({ currentUser, activeTab, setActiveTab, hasPermission, onLogout, isOpen = true, onClose }: Props) {
  const navItems = [
    { key: 'dashboard', label: 'Dashboard', icon: Home, show: true },
    { key: 'patients', label: 'Patients', icon: User, show: hasPermission('canViewPatients') },
    { key: 'appointments', label: 'Appointments', icon: Calendar, show: hasPermission('canViewAppointments') },
    { key: 'files', label: 'Patient Files', icon: Lock, show: hasPermission('canViewPatients') },
    { key: 'lab-tests', label: 'Lab Tests', icon: TestTube, show: hasPermission('canViewLabs') },
    { key: 'lab-billing', label: 'Lab Billing', icon: Receipt, show: currentUser?.role === 'lab_technician' },
    { key: 'prescriptions', label: 'Prescriptions', icon: FileText, show: currentUser?.role === 'doctor' || currentUser?.role === 'pharmacist' },
    { key: 'billing', label: 'Billing', icon: DollarSign, show: hasPermission('canViewBilling') },
    { key: 'pharmacy', label: 'Pharmacy', icon: Pill, show: hasPermission('canViewPharmacy') },
    { key: 'admin-dashboard', label: 'Admin Dashboard', icon: BarChart3, show: currentUser?.role === 'admin' },
    { key: 'audit-logs', label: 'Audit Logs', icon: Activity, show: currentUser?.role === 'admin' },
    { key: 'admin', label: 'Admin Tools', icon: Shield, show: hasPermission('canManageUsers') },
  ]

  const handleNavClick = (tab: string) => {
    setActiveTab(tab)
    // Auto-close sidebar on mobile when nav item clicked
    if (onClose && !isOpen) {
      // Already closed
    }
  }

  return (
    <aside className={`sidebar flex flex-col transition-all duration-300 ${isOpen ? 'sidebar-open' : 'sidebar-closed md:sidebar-open'}`}>
      <div className="brand flex items-center justify-between px-4 py-5">
        <div className="flex items-center gap-3 flex-1 min-w-0">
          <div className="logo flex items-center justify-center flex-shrink-0">
            <Home size={24} />
          </div>
          <div className="min-w-0">
            <div className="text-sm font-bold truncate">Hospital Portal</div>
            <div className="text-xs muted truncate">{currentUser?.role || 'User'}</div>
          </div>
        </div>
        {onClose && (
          <button
            onClick={onClose}
            aria-label="Close sidebar"
            className="md:hidden p-1.5 hover:bg-white/10 rounded transition flex-shrink-0"
          >
            <X size={20} className="text-white/70" />
          </button>
        )}
      </div>

      <nav className="mt-4 flex-1 px-2 space-y-1 overflow-y-auto">
        {navItems.map(item => {
          if (!item.show) return null
          const Icon = item.icon
          const isActive = activeTab === item.key
          return (
            <button
              key={item.key}
              onClick={() => handleNavClick(item.key)}
              className={`w-full nav-item ${isActive ? 'active bg-blue-600/20 border-l-4 border-blue-500' : 'hover:bg-white/5 border-l-4 border-transparent'}`}
            >
              <Icon size={18} className="flex-shrink-0" />
              <span className="font-medium truncate">{item.label}</span>
            </button>
          )
        })}
      </nav>

      <div className="p-4 border-t border-white/10">
        <button 
          onClick={onLogout} 
          className="w-full py-2 px-3 bg-red-600/20 hover:bg-red-600/40 text-red-300 hover:text-red-200 rounded-lg flex items-center justify-center gap-2 font-medium transition"
        >
          <LogOut size={16}/>
          Logout
        </button>
      </div>
    </aside>
  )
}

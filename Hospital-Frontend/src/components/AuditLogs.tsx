import React, { useState, useEffect } from 'react'
import { Search, Filter, Download, RefreshCw, Shield, AlertTriangle, CheckCircle, XCircle, Activity, Eye } from 'lucide-react'
import Card from './Card'

interface AuditLog {
  id: string
  user_id: string
  action: string
  resource_type: string
  resource_id: string
  ip_address: string
  user_agent: string
  details: {
    severity?: string
    userEmail?: string
    userRole?: string
    status?: string
    reason?: string
  }
  created_at: string
  actor_name?: string
  actor_email?: string
}

interface Metrics {
  totalLogs: number
  auditLogs: number
  applicationLogs: number
  errorCount: number
  loginFailures: number
  mfaFailures: number
  decryptAttempts: number
  decryptFailures: number
  unauthorizedAccess: number
  uptimeFormatted: string
  byService: Record<string, number>
  bySeverity: Record<string, number>
}

interface AuditLogsProps {
  userRole: string
}

const AuditLogs: React.FC<AuditLogsProps> = ({ userRole }) => {
  const [logs, setLogs] = useState<AuditLog[]>([])
  const [metrics, setMetrics] = useState<Metrics | null>(null)
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [actionFilter, setActionFilter] = useState('')
  const [viewMode, setViewMode] = useState<'logs' | 'metrics'>('logs')
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null)
  const [autoRefresh, setAutoRefresh] = useState(false)

  useEffect(() => {
    loadData()
    if (autoRefresh) {
      const interval = setInterval(loadData, 10000)
      return () => clearInterval(interval)
    }
  }, [search, severityFilter, actionFilter, autoRefresh])

  const loadData = async () => {
    try {
      const token = localStorage.getItem('hp_access_token')
      if (!token) return

      const params = new URLSearchParams()
      params.append('limit', '100')
      if (search) params.append('search', search)
      if (severityFilter) params.append('severity', severityFilter)
      if (actionFilter) params.append('action', actionFilter)

      const [logsRes, metricsRes] = await Promise.all([
        fetch(`/api/audit-logs?${params.toString()}`, {
          headers: { 'Authorization': `Bearer ${token}` }
        }),
        fetch('/api/monitoring/metrics', {
          headers: { 'Authorization': `Bearer ${token}` }
        })
      ])

      if (logsRes.ok) {
        const data = await logsRes.json()
        setLogs(data.data || [])
      }
      if (metricsRes.ok) {
        const data = await metricsRes.json()
        setMetrics(data.metrics)
      }
    } catch (error) {
      console.error('Failed to load audit data:', error)
    } finally {
      setLoading(false)
    }
  }

  const getSeverityColor = (severity?: string) => {
    switch (severity) {
      case 'CRITICAL': return 'bg-red-500/20 text-red-400 border-red-500/30'
      case 'ERROR': return 'bg-orange-500/20 text-orange-400 border-orange-500/30'
      case 'WARN': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
      case 'INFO': return 'bg-blue-500/20 text-blue-400 border-blue-500/30'
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30'
    }
  }

  const getActionIcon = (action: string) => {
    if (action.includes('LOGIN_SUCCESS') || action.includes('MFA_SUCCESS')) return <CheckCircle size={14} className="text-green-400" />
    if (action.includes('FAILURE') || action.includes('DENIED')) return <XCircle size={14} className="text-red-400" />
    if (action.includes('ENCRYPT') || action.includes('DECRYPT')) return <Shield size={14} className="text-purple-400" />
    return <Activity size={14} className="text-blue-400" />
  }

  const exportLogs = () => {
    const csv = [
      ['Timestamp', 'Action', 'User', 'IP Address', 'Severity', 'Status'].join(','),
      ...logs.map(log => [
        log.created_at,
        log.action,
        log.details?.userEmail || 'N/A',
        log.ip_address || 'N/A',
        log.details?.severity || 'INFO',
        log.details?.status || 'N/A'
      ].map(v => `"${v}"`).join(','))
    ].join('\n')
    
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `audit-logs-${new Date().toISOString().split('T')[0]}.csv`
    a.click()
  }

  if (userRole !== 'admin') {
    return (
      <Card className="text-center p-8">
        <AlertTriangle size={48} className="mx-auto text-yellow-400 mb-4" />
        <h2 className="text-xl font-bold text-white mb-2">Access Restricted</h2>
        <p className="text-gray-400">Only administrators can access audit logs and monitoring.</p>
      </Card>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <Shield className="text-blue-400" /> Centralized Logging & Monitoring
          </h2>
          <p className="text-gray-400 text-sm mt-1">Security audit logs and real-time system metrics</p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => setAutoRefresh(!autoRefresh)}
            className={`px-3 py-2 rounded text-sm flex items-center gap-1 ${autoRefresh ? 'bg-green-500/20 text-green-400' : 'bg-white/5 text-gray-400'}`}>
            <RefreshCw size={14} className={autoRefresh ? 'animate-spin' : ''} /> Auto
          </button>
          <button onClick={exportLogs} className="px-3 py-2 bg-white/5 text-gray-400 rounded text-sm flex items-center gap-1 hover:bg-white/10">
            <Download size={14} /> Export
          </button>
        </div>
      </div>

      {/* Metrics Cards */}
      {metrics && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
          <Card className="border-l-4 border-blue-500">
            <p className="text-gray-400 text-xs">Total Logs</p>
            <p className="text-2xl font-bold text-white">{metrics.totalLogs}</p>
          </Card>
          <Card className="border-l-4 border-red-500">
            <p className="text-gray-400 text-xs">Login Failures</p>
            <p className="text-2xl font-bold text-red-400">{metrics.loginFailures}</p>
          </Card>
          <Card className="border-l-4 border-yellow-500">
            <p className="text-gray-400 text-xs">MFA Failures</p>
            <p className="text-2xl font-bold text-yellow-400">{metrics.mfaFailures}</p>
          </Card>
          <Card className="border-l-4 border-purple-500">
            <p className="text-gray-400 text-xs">Decrypt Attempts</p>
            <p className="text-2xl font-bold text-purple-400">{metrics.decryptAttempts}</p>
          </Card>
          <Card className="border-l-4 border-orange-500">
            <p className="text-gray-400 text-xs">Unauthorized</p>
            <p className="text-2xl font-bold text-orange-400">{metrics.unauthorizedAccess}</p>
          </Card>
          <Card className="border-l-4 border-green-500">
            <p className="text-gray-400 text-xs">Uptime</p>
            <p className="text-lg font-bold text-green-400">{metrics.uptimeFormatted}</p>
          </Card>
        </div>
      )}

      {/* View Toggle & Filters */}
      <div className="flex flex-wrap gap-4 items-center">
        <div className="flex bg-white/5 rounded-lg p-1">
          <button onClick={() => setViewMode('logs')}
            className={`px-4 py-2 rounded text-sm ${viewMode === 'logs' ? 'bg-blue-600 text-white' : 'text-gray-400'}`}>
            Audit Logs
          </button>
          <button onClick={() => setViewMode('metrics')}
            className={`px-4 py-2 rounded text-sm ${viewMode === 'metrics' ? 'bg-blue-600 text-white' : 'text-gray-400'}`}>
            Metrics Detail
          </button>
        </div>

        <div className="flex-1 relative">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
          <input type="text" placeholder="Search logs..." value={search} onChange={e => setSearch(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-white/5 border border-white/10 rounded text-white text-sm" />
        </div>

        <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}
          className="px-3 py-2 bg-white/5 border border-white/10 rounded text-white text-sm">
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="ERROR">Error</option>
          <option value="WARN">Warning</option>
          <option value="INFO">Info</option>
        </select>

        <select value={actionFilter} onChange={e => setActionFilter(e.target.value)}
          className="px-3 py-2 bg-white/5 border border-white/10 rounded text-white text-sm">
          <option value="">All Actions</option>
          <option value="IAM:">IAM Events</option>
          <option value="MFA:">MFA Events</option>
          <option value="ENCRYPTION:">Encryption Events</option>
        </select>
      </div>

      {/* Logs Table */}
      {viewMode === 'logs' && (
        <Card>
          {loading ? (
            <p className="text-gray-400 text-center py-8">Loading audit logs...</p>
          ) : logs.length === 0 ? (
            <p className="text-gray-400 text-center py-8">No audit logs found</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-white/10 text-gray-400">
                    <th className="px-4 py-3 text-left">Time</th>
                    <th className="px-4 py-3 text-left">Action</th>
                    <th className="px-4 py-3 text-left">User</th>
                    <th className="px-4 py-3 text-left">IP Address</th>
                    <th className="px-4 py-3 text-left">Severity</th>
                    <th className="px-4 py-3 text-left">Status</th>
                    <th className="px-4 py-3 text-left"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {logs.map(log => (
                    <tr key={log.id} className="hover:bg-white/2">
                      <td className="px-4 py-3 text-gray-400 text-xs whitespace-nowrap">
                        {new Date(log.created_at).toLocaleString()}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          {getActionIcon(log.action)}
                          <span className="text-white font-mono text-xs">{log.action}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-gray-300 text-xs">{log.details?.userEmail || log.actor_email || 'N/A'}</td>
                      <td className="px-4 py-3 text-gray-400 text-xs font-mono">{log.ip_address || 'N/A'}</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-1 text-xs rounded border ${getSeverityColor(log.details?.severity)}`}>
                          {log.details?.severity || 'INFO'}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-1 text-xs rounded ${log.details?.status === 'success' ? 'bg-green-500/20 text-green-400' : log.details?.status === 'failure' ? 'bg-red-500/20 text-red-400' : 'bg-gray-500/20 text-gray-400'}`}>
                          {log.details?.status || 'N/A'}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <button onClick={() => setSelectedLog(log)} className="text-blue-400 hover:text-blue-300">
                          <Eye size={14} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}

      {/* Metrics Detail View */}
      {viewMode === 'metrics' && metrics && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Card>
            <h3 className="text-lg font-semibold text-white mb-4">Logs by Service</h3>
            <div className="space-y-3">
              {Object.entries(metrics.byService || {}).map(([service, count]) => (
                <div key={service} className="flex justify-between items-center">
                  <span className="text-gray-400">{service}</span>
                  <span className="text-white font-mono">{count}</span>
                </div>
              ))}
            </div>
          </Card>
          <Card>
            <h3 className="text-lg font-semibold text-white mb-4">Logs by Severity</h3>
            <div className="space-y-3">
              {Object.entries(metrics.bySeverity || {}).map(([severity, count]) => (
                <div key={severity} className="flex justify-between items-center">
                  <span className={getSeverityColor(severity).replace('bg-', 'text-').split(' ')[1]}>{severity}</span>
                  <span className="text-white font-mono">{count}</span>
                </div>
              ))}
            </div>
          </Card>
        </div>
      )}

      {/* Log Detail Modal */}
      {selectedLog && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setSelectedLog(null)}>
          <div className="max-w-2xl w-full mx-4 max-h-[80vh] overflow-auto" onClick={e => e.stopPropagation()}>
            <Card className="w-full">
              <div className="flex justify-between items-center mb-4">
                <h3 className="text-lg font-semibold text-white">Log Details</h3>
                <button onClick={() => setSelectedLog(null)} className="text-gray-400 hover:text-white">&times;</button>
              </div>
            <pre className="bg-black/30 p-4 rounded text-xs text-gray-300 overflow-auto">
              {JSON.stringify(selectedLog, null, 2)}
            </pre>
            </Card>
          </div>
        </div>
      )}
    </div>
  )
}

export default AuditLogs


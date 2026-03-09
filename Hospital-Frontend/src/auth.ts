const API_BASE = ''

const ACCESS_KEY = 'hp_access_token'
const REFRESH_KEY = 'hp_refresh_token'

type TokenPair = { token?: string; refreshToken?: string }

export function setTokens({ token, refreshToken }: TokenPair) {
  if (token) localStorage.setItem(ACCESS_KEY, token)
  if (refreshToken) localStorage.setItem(REFRESH_KEY, refreshToken)
}

export function clearTokens() {
  localStorage.removeItem(ACCESS_KEY)
  localStorage.removeItem(REFRESH_KEY)
}

export function getAccessToken(): string | null {
  return localStorage.getItem(ACCESS_KEY)
}

export function getRefreshToken(): string | null {
  return localStorage.getItem(REFRESH_KEY)
}

async function fetchWithAuth(input: string, init: RequestInit = {}, retry = true): Promise<Response> {
  const token = getAccessToken()
  init.headers = init.headers || {}
  if (token && typeof init.headers !== 'string') (init.headers as Record<string, string>)['Authorization'] = `Bearer ${token}`
  try {
    const res = await fetch(`${API_BASE}${input}`, init)
    if (res.status === 401 && retry) {
      const refresh = getRefreshToken()
      if (!refresh) return res
      const rres = await fetch(`${API_BASE}/api/token/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: refresh })
      })
      if (rres.ok) {
        const rdata = await rres.json()
        if (rdata.success && rdata.token) {
          setTokens({ token: rdata.token, refreshToken: rdata.refreshToken })
          ;(init.headers as Record<string, string>)['Authorization'] = `Bearer ${rdata.token}`
          return fetch(`${API_BASE}${input}`, init)
        }
      }
    }
    return res
  } catch (err) {
    throw err
  }
}

export async function login(email: string, password: string) {
  try {
    // Auth endpoints are proxied via Vite dev server
    console.log('Attempting login to /api/login')
    const res = await fetch(`${API_BASE}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    })
    console.log('Login response status:', res.status)
    const data = await res.json()
    console.log('Login response:', data)
    return data
  } catch (err) {
    console.error('Login error:', err)
    return { success: false, error: 'Network error' }
  }
}

export async function verifyMfa(email: string, code: string) {
  try {
    // Auth endpoints are proxied via Vite dev server
    console.log('Attempting MFA verify to /api/mfa/verify')
    const res = await fetch(`${API_BASE}/api/mfa/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, code })
    })
    console.log('MFA verify response status:', res.status)
    const data = await res.json()
    console.log('MFA verify response:', data)
    return data
  } catch (err) {
    console.error('MFA verify error:', err)
    return { success: false, error: 'Network error' }
  }
}

export async function fetchPatients() {
  const res = await fetchWithAuth(`/api/patients`, { method: 'GET' })
  return res.json()
}

export async function fetchAppointments() {
  const res = await fetchWithAuth(`/api/appointments`, { method: 'GET' })
  return res.json()
}

export async function fetchMe() {
  const res = await fetchWithAuth(`/api/me`, { method: 'GET' })
  return res.json()
}

export async function fetchAdminMfaSecret(email: string) {
  // Admin MFA secret is proxied via Vite dev server
  const res = await fetch(`${API_BASE}/api/admin/mfa/secret?email=${encodeURIComponent(email)}`, { method: 'GET' })
  return res.json()
}

export async function updatePatient(patientId: string, patientData: any) {
  const res = await fetchWithAuth(`/api/patients/${patientId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      first_name: patientData.name?.split(' ')[0] || patientData.firstName,
      last_name: patientData.name?.split(' ')[1] || patientData.lastName,
      dob: patientData.dob,
      gender: patientData.gender || 'Not specified',
      contact: patientData.phone || patientData.contact,
      insurance: patientData.insurance
    })
  })
  return res.json()
}

export async function createPatient(patientData: any) {
  const res = await fetchWithAuth('/api/patients', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      first_name: patientData.name?.split(' ')[0] || '',
      last_name: patientData.name?.split(' ')[1] || '',
      dob: patientData.dob,
      gender: patientData.gender || 'Not specified',
      contact: patientData.phone || patientData.contact,
      insurance: patientData.insurance
    })
  })
  return res.json()
}

export async function deletePatient(patientId: string) {
  const res = await fetchWithAuth(`/api/patients/${patientId}`, {
    method: 'DELETE'
  })
  return res.json()
}

export async function createAppointment(appointmentData: any) {
  const res = await fetchWithAuth('/api/appointments', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      patient_id: appointmentData.patientId,
      doctor_id: appointmentData.doctorId,
      scheduled_at: new Date(`${appointmentData.date}T${appointmentData.time}`).toISOString(),
      appointment_type: appointmentData.appointmentType || 'consultation',
      notes: appointmentData.notes || appointmentData.reason
    })
  })
  return res.json()
}

export async function updateAppointment(appointmentId: string, appointmentData: any) {
  const res = await fetchWithAuth(`/api/appointments/${appointmentId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      patient_id: appointmentData.patientId,
      doctor_id: appointmentData.doctorId,
      scheduled_at: new Date(`${appointmentData.date}T${appointmentData.time}`).toISOString(),
      appointment_type: appointmentData.appointmentType,
      notes: appointmentData.notes,
      status: appointmentData.status
    })
  })
  return res.json()
}

export async function deleteAppointment(appointmentId: string) {
  const res = await fetchWithAuth(`/api/appointments/${appointmentId}`, {
    method: 'DELETE'
  })
  return res.json()
}

// Dashboard endpoints for different roles
export async function fetchDoctorDashboard() {
  const res = await fetchWithAuth('/api/doctor/dashboard', { method: 'GET' })
  return res.json()
}

export async function fetchReceptionistDashboard() {
  const res = await fetchWithAuth('/api/receptionist/dashboard', { method: 'GET' })
  return res.json()
}

export async function fetchNurseDashboard() {
  const res = await fetchWithAuth('/api/nurse/dashboard', { method: 'GET' })
  return res.json()
}

export async function fetchAccountantDashboard() {
  const res = await fetchWithAuth('/api/accountant/dashboard', { method: 'GET' })
  return res.json()
}

export async function fetchNotifications() {
  const res = await fetchWithAuth('/api/notifications', { method: 'GET' })
  return res.json()
}

export async function markNotificationRead(notificationId: string) {
  const res = await fetchWithAuth(`/api/notifications/${notificationId}/read`, {
    method: 'PUT'
  })
  return res.json()
}

export async function updateLabFees(billingId: string, labFees: number) {
  const res = await fetchWithAuth(`/api/billing/${billingId}/lab-fees`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ lab_fees: labFees })
  })
  return res.json()
}


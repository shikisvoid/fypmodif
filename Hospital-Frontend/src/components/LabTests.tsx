import React, { useState, useEffect } from 'react'
import { Plus, Download, Eye, FileUp, Clock, CheckCircle, AlertCircle, Beaker, Microscope, Badge, Search, RefreshCw, User, Trash2, FileText, Lock, Unlock, Shield } from 'lucide-react'
import Card from './Card'
import Button from './Button'
import Modal from './Modal'

// Test-specific field templates
const TEST_FIELD_TEMPLATES: { [key: string]: { name: string, unit: string, normalRange: string }[] } = {
  'Complete Blood Count (CBC)': [
    { name: 'hemoglobin', unit: 'g/dL', normalRange: '12-17' },
    { name: 'hematocrit', unit: '%', normalRange: '36-50' },
    { name: 'white_blood_cells', unit: 'cells/mcL', normalRange: '4500-11000' },
    { name: 'red_blood_cells', unit: 'million/mcL', normalRange: '4.5-5.5' },
    { name: 'platelets', unit: 'cells/mcL', normalRange: '150000-400000' },
  ],
  'Blood Glucose Test': [
    { name: 'fasting_glucose', unit: 'mg/dL', normalRange: '70-100' },
    { name: 'random_glucose', unit: 'mg/dL', normalRange: '< 140' },
  ],
  'Lipid Panel': [
    { name: 'total_cholesterol', unit: 'mg/dL', normalRange: '< 200' },
    { name: 'ldl_cholesterol', unit: 'mg/dL', normalRange: '< 100' },
    { name: 'hdl_cholesterol', unit: 'mg/dL', normalRange: '> 40' },
    { name: 'triglycerides', unit: 'mg/dL', normalRange: '< 150' },
  ],
  'Liver Function Test (LFT)': [
    { name: 'alt', unit: 'U/L', normalRange: '7-56' },
    { name: 'ast', unit: 'U/L', normalRange: '10-40' },
    { name: 'alkaline_phosphatase', unit: 'U/L', normalRange: '44-147' },
    { name: 'bilirubin_total', unit: 'mg/dL', normalRange: '0.1-1.2' },
    { name: 'albumin', unit: 'g/dL', normalRange: '3.5-5.0' },
  ],
  'Thyroid Panel': [
    { name: 'tsh', unit: 'mIU/L', normalRange: '0.4-4.0' },
    { name: 't3', unit: 'ng/dL', normalRange: '80-200' },
    { name: 't4', unit: 'mcg/dL', normalRange: '4.5-12.0' },
  ],
  'default': [
    { name: 'result_value', unit: '', normalRange: '' },
  ]
}

interface ResultField {
  name: string
  value: string
  unit: string
  normalRange: string
  status: 'normal' | 'abnormal' | ''
}

interface LabResultEntryFormProps {
  test: LabTest | null
  userName: string
  onSubmit: (resultData: any, generatePdf: boolean) => void
  onCancel: () => void
}

const LabResultEntryForm: React.FC<LabResultEntryFormProps> = ({ test, userName, onSubmit, onCancel }) => {
  const [fields, setFields] = useState<ResultField[]>([])
  const [technicianNotes, setTechnicianNotes] = useState('')
  const [generatePdf, setGeneratePdf] = useState(true)
  const [resultStatus, setResultStatus] = useState<'Normal' | 'Abnormal' | 'Critical'>('Normal')

  useEffect(() => {
    if (test) {
      const template = TEST_FIELD_TEMPLATES[test.test_name] || TEST_FIELD_TEMPLATES['default']
      setFields(template.map(t => ({ ...t, value: '', status: '' })))
    }
  }, [test])

  const handleFieldChange = (index: number, value: string) => {
    const updated = [...fields]
    updated[index].value = value
    setFields(updated)
  }

  const handleAddField = () => {
    setFields([...fields, { name: '', value: '', unit: '', normalRange: '', status: '' }])
  }

  const handleRemoveField = (index: number) => {
    setFields(fields.filter((_, i) => i !== index))
  }

  const handleFieldNameChange = (index: number, name: string) => {
    const updated = [...fields]
    updated[index].name = name
    setFields(updated)
  }

  const handleSubmit = () => {
    const resultData: any = {}
    fields.forEach(f => {
      if (f.name && f.value) {
        resultData[f.name] = f.value + (f.unit ? ` ${f.unit}` : '')
      }
    })
    resultData.result_status = resultStatus
    resultData.technician_notes = technicianNotes
    resultData.entered_by = userName
    resultData.entered_at = new Date().toISOString()
    onSubmit(resultData, generatePdf)
  }

  if (!test) return null

  return (
    <div className="space-y-4">
      {/* Patient Info Header */}
      <div className="bg-gradient-to-r from-blue-500/10 to-purple-500/10 border border-blue-500/30 rounded-lg p-4">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-full bg-blue-500/20 flex items-center justify-center">
            <User size={24} className="text-blue-400" />
          </div>
          <div>
            <h3 className="font-semibold text-white">{test.first_name} {test.last_name}</h3>
            <p className="text-sm text-gray-400">{test.test_name}</p>
            <p className="text-xs text-gray-500">Ordered: {new Date(test.created_at).toLocaleDateString()}</p>
          </div>
        </div>
      </div>

      {/* Result Fields - Card Based */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h4 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
            <Beaker size={16} className="text-green-400" />
            Test Results
          </h4>
          <span className="text-xs text-gray-500">{fields.length} field(s)</span>
        </div>

        <div className="space-y-3 max-h-64 overflow-y-auto pr-2">
          {fields.map((field, idx) => (
            <div key={idx} className="bg-gray-700 rounded-xl p-4 border border-gray-600 relative">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 bg-green-600 rounded-full flex items-center justify-center text-xs text-white font-bold">
                    {idx + 1}
                  </div>
                  <input
                    type="text"
                    value={field.name.replace(/_/g, ' ')}
                    onChange={(e) => handleFieldNameChange(idx, e.target.value.replace(/ /g, '_'))}
                    className="bg-transparent text-green-400 font-semibold text-sm border-none focus:outline-none capitalize"
                    placeholder="Field name"
                  />
                </div>
                {fields.length > 1 && (
                  <button
                    onClick={() => handleRemoveField(idx)}
                    className="text-red-400 hover:text-red-300 p-1 rounded hover:bg-red-900/30"
                  >
                    <Trash2 size={14} />
                  </button>
                )}
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-1">
                  <label className="text-xs text-gray-400 mb-1 block">Value</label>
                  <input
                    type="text"
                    value={field.value}
                    onChange={(e) => handleFieldChange(idx, e.target.value)}
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded text-white text-sm"
                    placeholder="Enter value"
                  />
                </div>
                <div>
                  <label className="text-xs text-gray-400 mb-1 block">Unit</label>
                  <input
                    type="text"
                    value={field.unit}
                    onChange={(e) => {
                      const updated = [...fields]
                      updated[idx].unit = e.target.value
                      setFields(updated)
                    }}
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded text-white text-sm"
                    placeholder="e.g., mg/dL"
                  />
                </div>
                <div>
                  <label className="text-xs text-gray-400 mb-1 block">Normal Range</label>
                  <input
                    type="text"
                    value={field.normalRange}
                    onChange={(e) => {
                      const updated = [...fields]
                      updated[idx].normalRange = e.target.value
                      setFields(updated)
                    }}
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded text-white text-sm"
                    placeholder="e.g., 12-17"
                  />
                </div>
              </div>
            </div>
          ))}
        </div>

        <button
          onClick={handleAddField}
          className="w-full py-3 border-2 border-dashed border-green-600 rounded-xl text-green-400 hover:bg-green-900/20 flex items-center justify-center gap-2"
        >
          <Plus size={16} />
          Add Result Field
        </button>
      </div>

      {/* Result Status */}
      <div className="bg-gray-700 rounded-lg p-4 border border-gray-600">
        <label className="text-sm font-semibold text-gray-300 block mb-3">Overall Result Status</label>
        <div className="flex gap-3">
          {(['Normal', 'Abnormal', 'Critical'] as const).map((status) => (
            <button
              key={status}
              onClick={() => setResultStatus(status)}
              className={`flex-1 py-2 px-4 rounded-lg text-sm font-medium transition ${
                resultStatus === status
                  ? status === 'Normal' ? 'bg-green-600 text-white' :
                    status === 'Abnormal' ? 'bg-yellow-600 text-white' :
                    'bg-red-600 text-white'
                  : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
              }`}
            >
              {status}
            </button>
          ))}
        </div>
      </div>

      {/* Technician Notes */}
      <div>
        <label className="text-sm font-semibold text-gray-300 block mb-2">Technician Notes</label>
        <textarea
          value={technicianNotes}
          onChange={(e) => setTechnicianNotes(e.target.value)}
          className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm"
          rows={3}
          placeholder="Add any observations or notes..."
        />
      </div>

      {/* Generate PDF Option */}
      <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={generatePdf}
            onChange={(e) => setGeneratePdf(e.target.checked)}
            className="w-5 h-5 accent-blue-500"
          />
          <div>
            <span className="text-white font-medium flex items-center gap-2">
              <FileText size={16} className="text-blue-400" />
              Generate PDF Report
            </span>
            <p className="text-xs text-gray-400 mt-1">Create a downloadable PDF report for this test result</p>
          </div>
        </label>
      </div>

      {/* Actions */}
      <div className="flex gap-2 justify-end pt-4 border-t border-gray-700">
        <Button onClick={onCancel} variant="ghost">Cancel</Button>
        <Button onClick={handleSubmit} className="bg-green-600 hover:bg-green-700">
          <CheckCircle size={16} className="mr-1" />
          Submit Results
        </Button>
      </div>
    </div>
  )
}

interface LabTest {
  id: string
  patient_id: string
  first_name: string
  last_name: string
  test_name: string
  status: 'pending' | 'collected' | 'completed' | 'reviewed'
  result_data?: any
  result_file_url?: string
  result_pdf_key?: string
  notes?: string
  created_at: string
  completed_at?: string
  requested_by_name?: string
  sample_collected?: boolean
  sample_collected_at?: string
  priority?: 'normal' | 'urgent'
  lab_fees?: number
  technician_id?: string
  technician_name?: string
}

interface Patient {
  id: string
  first_name: string
  last_name: string
}

interface LabTestsProps {
  userEmail: string
  userName: string
  userRole: string
  hasViewPermission: boolean
}

const LabTests: React.FC<LabTestsProps> = ({
  userEmail,
  userName,
  userRole,
  hasViewPermission
}) => {
  const [tests, setTests] = useState<LabTest[]>([])
  const [patients, setPatients] = useState<Patient[]>([])
  const [loading, setLoading] = useState(true)
  const [showOrderModal, setShowOrderModal] = useState(false)
  const [showUploadModal, setShowUploadModal] = useState(false)
  const [showViewModal, setShowViewModal] = useState(false)
  const [showCollectModal, setShowCollectModal] = useState(false)
  const [selectedTest, setSelectedTest] = useState<LabTest | null>(null)
  const [newTestName, setNewTestName] = useState('')
  const [newTestNotes, setNewTestNotes] = useState('')
  const [patientId, setPatientId] = useState('')
  const [resultData, setResultData] = useState('')
  const [collectionNotes, setCollectionNotes] = useState('')
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('')
  const [testPriority, setTestPriority] = useState<'normal' | 'urgent'>('normal')
  const [encryptionStatus, setEncryptionStatus] = useState<{ [key: string]: string }>({})
  const [encryptingTests, setEncryptingTests] = useState<Set<string>>(new Set())

  useEffect(() => {
    loadTests()
    loadPatients()
  }, [userRole])

  const loadPatients = async () => {
    try {
      const token = localStorage.getItem('hp_access_token')
      if (!token) return

      const response = await fetch('/api/patients', {
        headers: { 'Authorization': `Bearer ${token}` }
      })
      if (response.ok) {
        const data = await response.json()
        // Backend returns { success: true, patients: [...] }
        const patientList = data.patients || data.data || data || []
        setPatients(patientList.map((p: any) => ({
          id: p.id,
          first_name: p.firstName || p.first_name || p.name?.split(' ')[0] || '',
          last_name: p.lastName || p.last_name || p.name?.split(' ')[1] || ''
        })))
      }
    } catch (error) {
      console.error('Failed to load patients:', error)
    }
  }

  const loadTests = async () => {
    try {
      setLoading(true)
      const token = localStorage.getItem('hp_access_token')
      if (!token) {
        setTests([])
        setLoading(false)
        return
      }

      const response = await fetch('/api/lab-tests', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })

      if (response.ok) {
        const data = await response.json()
        const testList = data.data || []
        setTests(testList)

        // Check encryption status for completed tests
        for (const test of testList) {
          if (test.status === 'completed') {
            checkEncryptionStatus(test.id)
          }
        }
      }
    } catch (error) {
      console.error('Failed to load lab tests:', error)
      setTests([])
    } finally {
      setLoading(false)
    }
  }

  // Filter tests based on search and status
  const filteredTests = tests.filter(test => {
    const matchesSearch = searchTerm === '' ||
      test.test_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      `${test.first_name} ${test.last_name}`.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesStatus = statusFilter === '' || test.status === statusFilter
    return matchesSearch && matchesStatus
  })

  const handleOrderTest = async () => {
    if (!newTestName || !patientId) {
      alert('Please fill in all fields')
      return
    }

    try {
      const token = localStorage.getItem('hp_access_token')
      if (!token) return

      const response = await fetch('/api/lab-tests', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          patient_id: patientId,
          test_name: newTestName,
          notes: newTestNotes,
          priority: testPriority,
          lab_fees: testPriority === 'urgent' ? 150 : 100 // Default fees based on priority
        })
      })

      if (response.ok) {
        const data = await response.json()
        await loadTests() // Reload to get full data
        setShowOrderModal(false)
        setNewTestName('')
        setNewTestNotes('')
        setPatientId('')
        setTestPriority('normal')
        alert('Lab test ordered successfully!')
      } else {
        const err = await response.json()
        alert(`Failed to order test: ${err.error || 'Unknown error'}`)
      }
    } catch (error) {
      alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  const handleUploadResult = async () => {
    if (!resultData) {
      alert('Please provide test result data')
      return
    }

    if (!selectedTest) return

    try {
      const token = localStorage.getItem('hp_access_token')
      if (!token) return

      // Update lab test with result data
      const response = await fetch(`/api/lab-tests/${selectedTest.id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          status: 'completed',
          result_data: JSON.parse(resultData),
          notes: `Result entered by ${userName}`
        })
      })

      if (response.ok) {
        await loadTests()
        setShowUploadModal(false)
        setResultData('')
        setSelectedTest(null)
        alert('Lab test result saved successfully!')
      } else {
        const err = await response.json()
        alert(`Error: ${err.error || 'Failed to save results'}`)
      }
    } catch (error) {
      alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  const handleCollectSample = async () => {
    if (!selectedTest) return

    try {
      const token = localStorage.getItem('hp_access_token')
      if (!token) return

      const response = await fetch(`/api/lab-tests/${selectedTest.id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          status: 'collected',
          sample_collected: true,
          sample_collected_at: new Date().toISOString(),
          notes: collectionNotes ? `Sample collected: ${collectionNotes}` : `Sample collected by ${userName}`
        })
      })

      if (response.ok) {
        await loadTests()
        setShowCollectModal(false)
        setCollectionNotes('')
        setSelectedTest(null)
        alert('Sample collection recorded!')
      }
    } catch (error) {
      alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  const checkEncryptionStatus = async (testId: string) => {
    try {
      const token = localStorage.getItem('hp_access_token')
      if (!token) return

      const response = await fetch(`/api/lab/results/${testId}/encryption-status`, {
        headers: { 'Authorization': `Bearer ${token}` }
      })

      if (response.ok) {
        const data = await response.json()
        setEncryptionStatus(prev => ({
          ...prev,
          [testId]: data.encryptionStatus
        }))
      }
    } catch (error) {
      console.error('Failed to check encryption status:', error)
    }
  }

  const handleEncryptReport = async (test: LabTest) => {
    try {
      const token = localStorage.getItem('hp_access_token')
      if (!token) {
        alert('Please login first')
        return
      }

      setEncryptingTests(prev => new Set(prev).add(test.id))

      const response = await fetch(`/api/lab/results/${test.id}/encrypt`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      })

      if (response.ok) {
        await checkEncryptionStatus(test.id)
        alert('✓ Lab report encrypted successfully!')
      } else {
        const err = await response.json()
        alert(`Error: ${err.error || 'Failed to encrypt report'}`)
      }
    } catch (error) {
      alert(`Error encrypting report: ${error instanceof Error ? error.message : 'Unknown error'}`)
    } finally {
      setEncryptingTests(prev => {
        const newSet = new Set(prev)
        newSet.delete(test.id)
        return newSet
      })
    }
  }

  const handleDecryptReport = async (test: LabTest) => {
    try {
      const token = localStorage.getItem('hp_access_token')
      if (!token) {
        alert('Please login first')
        return
      }

      setEncryptingTests(prev => new Set(prev).add(test.id))

      const response = await fetch(`/api/lab/results/${test.id}/decrypt`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      })

      if (response.ok && response.headers.get('content-type') && response.headers.get('content-type')!.includes('application/pdf')) {
        const blob = await response.blob()
        const url = window.URL.createObjectURL(blob)
        const link = document.createElement('a')
        link.href = url
        link.download = `lab-report-${test.test_name}-${test.id.substring(0, 8)}-decrypted.pdf`
        document.body.appendChild(link)
        link.click()
        document.body.removeChild(link)
        window.URL.revokeObjectURL(url)

        await checkEncryptionStatus(test.id)
        alert('✓ Lab report decrypted and downloaded successfully!')
      } else {
        const err = await response.json()
        alert(`Error: ${err.error || 'Failed to decrypt report'}`)
      }
    } catch (error) {
      alert(`Error decrypting report: ${error instanceof Error ? error.message : 'Unknown error'}`)
    } finally {
      setEncryptingTests(prev => {
        const newSet = new Set(prev)
        newSet.delete(test.id)
        return newSet
      })
    }
  }

  const canOrderTests = ['doctor', 'nurse', 'admin'].includes(userRole)
  const canUploadResults = ['lab_technician', 'admin'].includes(userRole)
  const canDownloadEncrypted = ['doctor', 'lab_technician'].includes(userRole)

  const downloadPDF = async (testToDownload?: LabTest) => {
    const test = testToDownload || selectedTest
    if (!test) {
      alert('No test selected')
      return
    }

    // Check if test has results
    if (test.status !== 'completed' && !test.result_data) {
      alert('No results available for this test yet')
      return
    }

    try {
      const token = localStorage.getItem('hp_access_token')
      if (!token) {
        alert('Please login first')
        return
      }

      // Try encrypted stored report download first (if present on server)
      const downloadResp = await fetch(`/api/lab/results/${test.id}/download`, {
        headers: { 'Authorization': `Bearer ${token}` }
      })

      if (downloadResp.ok && downloadResp.headers.get('content-type') && !downloadResp.headers.get('content-type')!.includes('application/json')) {
        const blob = await downloadResp.blob()
        const url = window.URL.createObjectURL(blob)
        const link = document.createElement('a')
        link.href = url
        link.download = `lab-report-${test.test_name}-${test.id.substring(0, 8)}.pdf`
        document.body.appendChild(link)
        link.click()
        document.body.removeChild(link)
        window.URL.revokeObjectURL(url)
        return
      }

      // If encrypted download not available, fall back to PDF generation endpoint
      const response = await fetch(`/api/lab-tests/${test.id}/pdf`, {
        headers: { 'Authorization': `Bearer ${token}` }
      })

      if (!response.ok) {
        const error = await response.json().catch(() => ({ error: 'Failed to download PDF' }))
        alert(`Error: ${error.error || 'Failed to download PDF'}`)
        return
      }

      // Get the PDF blob
      const blob = await response.blob()

      // Create a download link
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `lab-report-${test.test_name}-${test.id.substring(0, 8)}.pdf`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      window.URL.revokeObjectURL(url)
    } catch (error) {
      alert(`Error downloading PDF: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  const viewPDF = async (testToView?: LabTest) => {
    const test = testToView || selectedTest
    if (!test) {
      alert('No test selected')
      return
    }

    if (test.status !== 'completed' && !test.result_data) {
      alert('No results available for this test yet')
      return
    }

    try {
      const token = localStorage.getItem('hp_access_token')
      if (!token) {
        alert('Please login first')
        return
      }

      // Try encrypted stored file viewer first
      const downloadResp = await fetch(`/api/lab/results/${test.id}/download`, {
        headers: { 'Authorization': `Bearer ${token}` }
      })

      if (downloadResp.ok && downloadResp.headers.get('content-type') && !downloadResp.headers.get('content-type')!.includes('application/json')) {
        const blob = await downloadResp.blob()
        const url = window.URL.createObjectURL(blob)
        window.open(url, '_blank')
        return
      }

      const response = await fetch(`/api/lab-tests/${test.id}/pdf`, {
        headers: { 'Authorization': `Bearer ${token}` }
      })

      if (response.ok) {
        const blob = await response.blob()
        const url = window.URL.createObjectURL(blob)
        window.open(url, '_blank')
      } else {
        const error = await response.json().catch(() => ({ error: 'Failed to view PDF' }))
        alert(`Error: ${error.error || 'Failed to view PDF'}`)
      }
    } catch (error) {
      alert(`Error viewing PDF: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <Microscope size={28} className="text-blue-400" />
            Laboratory Tests
          </h2>
          {userRole === 'lab_technician' && (
            <p className="text-sm text-gray-400 mt-1">Lab Technician Dashboard • Manage sample collection & test results</p>
          )}
        </div>
        {canOrderTests && (
          <Button
            onClick={() => setShowOrderModal(true)}
            className="bg-blue-600 hover:bg-blue-700 text-white gap-2"
          >
            <Plus size={18} />
            Order Test
          </Button>
        )}
      </div>

      {/* Role-specific welcome banner */}
      {userRole === 'lab_technician' && (
        <Card className="bg-gradient-to-r from-purple-500/10 to-blue-500/10 border border-purple-500/30">
          <div className="flex items-start gap-3">
            <Beaker size={24} className="text-purple-400 mt-1 flex-shrink-0" />
            <div>
              <h3 className="font-semibold text-white mb-1">Lab Technician Workflow</h3>
              <p className="text-sm text-gray-300">1. <strong>Receive</strong> test orders • 2. <strong>Collect</strong> samples • 3. <strong>Run</strong> tests • 4. <strong>Upload</strong> results</p>
            </div>
          </div>
        </Card>
      )}

      {/* Stats Cards - Role-aware */}
      <div className={`grid gap-4 ${userRole === 'lab_technician' ? 'grid-cols-1 md:grid-cols-4' : 'grid-cols-1 md:grid-cols-3'}`}>
        <Card className="border-l-4 border-yellow-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Pending</p>
              <p className="text-3xl font-bold text-yellow-400">{tests.filter(t => t.status === 'pending').length}</p>
            </div>
            <Clock size={28} className="text-yellow-500/40" />
          </div>
        </Card>

        {userRole === 'lab_technician' && (
          <Card className="border-l-4 border-orange-500">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Collected</p>
                <p className="text-3xl font-bold text-orange-400">{tests.filter(t => t.status === 'collected').length}</p>
              </div>
              <Badge size={28} className="text-orange-500/40" />
            </div>
          </Card>
        )}

        <Card className="border-l-4 border-green-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Completed</p>
              <p className="text-3xl font-bold text-green-400">{tests.filter(t => t.status === 'completed').length}</p>
            </div>
            <CheckCircle size={28} className="text-green-500/40" />
          </div>
        </Card>

        <Card className="border-l-4 border-blue-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Total Tests</p>
              <p className="text-3xl font-bold text-blue-400">{tests.length}</p>
            </div>
            <Microscope size={28} className="text-blue-500/40" />
          </div>
        </Card>
      </div>

      {/* Search and Filters */}
      <div className="flex flex-wrap gap-4 items-center">
        <div className="flex-1 relative min-w-64">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
          <input
            type="text"
            placeholder="Search tests or patients..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-white/5 border border-white/10 rounded text-white text-sm placeholder-gray-500"
          />
        </div>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-3 py-2 bg-white/5 border border-white/10 rounded text-white text-sm"
        >
          <option value="">All Status</option>
          <option value="pending">Pending</option>
          <option value="collected">Collected</option>
          <option value="completed">Completed</option>
          <option value="reviewed">Reviewed</option>
        </select>
        <Button variant="ghost" onClick={loadTests} className="gap-1">
          <RefreshCw size={14} /> Refresh
        </Button>
      </div>

      {/* Tests List */}
      <Card>
        {loading ? (
          <p className="text-gray-400">Loading tests...</p>
        ) : filteredTests.length === 0 ? (
          <div className="text-center py-8">
            <Beaker size={32} className="text-gray-600 mx-auto mb-3" />
            <p className="text-gray-400">{tests.length === 0 ? 'No lab tests found' : 'No tests match your filters'}</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/6 text-gray-400">
                  <th className="px-6 py-3 text-left font-semibold">Patient</th>
                  <th className="px-6 py-3 text-left font-semibold">Test</th>
                  <th className="px-6 py-3 text-left font-semibold">Status</th>
                  {userRole === 'lab_technician' && <th className="px-6 py-3 text-left font-semibold">Sample</th>}
                  <th className="px-6 py-3 text-left font-semibold">Ordered By</th>
                  <th className="px-6 py-3 text-left font-semibold">Date</th>
                  <th className="px-6 py-3 text-left font-semibold">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/6">
                {filteredTests.map(test => (
                  <tr key={test.id} className="hover:bg-white/2">
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <div className="w-8 h-8 rounded-full bg-blue-500/20 flex items-center justify-center">
                          <User size={14} className="text-blue-400" />
                        </div>
                        <span className="font-medium text-white">{test.first_name} {test.last_name}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-gray-300">{test.test_name}</td>
                    <td className="px-6 py-4">
                      <span className={`px-3 py-1 rounded-full text-xs font-semibold inline-flex items-center gap-1 ${
                        test.status === 'pending' ? 'bg-yellow-500/20 text-yellow-400' :
                        test.status === 'collected' ? 'bg-orange-500/20 text-orange-400' :
                        test.status === 'completed' ? 'bg-green-500/20 text-green-400' :
                        'bg-blue-500/20 text-blue-400'
                      }`}>
                        {test.status === 'pending' && <Clock size={12} />}
                        {test.status === 'collected' && <Badge size={12} />}
                        {test.status === 'completed' && <CheckCircle size={12} />}
                        {test.status.charAt(0).toUpperCase() + test.status.slice(1)}
                      </span>
                    </td>
                    {userRole === 'lab_technician' && (
                      <td className="px-6 py-4">
                        <span className={`text-xs px-2 py-1 rounded ${
                          test.sample_collected ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'
                        }`}>
                          {test.sample_collected ? '✓ Collected' : '○ Pending'}
                        </span>
                      </td>
                    )}
                    <td className="px-6 py-4 text-gray-400 text-xs">{test.requested_by_name || 'N/A'}</td>
                    <td className="px-6 py-4 text-gray-400 text-xs">{new Date(test.created_at).toLocaleDateString()}</td>
                    <td className="px-6 py-4">
                      <div className="flex gap-2 flex-wrap">
                        {userRole === 'lab_technician' && test.status === 'pending' && !test.sample_collected && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setSelectedTest(test)
                              setShowCollectModal(true)
                            }}
                            className="gap-1"
                          >
                            <Badge size={14} />
                            Collect
                          </Button>
                        )}
                        {canUploadResults && test.status !== 'reviewed' && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setSelectedTest(test)
                              setShowUploadModal(true)
                            }}
                            className="gap-1"
                          >
                            <FileUp size={14} />
                            Upload
                          </Button>
                        )}
                        {test.status === 'completed' && (
                          <>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                setSelectedTest(test)
                                setShowViewModal(true)
                              }}
                              className="gap-1"
                            >
                              <Eye size={14} />
                              View
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => downloadPDF(test)}
                              className="gap-1 text-blue-400 hover:text-blue-300"
                            >
                              <Download size={14} />
                              PDF
                            </Button>
                            {canDownloadEncrypted && (
                              <>
                                {encryptionStatus[test.id] === 'encrypted' ? (
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => handleDecryptReport(test)}
                                    disabled={encryptingTests.has(test.id)}
                                    className="gap-1 text-yellow-400 hover:text-yellow-300 disabled:opacity-50"
                                    title="Decrypt encrypted report"
                                  >
                                    <Unlock size={14} />
                                    {encryptingTests.has(test.id) ? 'Decrypting...' : 'Decrypt'}
                                  </Button>
                                ) : (
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => handleEncryptReport(test)}
                                    disabled={encryptingTests.has(test.id)}
                                    className="gap-1 text-green-400 hover:text-green-300 disabled:opacity-50"
                                    title="Encrypt report with AES-256-GCM"
                                  >
                                    <Lock size={14} />
                                    {encryptingTests.has(test.id) ? 'Encrypting...' : 'Encrypt'}
                                  </Button>
                                )}
                              </>
                            )}
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Order Test Modal */}
      <Modal
        isOpen={showOrderModal}
        onClose={() => setShowOrderModal(false)}
        title="Order Lab Test"
        size="md"
      >
        <div className="space-y-4">
          <div>
            <label className="text-sm font-semibold text-gray-300">Select Patient</label>
            <select
              value={patientId}
              onChange={(e) => setPatientId(e.target.value)}
              className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white"
            >
              <option value="">-- Select a patient --</option>
              {patients.map(p => (
                <option key={p.id} value={p.id}>{p.first_name} {p.last_name}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-sm font-semibold text-gray-300">Test Type</label>
            <select
              value={newTestName}
              onChange={(e) => setNewTestName(e.target.value)}
              className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white"
            >
              <option value="">-- Select test type --</option>
              <option value="Complete Blood Count (CBC)">Complete Blood Count (CBC)</option>
              <option value="Blood Glucose Test">Blood Glucose Test</option>
              <option value="Lipid Panel">Lipid Panel</option>
              <option value="Liver Function Test (LFT)">Liver Function Test (LFT)</option>
              <option value="Kidney Function Test">Kidney Function Test</option>
              <option value="Thyroid Panel">Thyroid Panel</option>
              <option value="Urinalysis">Urinalysis</option>
              <option value="COVID-19 Test">COVID-19 Test</option>
              <option value="HIV Test">HIV Test</option>
              <option value="Hemoglobin A1C">Hemoglobin A1C</option>
              <option value="Vitamin D Test">Vitamin D Test</option>
              <option value="Chest X-Ray">Chest X-Ray</option>
              <option value="MRI Scan">MRI Scan</option>
              <option value="CT Scan">CT Scan</option>
              <option value="Ultrasound">Ultrasound</option>
              <option value="ECG/EKG">ECG/EKG</option>
            </select>
          </div>
          <div>
            <label className="text-sm font-semibold text-gray-300">Priority</label>
            <div className="flex gap-4 mt-2">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  name="priority"
                  checked={testPriority === 'normal'}
                  onChange={() => setTestPriority('normal')}
                  className="accent-blue-500"
                />
                <span className="text-gray-300">Normal</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  name="priority"
                  checked={testPriority === 'urgent'}
                  onChange={() => setTestPriority('urgent')}
                  className="accent-red-500"
                />
                <span className="text-red-400">Urgent</span>
              </label>
            </div>
          </div>
          <div>
            <label className="text-sm font-semibold text-gray-300">Notes (Optional)</label>
            <textarea
              value={newTestNotes}
              onChange={(e) => setNewTestNotes(e.target.value)}
              placeholder="Any special instructions for lab tech"
              className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white placeholder-gray-500"
              rows={3}
            />
          </div>
          {/* Lab Fees Display */}
          <div className="bg-green-500/10 border border-green-500/20 rounded p-3">
            <div className="flex justify-between items-center">
              <span className="text-sm text-gray-300">Estimated Lab Fees:</span>
              <span className="text-xl font-bold text-green-400">
                ${testPriority === 'urgent' ? '150.00' : '100.00'}
              </span>
            </div>
            <p className="text-xs text-gray-500 mt-1">
              {testPriority === 'urgent' ? 'Urgent tests include priority processing fee' : 'Standard processing fee'}
            </p>
          </div>
          <div className="flex gap-2 justify-end mt-6">
            <Button onClick={() => setShowOrderModal(false)} variant="ghost">Cancel</Button>
            <Button onClick={handleOrderTest} className="bg-blue-600 hover:bg-blue-700">Order Test</Button>
          </div>
        </div>
      </Modal>

      {/* Collect Sample Modal - Lab Technician only */}
      {userRole === 'lab_technician' && (
        <Modal
          isOpen={showCollectModal}
          onClose={() => setShowCollectModal(false)}
          title={`Collect Sample: ${selectedTest?.test_name}`}
          size="md"
        >
          <div className="space-y-4">
            <div className="bg-blue-500/10 border border-blue-500/30 rounded p-4">
              <div className="flex gap-2">
                <Badge size={20} className="text-blue-400 flex-shrink-0" />
                <div>
                  <h4 className="font-semibold text-white text-sm">Patient: {selectedTest?.first_name} {selectedTest?.last_name}</h4>
                  <p className="text-xs text-gray-400 mt-1">Test: {selectedTest?.test_name}</p>
                </div>
              </div>
            </div>

            <div className="bg-white/5 border border-white/10 rounded p-4 text-sm text-gray-300">
              <p className="font-semibold text-white mb-2">Sample Collection Checklist:</p>
              <ul className="space-y-1 text-xs">
                <li>✓ Verify patient identity</li>
                <li>✓ Check for sample type requirements</li>
                <li>✓ Use appropriate collection containers</li>
                <li>✓ Label sample with patient ID and date/time</li>
                <li>✓ Follow safety protocols</li>
              </ul>
            </div>

            <div>
              <label className="text-sm font-semibold text-gray-300">Collection Notes (Optional)</label>
              <textarea
                value={collectionNotes}
                onChange={(e) => setCollectionNotes(e.target.value)}
                placeholder="e.g., Blood sample collected via venipuncture, fasting state confirmed"
                className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white placeholder-gray-500 text-sm"
                rows={3}
              />
            </div>

            <div className="flex gap-2 justify-end mt-6">
              <Button onClick={() => setShowCollectModal(false)} variant="ghost">Cancel</Button>
              <Button onClick={handleCollectSample} className="bg-green-600 hover:bg-green-700">Confirm Collection</Button>
            </div>
          </div>
        </Modal>
      )}

      {/* Upload Result Modal - Card Based Entry */}
      <Modal
        isOpen={showUploadModal}
        onClose={() => setShowUploadModal(false)}
        title={`Enter Lab Results: ${selectedTest?.test_name}`}
        size="xl"
      >
        <LabResultEntryForm
          test={selectedTest}
          userName={userName}
          onSubmit={async (resultData, generatePdf) => {
            if (!selectedTest) return
            try {
              const token = localStorage.getItem('hp_access_token')
              if (!token) return

              const response = await fetch(`/api/lab-tests/${selectedTest.id}`, {
                method: 'PUT',
                headers: {
                  'Content-Type': 'application/json',
                  'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                  status: 'completed',
                  result_data: resultData,
                  notes: `Result entered by ${userName}`,
                  generate_pdf: generatePdf
                })
              })

              if (response.ok) {
                await loadTests()
                setShowUploadModal(false)
                setResultData('')
                setSelectedTest(null)
                alert('Lab test result saved successfully!')
              } else {
                const err = await response.json()
                alert(`Error: ${err.error || 'Failed to save results'}`)
              }
            } catch (error) {
              alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`)
            }
          }}
          onCancel={() => setShowUploadModal(false)}
        />
      </Modal>

      {/* View Report Modal */}
      <Modal
        isOpen={showViewModal}
        onClose={() => setShowViewModal(false)}
        title={`Lab Report: ${selectedTest?.test_name}`}
        size="lg"
      >
        <div className="space-y-4">
          {/* Patient Info Header */}
          <div className="bg-gradient-to-r from-blue-500/10 to-purple-500/10 border border-blue-500/30 rounded-lg p-4">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-full bg-blue-500/20 flex items-center justify-center">
                <User size={24} className="text-blue-400" />
              </div>
              <div>
                <h3 className="font-semibold text-white">{selectedTest?.first_name} {selectedTest?.last_name}</h3>
                <p className="text-sm text-gray-400">Test: {selectedTest?.test_name}</p>
                <p className="text-xs text-gray-500">Completed: {selectedTest?.completed_at ? new Date(selectedTest.completed_at).toLocaleString() : 'N/A'}</p>
              </div>
            </div>
          </div>

          {/* Test Results Data */}
          {selectedTest?.result_data ? (
            <div className="bg-white/5 border border-white/10 rounded-lg p-4">
              <h4 className="font-semibold text-white mb-3 flex items-center gap-2">
                <Beaker size={18} className="text-green-400" />
                Test Results
              </h4>
              <div className="grid grid-cols-2 gap-3">
                {typeof selectedTest.result_data === 'string' ? (
                  <pre className="col-span-2 text-xs bg-black/20 p-3 rounded overflow-auto max-h-48 text-gray-300 font-mono">
                    {JSON.stringify(JSON.parse(selectedTest.result_data), null, 2)}
                  </pre>
                ) : (
                  Object.entries(selectedTest.result_data).map(([key, value]) => (
                    <div key={key} className="bg-black/20 rounded p-3">
                      <span className="text-gray-400 text-xs uppercase">{key.replace(/_/g, ' ')}</span>
                      <p className="text-white font-semibold mt-1">{String(value)}</p>
                    </div>
                  ))
                )}
              </div>
            </div>
          ) : (
            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4 text-center">
              <AlertCircle size={24} className="text-yellow-400 mx-auto mb-2" />
              <p className="text-yellow-300 text-sm">No result data available yet</p>
              <p className="text-gray-500 text-xs mt-1">Results will appear here once uploaded by lab technician</p>
            </div>
          )}

          {/* PDF Download/View - Always show for completed tests */}
          {selectedTest?.status === 'completed' && (
            <div className="space-y-3">
              {/* Encryption Status Badge */}
              <div className={`rounded-lg p-4 ${encryptionStatus[selectedTest.id] === 'encrypted' ? 'bg-yellow-500/10 border border-yellow-500/30' : 'bg-green-500/10 border border-green-500/30'}`}>
                <div className="flex items-center gap-2 mb-2">
                  <Shield size={18} className={encryptionStatus[selectedTest.id] === 'encrypted' ? 'text-yellow-400' : 'text-green-400'} />
                  <span className={`font-semibold ${encryptionStatus[selectedTest.id] === 'encrypted' ? 'text-yellow-300' : 'text-green-300'}`}>
                    {encryptionStatus[selectedTest.id] === 'encrypted' ? '🔒 Encrypted' : '🔓 Not Encrypted'}
                  </span>
                </div>
                <p className={`text-sm ${encryptionStatus[selectedTest.id] === 'encrypted' ? 'text-yellow-400/70' : 'text-green-400/70'}`}>
                  {encryptionStatus[selectedTest.id] === 'encrypted' 
                    ? 'Report is encrypted with AES-256-GCM. Click decrypt to access.' 
                    : 'Report is unencrypted. Click encrypt to secure it.'}
                </p>
              </div>

              <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
                <p className="text-sm text-blue-300 mb-3 flex items-center gap-2">
                  <FileText size={16} />
                  Lab Report PDF
                </p>
                <div className="flex gap-3 flex-wrap">
                  <button
                    onClick={() => viewPDF()}
                    className="inline-flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded font-medium transition"
                  >
                    <Eye size={16} />
                    View PDF
                  </button>
                  <button
                    onClick={() => downloadPDF()}
                    className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded font-medium transition"
                  >
                    <Download size={16} />
                    Download PDF
                  </button>
                  {canDownloadEncrypted && (
                    <>
                      {encryptionStatus[selectedTest.id] === 'encrypted' ? (
                        <button
                          onClick={() => handleDecryptReport(selectedTest)}
                          disabled={encryptingTests.has(selectedTest.id)}
                          className="inline-flex items-center gap-2 px-4 py-2 bg-yellow-600 hover:bg-yellow-700 text-white rounded font-medium transition disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          <Unlock size={16} />
                          {encryptingTests.has(selectedTest.id) ? 'Decrypting...' : 'Decrypt Report'}
                        </button>
                      ) : (
                        <button
                          onClick={() => handleEncryptReport(selectedTest)}
                          disabled={encryptingTests.has(selectedTest.id)}
                          className="inline-flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded font-medium transition disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          <Lock size={16} />
                          {encryptingTests.has(selectedTest.id) ? 'Encrypting...' : 'Encrypt Report'}
                        </button>
                      )}
                    </>
                  )}
                </div>
                <p className="text-xs text-gray-400 mt-2">PDF will be generated from the lab results data</p>
              </div>
            </div>
          )}

          {/* Notes */}
          {selectedTest?.notes && (
            <div className="bg-white/5 border border-white/10 rounded-lg p-4">
              <h4 className="font-semibold text-white mb-2">Lab Notes:</h4>
              <p className="text-gray-300 text-sm">{selectedTest.notes}</p>
            </div>
          )}

          <div className="flex justify-end gap-2 mt-6">
            <Button onClick={() => setShowViewModal(false)} className="bg-blue-600 hover:bg-blue-700">Close</Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}

export default LabTests

import React, { useState, useEffect } from 'react'
import {
  BarChart3,
  TestTube,
  Droplet,
  CheckCircle,
  Plus,
  Upload,
  Eye,
  Download,
  AlertCircle,
  Search,
  Filter,
  User,
  FileText,
  Loader,
  LogOut,
  UserCircle
} from 'lucide-react'
import Card from './Card'
import Table from './Table'
import Button from './Button'
import Modal from './Modal'

interface LabTest {
  id: string
  test_id_masked: string
  patient_name: string
  test_type: string
  doctor_name: string
  status: 'pending' | 'collected' | 'completed'
  ordered_at: string
}

const LabTechnician: React.FC<{ user?: any }> = ({ user }) => {
  const [activeTab, setActiveTab] = useState('dashboard')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  // Dashboard data
  const [dashboardStats, setDashboardStats] = useState({
    pendingTests: 0,
    collectedSamples: 0,
    completedTests: 0,
    totalTests: 0
  })

  // Test Orders data
  const [testOrders, setTestOrders] = useState([])
  const [filteredTests, setFilteredTests] = useState([])
  const [testSearch, setTestSearch] = useState('')
  const [testFilter, setTestFilter] = useState('all')

  // Sample Collection
  const [showCollectSample, setShowCollectSample] = useState(false)
  const [selectedTestForSample, setSelectedTestForSample] = useState<any>(null)
  const [sampleForm, setSampleForm] = useState({
    collectionNotes: '',
    sampleBarcode: '',
    sampleType: 'Blood'
  })

  // Upload Results
  const [showUploadResults, setShowUploadResults] = useState(false)
  const [selectedTestForUpload, setSelectedTestForUpload] = useState<any>(null)
  const [uploadForm, setUploadForm] = useState({
    testParameters: '',
    observations: '',
    pdfFile: null as File | null
  })
  const [uploadProgress, setUploadProgress] = useState(0)

  // Completed tests
  const [completedTests, setCompletedTests] = useState([])
  const [showViewResult, setShowViewResult] = useState(false)
  const [selectedResult, setSelectedResult] = useState<any>(null)

  const API_URL = 'http://localhost:3000'
  const token = localStorage.getItem('token')

  // Fetch dashboard stats
  useEffect(() => {
    if (activeTab === 'dashboard') {
      fetchDashboardStats()
    }
  }, [activeTab])

  const fetchDashboardStats = async () => {
    try {
      setLoading(true)
      const response = await fetch(`${API_URL}/api/lab/dashboard`, {
        headers: { Authorization: `Bearer ${token}` }
      })
      const data = await response.json()
      if (data.success) {
        setDashboardStats(data.dashboard)
      }
    } catch (err: any) {
      setError('Failed to load dashboard stats')
    } finally {
      setLoading(false)
    }
  }

  // Fetch test orders
  useEffect(() => {
    if (activeTab === 'orders') {
      fetchTestOrders()
    }
  }, [activeTab, testFilter])

  const fetchTestOrders = async () => {
    try {
      setLoading(true)
      const status = testFilter === 'all' ? '' : `&status=${testFilter}`
      const response = await fetch(
        `${API_URL}/api/lab/tests?${status}`,
        { headers: { Authorization: `Bearer ${token}` } }
      )
      const data = await response.json()
      if (data.success) {
        setTestOrders(data.tests)
        setFilteredTests(data.tests)
      }
    } catch (err: any) {
      setError('Failed to load test orders')
    } finally {
      setLoading(false)
    }
  }

  // Search test orders
  useEffect(() => {
    if (testSearch.trim() === '') {
      setFilteredTests(testOrders)
    } else {
      const search = testSearch.toLowerCase()
      setFilteredTests(
        testOrders.filter(
          (t: any) =>
            t.test_id_masked?.toLowerCase().includes(search) ||
            t.patient_name?.toLowerCase().includes(search) ||
            t.test_type?.toLowerCase().includes(search) ||
            t.doctor_name?.toLowerCase().includes(search)
        )
      )
    }
  }, [testSearch, testOrders])

  // Collect Sample
  const handleCollectSample = async () => {
    if (!selectedTestForSample || !sampleForm.sampleType) {
      setError('Please fill all required fields')
      return
    }

    try {
      setLoading(true)
      const response = await fetch(
        `${API_URL}/api/lab/samples`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            testId: selectedTestForSample.id,
            sampleType: sampleForm.sampleType,
            barcode: sampleForm.sampleBarcode,
            notes: sampleForm.collectionNotes
          })
        }
      )
      const data = await response.json()

      if (data.success) {
        setSuccess('Sample collected successfully!')
        setShowCollectSample(false)
        setSampleForm({ collectionNotes: '', sampleBarcode: '', sampleType: 'Blood' })
        fetchTestOrders()
        setTimeout(() => setSuccess(''), 3000)
      }
    } catch (err: any) {
      setError(err.message || 'Failed to collect sample')
    } finally {
      setLoading(false)
    }
  }

  // Upload Results
  const handleUploadResults = async () => {
    if (!selectedTestForUpload || !uploadForm.pdfFile || !uploadForm.testParameters) {
      setError('Please fill all required fields')
      return
    }

    try {
      setLoading(true)
      const formData = new FormData()
      formData.append('testId', selectedTestForUpload.id)
      formData.append('testParameters', uploadForm.testParameters)
      formData.append('observations', uploadForm.observations)
      formData.append('reportFile', uploadForm.pdfFile)

      const xhr = new XMLHttpRequest()

      xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) {
          const percentCompleted = Math.round((e.loaded * 100) / e.total)
          setUploadProgress(percentCompleted)
        }
      })

      xhr.addEventListener('load', async () => {
        if (xhr.status === 200) {
          const response = JSON.parse(xhr.responseText)
          if (response.success) {
            setSuccess('Results uploaded and encrypted successfully!')
            setShowUploadResults(false)
            setUploadForm({ testParameters: '', observations: '', pdfFile: null })
            setUploadProgress(0)
            fetchTestOrders()
            setTimeout(() => setSuccess(''), 3000)
          }
        } else {
          const response = JSON.parse(xhr.responseText)
          setError(response.error || 'Failed to upload results')
        }
        setLoading(false)
        setUploadProgress(0)
      })

      xhr.addEventListener('error', () => {
        setError('Failed to upload results')
        setLoading(false)
        setUploadProgress(0)
      })

      xhr.open('POST', `${API_URL}/api/lab/results`)
      xhr.setRequestHeader('Authorization', `Bearer ${token}`)
      xhr.send(formData)
    } catch (err: any) {
      setError('Failed to upload results')
      setLoading(false)
      setUploadProgress(0)
    }
  }

  // Fetch completed tests
  useEffect(() => {
    if (activeTab === 'completed') {
      fetchCompletedTests()
    }
  }, [activeTab])

  const fetchCompletedTests = async () => {
    try {
      setLoading(true)
      const response = await fetch(
        `${API_URL}/api/lab/tests?status=completed`,
        { headers: { Authorization: `Bearer ${token}` } }
      )
      const data = await response.json()
      if (data.success) {
        setCompletedTests(data.tests)
      }
    } catch (err: any) {
      setError('Failed to load completed tests')
    } finally {
      setLoading(false)
    }
  }

  // View Result Details
  const handleViewResult = async (test: any) => {
    try {
      setLoading(true)
      const response = await fetch(
        `${API_URL}/api/lab/results/${test.id}`,
        { headers: { Authorization: `Bearer ${token}` } }
      )
      const data = await response.json()
      if (data.success) {
        setSelectedResult(data.result)
        setShowViewResult(true)
      }
    } catch (err: any) {
      setError('Failed to load result details')
    } finally {
      setLoading(false)
    }
  }

  // Dashboard Tab
  const renderDashboard = () => (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-gray-800">Lab Dashboard</h2>
        <button
          onClick={fetchDashboardStats}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 flex items-center gap-2"
        >
          <BarChart3 size={18} />
          Refresh
        </button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-gradient-to-br from-yellow-50 to-yellow-100">
          <div className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-yellow-700 text-sm font-semibold">Pending Tests</p>
                <p className="text-3xl font-bold text-yellow-900 mt-2">
                  {dashboardStats.pendingTests}
                </p>
              </div>
              <TestTube className="text-yellow-600" size={40} />
            </div>
          </div>
        </Card>

        <Card className="bg-gradient-to-br from-blue-50 to-blue-100">
          <div className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-blue-700 text-sm font-semibold">Samples Collected</p>
                <p className="text-3xl font-bold text-blue-900 mt-2">
                  {dashboardStats.collectedSamples}
                </p>
              </div>
              <Droplet className="text-blue-600" size={40} />
            </div>
          </div>
        </Card>

        <Card className="bg-gradient-to-br from-green-50 to-green-100">
          <div className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-green-700 text-sm font-semibold">Completed Tests</p>
                <p className="text-3xl font-bold text-green-900 mt-2">
                  {dashboardStats.completedTests}
                </p>
              </div>
              <CheckCircle className="text-green-600" size={40} />
            </div>
          </div>
        </Card>

        <Card className="bg-gradient-to-br from-purple-50 to-purple-100">
          <div className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-purple-700 text-sm font-semibold">Total Tests</p>
                <p className="text-3xl font-bold text-purple-900 mt-2">
                  {dashboardStats.totalTests}
                </p>
              </div>
              <BarChart3 className="text-purple-600" size={40} />
            </div>
          </div>
        </Card>
      </div>

      {/* Quick Actions */}
      <Card>
        <div className="p-6">
          <h3 className="text-lg font-semibold text-gray-800 mb-4">Quick Actions</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <button
              onClick={() => {
                setActiveTab('orders')
                setTestFilter('pending')
              }}
              className="p-4 border-2 border-yellow-300 rounded-lg hover:bg-yellow-50 transition text-left"
            >
              <TestTube className="text-yellow-600 mb-2" size={24} />
              <p className="font-semibold text-gray-800">View Pending Orders</p>
              <p className="text-sm text-gray-600">Manage pending test orders</p>
            </button>

            <button
              onClick={() => setActiveTab('samples')}
              className="p-4 border-2 border-blue-300 rounded-lg hover:bg-blue-50 transition text-left"
            >
              <Droplet className="text-blue-600 mb-2" size={24} />
              <p className="font-semibold text-gray-800">Start Sample Collection</p>
              <p className="text-sm text-gray-600">Collect lab samples</p>
            </button>

            <button
              onClick={() => setActiveTab('upload')}
              className="p-4 border-2 border-green-300 rounded-lg hover:bg-green-50 transition text-left"
            >
              <Upload className="text-green-600 mb-2" size={24} />
              <p className="font-semibold text-gray-800">Upload Test Results</p>
              <p className="text-sm text-gray-600">Upload and encrypt results</p>
            </button>
          </div>
        </div>
      </Card>
    </div>
  )

  // Test Orders Tab
  const renderTestOrders = () => (
    <div className="space-y-4">
      <div className="flex flex-col md:flex-row gap-4 items-center">
        <h2 className="text-2xl font-bold text-gray-800">Test Orders</h2>
        <div className="flex-1 flex gap-2">
          <div className="flex-1 relative">
            <Search
              className="absolute left-3 top-3 text-gray-400"
              size={18}
            />
            <input
              type="text"
              placeholder="Search tests..."
              value={testSearch}
              onChange={(e) => setTestSearch(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border rounded-lg focus:outline-none focus:border-blue-500"
            />
          </div>
          <select
            value={testFilter}
            onChange={(e) => setTestFilter(e.target.value)}
            className="px-4 py-2 border rounded-lg focus:outline-none focus:border-blue-500"
          >
            <option value="all">All Status</option>
            <option value="pending">Pending</option>
            <option value="collected">Collected</option>
            <option value="completed">Completed</option>
          </select>
        </div>
      </div>

      {loading ? (
        <div className="flex justify-center items-center py-8">
          <Loader className="animate-spin text-blue-600" size={32} />
        </div>
      ) : filteredTests.length === 0 ? (
        <Card>
          <div className="p-8 text-center">
            <AlertCircle className="mx-auto mb-4 text-gray-400" size={48} />
            <p className="text-gray-600">No tests found</p>
          </div>
        </Card>
      ) : (
        <Card>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b bg-gray-50">
                  <th className="px-6 py-3 text-left text-sm font-semibold text-gray-700">
                    Test ID
                  </th>
                  <th className="px-6 py-3 text-left text-sm font-semibold text-gray-700">
                    Patient
                  </th>
                  <th className="px-6 py-3 text-left text-sm font-semibold text-gray-700">
                    Doctor
                  </th>
                  <th className="px-6 py-3 text-left text-sm font-semibold text-gray-700">
                    Test Type
                  </th>
                  <th className="px-6 py-3 text-left text-sm font-semibold text-gray-700">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-sm font-semibold text-gray-700">
                    Action
                  </th>
                </tr>
              </thead>
              <tbody>
                {filteredTests.map((test: any) => (
                  <tr key={test.id} className="border-b hover:bg-gray-50">
                    <td className="px-6 py-4 text-sm text-gray-900">
                      {test.test_id_masked}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-900">
                      {test.patient_name}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-900">
                      {test.doctor_name}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-900">
                      {test.test_type}
                    </td>
                    <td className="px-6 py-4 text-sm">
                      <span
                        className={`px-3 py-1 rounded-full text-xs font-semibold ${
                          test.status === 'pending'
                            ? 'bg-yellow-100 text-yellow-800'
                            : test.status === 'collected'
                              ? 'bg-blue-100 text-blue-800'
                              : 'bg-green-100 text-green-800'
                        }`}
                      >
                        {test.status.charAt(0).toUpperCase() + test.status.slice(1)}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm">
                      {test.status === 'pending' && (
                        <button
                          onClick={() => {
                            setSelectedTestForSample(test)
                            setShowCollectSample(true)
                          }}
                          className="px-3 py-1 bg-blue-600 text-white rounded hover:bg-blue-700 text-xs font-semibold"
                        >
                          Collect
                        </button>
                      )}
                      {test.status === 'collected' && (
                        <button
                          onClick={() => {
                            setSelectedTestForUpload(test)
                            setShowUploadResults(true)
                          }}
                          className="px-3 py-1 bg-green-600 text-white rounded hover:bg-green-700 text-xs font-semibold"
                        >
                          Upload
                        </button>
                      )}
                      {test.status === 'completed' && (
                        <button
                          onClick={() => handleViewResult(test)}
                          className="px-3 py-1 bg-purple-600 text-white rounded hover:bg-purple-700 text-xs font-semibold"
                        >
                          View
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  )

  // Sample Collection Tab
  const renderSampleCollection = () => (
    <div className="space-y-4">
      <h2 className="text-2xl font-bold text-gray-800">Sample Collection</h2>

      {loading ? (
        <div className="flex justify-center items-center py-8">
          <Loader className="animate-spin text-blue-600" size={32} />
        </div>
      ) : testOrders.filter((t: any) => t.status === 'pending').length === 0 ? (
        <Card>
          <div className="p-8 text-center">
            <AlertCircle className="mx-auto mb-4 text-gray-400" size={48} />
            <p className="text-gray-600">No pending tests available for sample collection</p>
          </div>
        </Card>
      ) : (
        <Card>
          <div className="p-6">
            <div className="space-y-4">
              {testOrders
                .filter((t: any) => t.status === 'pending')
                .map((test: any) => (
                  <div
                    key={test.id}
                    className="p-4 border rounded-lg hover:bg-gray-50 cursor-pointer transition"
                    onClick={() => {
                      setSelectedTestForSample(test)
                      setShowCollectSample(true)
                    }}
                  >
                    <div className="flex justify-between items-start">
                      <div>
                        <p className="font-semibold text-gray-900">{test.test_id_masked}</p>
                        <p className="text-sm text-gray-600">{test.test_type}</p>
                        <p className="text-sm text-gray-600">Patient: {test.patient_name}</p>
                        <p className="text-sm text-gray-600">Doctor: {test.doctor_name}</p>
                      </div>
                      <button className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">
                        <Plus size={18} />
                      </button>
                    </div>
                  </div>
                ))}
            </div>
          </div>
        </Card>
      )}
    </div>
  )

  // Upload Results Tab
  const renderUploadResults = () => (
    <div className="space-y-4">
      <h2 className="text-2xl font-bold text-gray-800">Upload Results</h2>

      {loading ? (
        <div className="flex justify-center items-center py-8">
          <Loader className="animate-spin text-blue-600" size={32} />
        </div>
      ) : testOrders.filter((t: any) => t.status === 'collected').length === 0 ? (
        <Card>
          <div className="p-8 text-center">
            <AlertCircle className="mx-auto mb-4 text-gray-400" size={48} />
            <p className="text-gray-600">No collected samples available for upload</p>
          </div>
        </Card>
      ) : (
        <Card>
          <div className="p-6">
            <div className="space-y-4">
              {testOrders
                .filter((t: any) => t.status === 'collected')
                .map((test: any) => (
                  <div
                    key={test.id}
                    className="p-4 border rounded-lg hover:bg-gray-50 cursor-pointer transition"
                    onClick={() => {
                      setSelectedTestForUpload(test)
                      setShowUploadResults(true)
                    }}
                  >
                    <div className="flex justify-between items-start">
                      <div>
                        <p className="font-semibold text-gray-900">{test.test_id_masked}</p>
                        <p className="text-sm text-gray-600">{test.test_type}</p>
                        <p className="text-sm text-gray-600">Patient: {test.patient_name}</p>
                        <p className="text-sm text-gray-600">Doctor: {test.doctor_name}</p>
                      </div>
                      <button className="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700">
                        <Upload size={18} />
                      </button>
                    </div>
                  </div>
                ))}
            </div>
          </div>
        </Card>
      )}
    </div>
  )

  // Completed Tests Tab
  const renderCompletedTests = () => (
    <div className="space-y-4">
      <h2 className="text-2xl font-bold text-gray-800">Completed Tests</h2>

      {loading ? (
        <div className="flex justify-center items-center py-8">
          <Loader className="animate-spin text-blue-600" size={32} />
        </div>
      ) : completedTests.length === 0 ? (
        <Card>
          <div className="p-8 text-center">
            <AlertCircle className="mx-auto mb-4 text-gray-400" size={48} />
            <p className="text-gray-600">No completed tests yet</p>
          </div>
        </Card>
      ) : (
        <Card>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b bg-gray-50">
                  <th className="px-6 py-3 text-left text-sm font-semibold text-gray-700">
                    Test ID
                  </th>
                  <th className="px-6 py-3 text-left text-sm font-semibold text-gray-700">
                    Patient
                  </th>
                  <th className="px-6 py-3 text-left text-sm font-semibold text-gray-700">
                    Type
                  </th>
                  <th className="px-6 py-3 text-left text-sm font-semibold text-gray-700">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-sm font-semibold text-gray-700">
                    Action
                  </th>
                </tr>
              </thead>
              <tbody>
                {completedTests.map((test: any) => (
                  <tr key={test.id} className="border-b hover:bg-gray-50">
                    <td className="px-6 py-4 text-sm text-gray-900">
                      {test.test_id_masked}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-900">
                      {test.patient_name}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-900">
                      {test.test_type}
                    </td>
                    <td className="px-6 py-4 text-sm">
                      <span className="px-3 py-1 rounded-full text-xs font-semibold bg-green-100 text-green-800">
                        Completed
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm">
                      <button
                        onClick={() => handleViewResult(test)}
                        className="px-3 py-1 bg-purple-600 text-white rounded hover:bg-purple-700 text-xs font-semibold"
                      >
                        View
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  )

  return (
    <div className="space-y-6">
      {/* Alerts */}
      {error && (
        <div className="p-4 bg-red-100 border border-red-400 text-red-700 rounded-lg flex items-center gap-2">
          <AlertCircle size={20} />
          {error}
          <button
            onClick={() => setError('')}
            className="ml-auto text-xl font-bold"
          >
            ×
          </button>
        </div>
      )}

      {success && (
        <div className="p-4 bg-green-100 border border-green-400 text-green-700 rounded-lg flex items-center gap-2">
          <CheckCircle size={20} />
          {success}
          <button
            onClick={() => setSuccess('')}
            className="ml-auto text-xl font-bold"
          >
            ×
          </button>
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-2 border-b overflow-x-auto">
        {[
          { id: 'dashboard', label: 'Dashboard', icon: BarChart3 },
          { id: 'orders', label: 'Test Orders', icon: TestTube },
          { id: 'samples', label: 'Collect Samples', icon: Droplet },
          { id: 'upload', label: 'Upload Results', icon: Upload },
          { id: 'completed', label: 'Completed Tests', icon: CheckCircle }
        ].map((tab) => {
          const Icon = tab.icon
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-3 font-semibold whitespace-nowrap flex items-center gap-2 transition ${
                activeTab === tab.id
                  ? 'border-b-2 border-blue-600 text-blue-600'
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              <Icon size={18} />
              {tab.label}
            </button>
          )
        })}
      </div>

      {/* Tab Content */}
      {activeTab === 'dashboard' && renderDashboard()}
      {activeTab === 'orders' && renderTestOrders()}
      {activeTab === 'samples' && renderSampleCollection()}
      {activeTab === 'upload' && renderUploadResults()}
      {activeTab === 'completed' && renderCompletedTests()}

      {/* Collect Sample Modal */}
      <Modal
        isOpen={showCollectSample}
        title="Collect Lab Sample"
        onClose={() => {
          setShowCollectSample(false)
          setSampleForm({ collectionNotes: '', sampleBarcode: '', sampleType: 'Blood' })
        }}
      >
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">
                Test ID: {selectedTestForSample.test_id_masked}
              </label>
            </div>

            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">
                Sample Type
              </label>
              <select
                value={sampleForm.sampleType}
                onChange={(e) =>
                  setSampleForm({ ...sampleForm, sampleType: e.target.value })
                }
                className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:border-blue-500"
              >
                <option value="Blood">Blood</option>
                <option value="Urine">Urine</option>
                <option value="Tissue">Tissue</option>
                <option value="CSF">CSF</option>
                <option value="Other">Other</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">
                Sample Barcode (Optional)
              </label>
              <input
                type="text"
                value={sampleForm.sampleBarcode}
                onChange={(e) =>
                  setSampleForm({ ...sampleForm, sampleBarcode: e.target.value })
                }
                placeholder="Enter barcode or QR code"
                className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:border-blue-500"
              />
            </div>

            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">
                Collection Notes
              </label>
              <textarea
                value={sampleForm.collectionNotes}
                onChange={(e) =>
                  setSampleForm({ ...sampleForm, collectionNotes: e.target.value })
                }
                placeholder="Add any collection notes..."
                rows={3}
                className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:border-blue-500"
              />
            </div>

            <div className="flex gap-3 justify-end">
              <button
                onClick={() => {
                  setShowCollectSample(false)
                  setSampleForm({ collectionNotes: '', sampleBarcode: '', sampleType: 'Blood' })
                }}
                className="px-4 py-2 border rounded-lg text-gray-700 hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={handleCollectSample}
                disabled={loading}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                {loading ? 'Processing...' : 'Collect Sample'}
              </button>
            </div>
          </div>
        </Modal>

      {/* Upload Results Modal */}
      <Modal
        isOpen={showUploadResults}
        title="Upload Lab Results"
        onClose={() => {
          setShowUploadResults(false)
          setUploadForm({ testParameters: '', observations: '', pdfFile: null })
          setUploadProgress(0)
        }}
      >
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">
                Test ID: {selectedTestForUpload.test_id_masked}
              </label>
            </div>

            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">
                Test Parameters *
              </label>
              <textarea
                value={uploadForm.testParameters}
                onChange={(e) =>
                  setUploadForm({ ...uploadForm, testParameters: e.target.value })
                }
                placeholder="Enter test parameters (e.g., Hemoglobin: 13.5, RBC: 4.8)"
                rows={3}
                className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:border-blue-500"
              />
            </div>

            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">
                Observations
              </label>
              <textarea
                value={uploadForm.observations}
                onChange={(e) =>
                  setUploadForm({ ...uploadForm, observations: e.target.value })
                }
                placeholder="Add any observations..."
                rows={3}
                className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:border-blue-500"
              />
            </div>

            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">
                Upload PDF Report *
              </label>
              <input
                type="file"
                accept=".pdf,.png,.jpg,.jpeg"
                onChange={(e) => {
                  const file = e.target.files?.[0]
                  if (file && file.size > 10 * 1024 * 1024) {
                    setError('File size must be less than 10MB')
                  } else {
                    setUploadForm({ ...uploadForm, pdfFile: file || null })
                  }
                }}
                className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:border-blue-500"
              />
              {uploadForm.pdfFile && (
                <p className="text-sm text-green-600 mt-2">
                  ✓ File selected: {uploadForm.pdfFile.name}
                </p>
              )}
            </div>

            {uploadProgress > 0 && uploadProgress < 100 && (
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div
                  className="bg-blue-600 h-2 rounded-full transition-all"
                  style={{ width: `${uploadProgress}%` }}
                ></div>
              </div>
            )}

            <div className="flex gap-3 justify-end">
              <button
                onClick={() => {
                  setShowUploadResults(false)
                  setUploadForm({ testParameters: '', observations: '', pdfFile: null })
                  setUploadProgress(0)
                }}
                className="px-4 py-2 border rounded-lg text-gray-700 hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={handleUploadResults}
                disabled={loading || !uploadForm.testParameters || !uploadForm.pdfFile}
                className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50"
              >
                {loading ? `Uploading... ${uploadProgress}%` : 'Upload Results'}
              </button>
            </div>
          </div>
        </Modal>

      {/* View Result Modal */}
      <Modal
        isOpen={showViewResult}
        title="Test Result Details"
        onClose={() => {
          setShowViewResult(false)
          setSelectedResult(null)
        }}
      >
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">
                Test Parameters
              </label>
              <div className="p-3 bg-gray-50 rounded-lg">
                <p className="text-gray-700 whitespace-pre-wrap">
                  {selectedResult.resultValues}
                </p>
              </div>
            </div>

            {selectedResult.observations && (
              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2">
                  Observations
                </label>
                <div className="p-3 bg-gray-50 rounded-lg">
                  <p className="text-gray-700 whitespace-pre-wrap">
                    {selectedResult.observations}
                  </p>
                </div>
              </div>
            )}

            <div className="flex gap-3 justify-end">
              <button
                onClick={() => {
                  setShowViewResult(false)
                  setSelectedResult(null)
                }}
                className="px-4 py-2 border rounded-lg text-gray-700 hover:bg-gray-50"
              >
                Close
              </button>
            </div>
          </div>
        </Modal>
    </div>
  )
}

export default LabTechnician

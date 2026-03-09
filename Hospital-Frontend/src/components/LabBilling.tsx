import React, { useState, useEffect } from 'react'
import { DollarSign, Plus, User, Search, RefreshCw, CheckCircle, AlertCircle, FileText, CreditCard } from 'lucide-react'
import Card from './Card'
import Button from './Button'
import Modal from './Modal'

interface LabBill {
  id: string
  patient_id: string
  first_name: string
  last_name: string
  test_name: string
  lab_fees: number
  status: 'pending' | 'billed' | 'paid'
  created_at: string
  billed_at?: string
}

interface LabBillingProps {
  userEmail: string
  userName: string
  userRole: string
}

const LabBilling: React.FC<LabBillingProps> = ({ userEmail, userName, userRole }) => {
  const [bills, setBills] = useState<LabBill[]>([])
  const [loading, setLoading] = useState(true)
  const [showAddFeeModal, setShowAddFeeModal] = useState(false)
  const [selectedBill, setSelectedBill] = useState<LabBill | null>(null)
  const [labFee, setLabFee] = useState('')
  const [searchTerm, setSearchTerm] = useState('')

  useEffect(() => {
    loadBills()
  }, [])

  const loadBills = async () => {
    try {
      setLoading(true)
      const token = localStorage.getItem('hp_access_token')
      if (!token) return

      // Fetch completed lab tests that need billing
      const response = await fetch('/api/lab-tests', {
        headers: { 'Authorization': `Bearer ${token}` }
      })
      
      if (response.ok) {
        const data = await response.json()
        // Transform lab tests to billing format
        const labBills = (data.data || []).map((test: any) => ({
          id: test.id,
          patient_id: test.patient_id,
          first_name: test.first_name,
          last_name: test.last_name,
          test_name: test.test_name,
          lab_fees: test.lab_fees || 0,
          status: test.lab_fees ? 'billed' : 'pending',
          created_at: test.created_at,
          billed_at: test.billed_at
        }))
        setBills(labBills)
      }
    } catch (error) {
      console.error('Failed to load lab bills:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleAddLabFee = async () => {
    if (!selectedBill || !labFee) {
      alert('Please enter a lab fee amount')
      return
    }

    try {
      const token = localStorage.getItem('hp_access_token')
      if (!token) return

      const response = await fetch(`/api/lab-tests/${selectedBill.id}/billing`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          lab_fees: parseFloat(labFee),
          billed_by: userName
        })
      })

      if (response.ok) {
        await loadBills()
        setShowAddFeeModal(false)
        setSelectedBill(null)
        setLabFee('')
        alert('Lab fee added successfully!')
      } else {
        const err = await response.json()
        alert(`Error: ${err.error || 'Failed to add lab fee'}`)
      }
    } catch (error) {
      alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  const filteredBills = bills.filter(bill =>
    `${bill.first_name} ${bill.last_name}`.toLowerCase().includes(searchTerm.toLowerCase()) ||
    bill.test_name.toLowerCase().includes(searchTerm.toLowerCase())
  )

  const totalBilled = bills.reduce((sum, b) => sum + (b.lab_fees || 0), 0)
  const pendingCount = bills.filter(b => !b.lab_fees || b.lab_fees === 0).length

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <DollarSign size={28} className="text-green-400" />
          Lab Billing
        </h2>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="border-l-4 border-blue-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Total Tests</p>
              <p className="text-3xl font-bold text-blue-400">{bills.length}</p>
            </div>
            <FileText size={28} className="text-blue-500/40" />
          </div>
        </Card>
        <Card className="border-l-4 border-yellow-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Pending Billing</p>
              <p className="text-3xl font-bold text-yellow-400">{pendingCount}</p>
            </div>
            <AlertCircle size={28} className="text-yellow-500/40" />
          </div>
        </Card>
        <Card className="border-l-4 border-green-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Total Billed</p>
              <p className="text-3xl font-bold text-green-400">${totalBilled.toFixed(2)}</p>
            </div>
            <CreditCard size={28} className="text-green-500/40" />
          </div>
        </Card>
      </div>

      {/* Search */}
      <Card>
        <div className="flex items-center gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={18} />
            <input
              type="text"
              placeholder="Search by patient or test name..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
            />
          </div>
          <Button onClick={loadBills} className="bg-gray-600 hover:bg-gray-500 text-white gap-2">
            <RefreshCw size={18} />
            Refresh
          </Button>
        </div>
      </Card>

      {/* Bills List */}
      <Card>
        {loading ? (
          <div className="text-center py-8 text-gray-400">Loading lab bills...</div>
        ) : filteredBills.length === 0 ? (
          <div className="text-center py-8 text-gray-400">No lab tests found</div>
        ) : (
          <div className="space-y-4">
            {filteredBills.map((bill) => (
              <div key={bill.id} className="bg-gray-700 rounded-lg p-4 border border-gray-600">
                <div className="flex justify-between items-start">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-full bg-blue-500/20 flex items-center justify-center">
                      <User size={20} className="text-blue-400" />
                    </div>
                    <div>
                      <h3 className="text-white font-semibold">{bill.first_name} {bill.last_name}</h3>
                      <p className="text-gray-400 text-sm">{bill.test_name}</p>
                      <p className="text-gray-500 text-xs mt-1">
                        Date: {new Date(bill.created_at).toLocaleDateString()}
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    {bill.lab_fees > 0 ? (
                      <div>
                        <span className="text-green-400 font-bold text-xl">${bill.lab_fees.toFixed(2)}</span>
                        <p className="text-green-500 text-xs flex items-center gap-1 justify-end mt-1">
                          <CheckCircle size={12} /> Billed
                        </p>
                      </div>
                    ) : (
                      <div>
                        <span className="text-yellow-400 text-sm">Not Billed</span>
                        <Button
                          onClick={() => {
                            setSelectedBill(bill)
                            setShowAddFeeModal(true)
                          }}
                          className="mt-2 bg-green-600 hover:bg-green-700 text-white gap-1 text-xs"
                          size="sm"
                        >
                          <Plus size={14} />
                          Add Fee
                        </Button>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Add Lab Fee Modal */}
      <Modal
        isOpen={showAddFeeModal}
        onClose={() => setShowAddFeeModal(false)}
        title="Add Lab Test Fee"
        size="md"
      >
        <div className="space-y-4">
          {/* Patient & Test Info Card */}
          <div className="bg-gradient-to-r from-blue-500/10 to-purple-500/10 border border-blue-500/30 rounded-lg p-4">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-full bg-blue-500/20 flex items-center justify-center">
                <User size={24} className="text-blue-400" />
              </div>
              <div>
                <h3 className="font-semibold text-white">{selectedBill?.first_name} {selectedBill?.last_name}</h3>
                <p className="text-sm text-gray-400">{selectedBill?.test_name}</p>
              </div>
            </div>
          </div>

          {/* Fee Input Card */}
          <div className="bg-gray-700 rounded-xl p-4 border border-gray-600">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-8 h-8 bg-green-600 rounded-full flex items-center justify-center">
                <DollarSign size={16} className="text-white" />
              </div>
              <span className="text-green-400 font-semibold text-sm">Lab Test Fee</span>
            </div>
            <div className="relative">
              <span className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 text-lg">$</span>
              <input
                type="number"
                value={labFee}
                onChange={(e) => setLabFee(e.target.value)}
                placeholder="0.00"
                step="0.01"
                min="0"
                className="w-full pl-8 pr-4 py-3 bg-gray-800 border border-gray-600 rounded-lg text-white text-2xl font-bold focus:border-green-500 focus:ring-1 focus:ring-green-500"
              />
            </div>
            <p className="text-xs text-gray-500 mt-2">Enter the fee for the lab test performed</p>
          </div>

          {/* Quick Fee Buttons */}
          <div className="grid grid-cols-4 gap-2">
            {[50, 100, 150, 200].map((amount) => (
              <button
                key={amount}
                onClick={() => setLabFee(amount.toString())}
                className="py-2 bg-gray-700 hover:bg-gray-600 rounded text-gray-300 text-sm transition"
              >
                ${amount}
              </button>
            ))}
          </div>

          <div className="flex gap-2 justify-end pt-4">
            <Button onClick={() => setShowAddFeeModal(false)} variant="ghost">Cancel</Button>
            <Button onClick={handleAddLabFee} className="bg-green-600 hover:bg-green-700">
              <CheckCircle size={16} className="mr-1" />
              Add Fee
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}

export default LabBilling


import React, { useState, useEffect } from 'react'
import { Plus, DollarSign, Download, Eye, CreditCard, AlertCircle, Printer, Trash2, Edit2, X } from 'lucide-react'
import Card from './Card'
import Button from './Button'
import Modal from './Modal'

interface ChargeItem {
  id: string
  service_name: string
  description?: string
  quantity: number
  unit_price: number
  total: number
  date_of_service?: string
  added_by?: string
}

interface Bill {
  id: string
  patient_id?: string
  first_name?: string
  last_name?: string
  age?: number
  assigned_doctor?: string
  department?: string
  admitted_date?: string
  discharged_date?: string
  total_amount?: number
  amount_paid?: number
  discount?: number
  tax?: number
  insurance_coverage?: number
  status?: 'pending' | 'partial' | 'paid' | 'overdue'
  payment_method?: string
  payment_date?: string
  notes?: string
  services?: ChargeItem[]
  service_total?: number
  created_at?: string
  created_by?: string
  // Fee breakdown
  doctor_fees?: number
  lab_fees?: number
  pharmacist_fees?: number
}

interface BillingProps {
  userEmail: string
  userName: string
  userRole: string
  hasViewPermission: boolean
}

const BillingNew: React.FC<BillingProps> = ({
  userEmail,
  userName,
  userRole,
  hasViewPermission
}) => {
  const [bills, setBills] = useState<Bill[]>([])
  const [loading, setLoading] = useState(true)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [showDetailModal, setShowDetailModal] = useState(false)
  const [showAddChargeModal, setShowAddChargeModal] = useState(false)
  const [showPaymentModal, setShowPaymentModal] = useState(false)
  const [selectedBill, setSelectedBill] = useState<Bill | null>(null)
  const [charges, setCharges] = useState<ChargeItem[]>([])
  
  // Create bill form with fee breakdown
  const [newBill, setNewBill] = useState({
    patientId: '',
    patientName: '',
    doctorName: '',
    department: '',
    admittedDate: '',
    dischargedDate: '',
    doctorFees: 0,
    labFees: 0,
    pharmacistFees: 0
  })
  
  // Add charge form
  const [newCharge, setNewCharge] = useState({
    serviceName: '',
    description: '',
    quantity: 1,
    unitPrice: 0,
    dateOfService: new Date().toISOString().split('T')[0]
  })
  
  // Payment form
  const [payment, setPayment] = useState({
    amount: 0,
    method: 'cash', // cash, card, upi, insurance
    notes: '',
    discountReason: '',
    insuranceDetails: ''
  })
  
  // Discount & tax
  const [discount, setDiscount] = useState(0)
  const [discountReason, setDiscountReason] = useState('')
  const [tax, setTax] = useState(0)
  const [insuranceCoverage, setInsuranceCoverage] = useState(0)

  // Lab technician specific - lab fee modal
  const [showLabFeeModal, setShowLabFeeModal] = useState(false)
  const [labFeeAmount, setLabFeeAmount] = useState(0)

  // Pharmacist specific - pharmacy fee modal
  const [showPharmacyFeeModal, setShowPharmacyFeeModal] = useState(false)
  const [pharmacyFeeAmount, setPharmacyFeeAmount] = useState(0)

  // Receptionist specific - doctor fees modal
  const [showDoctorFeeModal, setShowDoctorFeeModal] = useState(false)
  const [doctorFeeAmount, setDoctorFeeAmount] = useState(0)

  useEffect(() => {
    loadBills()
  }, [userRole])

  const loadBills = async () => {
    try {
      setLoading(true)
      const token = localStorage.getItem('hp_access_token')
      if (!token) {
        setBills([])
        setLoading(false)
        return
      }

      const response = await fetch('/api/billing', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })

      if (response.ok) {
        const data = await response.json()
        setBills(data.data || [])
      }
    } catch (error) {
      console.error('Failed to load bills:', error)
      setBills([])
    } finally {
      setLoading(false)
    }
  }

  // Role-based permission checks
  const canCreateBills = ['admin', 'accountant', 'receptionist'].includes(userRole)
  const canEditBills = ['admin', 'accountant'].includes(userRole)
  const canAddCharges = ['admin', 'accountant', 'receptionist', 'doctor', 'pharmacist', 'lab_technician'].includes(userRole)
  const canApplyDiscount = ['admin', 'accountant'].includes(userRole)
  const canProcessPayment = ['admin', 'accountant', 'receptionist'].includes(userRole)
  const canViewFullBilling = ['admin', 'accountant', 'doctor', 'pharmacist', 'lab_technician'].includes(userRole)

  const handleCreateBill = async () => {
    if (!newBill.patientId) {
      alert('Please fill in all fields')
      return
    }

    try {
      const token = localStorage.getItem('hp_access_token')
      if (!token) return

      const response = await fetch('/api/billing', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          patient_id: newBill.patientId,
          notes: `Doctor: ${newBill.doctorName}, Dept: ${newBill.department}`,
          doctor_fees: newBill.doctorFees,
          lab_fees: newBill.labFees,
          pharmacist_fees: newBill.pharmacistFees
        })
      })

      if (response.ok) {
        await loadBills()
        setShowCreateModal(false)
        setNewBill({ patientId: '', patientName: '', doctorName: '', department: '', admittedDate: '', dischargedDate: '', doctorFees: 0, labFees: 0, pharmacistFees: 0 })
        alert('Bill created successfully!')
      }
    } catch (error) {
      alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  const handleAddCharge = async () => {
    if (!selectedBill || !newCharge.serviceName || newCharge.quantity <= 0 || newCharge.unitPrice <= 0) {
      alert('Please fill in all required fields')
      return
    }

    try {
      const token = localStorage.getItem('hp_access_token')
      if (!token) return

      const response = await fetch(`/api/billing/${selectedBill.id}/services`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          service_name: newCharge.serviceName,
          description: newCharge.description,
          quantity: newCharge.quantity,
          amount: newCharge.unitPrice * newCharge.quantity
        })
      })

      if (response.ok) {
        await loadBills()
        setShowAddChargeModal(false)
        setNewCharge({ serviceName: '', description: '', quantity: 1, unitPrice: 0, dateOfService: new Date().toISOString().split('T')[0] })
        alert('Charge added successfully!')
      }
    } catch (error) {
      alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  const handlePayment = async () => {
    if (!selectedBill || payment.amount <= 0) {
      alert('Please enter valid payment amount')
      return
    }

    try {
      const token = localStorage.getItem('hp_access_token')
      if (!token) return

      const response = await fetch(`/api/billing/${selectedBill.id}/payment`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          amount: payment.amount,
          payment_method: payment.method,
          discount_reason: payment.discountReason || undefined,
          insurance_details: payment.insuranceDetails ? JSON.parse(payment.insuranceDetails) : undefined,
          notes: payment.notes
        })
      })

      if (response.ok) {
        await loadBills()
        setShowPaymentModal(false)
        setPayment({ amount: 0, method: 'cash', notes: '', discountReason: '', insuranceDetails: '' })
        alert('Payment processed successfully!')
      }
    } catch (error) {
      alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  // Lab technician - update lab fees
  const handleUpdateLabFees = async () => {
    if (!selectedBill || labFeeAmount < 0) {
      alert('Please enter a valid lab fee amount')
      return
    }

    try {
      const token = localStorage.getItem('hp_access_token')
      if (!token) return

      const response = await fetch(`/api/billing/${selectedBill.id}/lab-fees`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ lab_fees: labFeeAmount })
      })

      if (response.ok) {
        await loadBills()
        setShowLabFeeModal(false)
        setLabFeeAmount(0)
        setSelectedBill(null)
        alert('Lab fees updated successfully! This will be reflected in the receptionist billing.')
      } else {
        const err = await response.json()
        alert(`Error: ${err.error || 'Failed to update lab fees'}`)
      }
    } catch (error) {
      alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  // Pharmacist - update pharmacy/prescription fees
  const handleUpdatePharmacyFees = async () => {
    if (!selectedBill || pharmacyFeeAmount < 0) {
      alert('Please enter a valid pharmacy fee amount')
      return
    }

    try {
      const token = localStorage.getItem('hp_access_token')
      if (!token) return

      const response = await fetch(`/api/billing/${selectedBill.id}/pharmacy-fees`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ pharmacist_fees: pharmacyFeeAmount })
      })

      if (response.ok) {
        await loadBills()
        setShowPharmacyFeeModal(false)
        setPharmacyFeeAmount(0)
        setSelectedBill(null)
        alert('Pharmacy fees updated successfully! This will be reflected in the receptionist billing.')
      } else {
        const err = await response.json()
        alert(`Error: ${err.error || 'Failed to update pharmacy fees'}`)
      }
    } catch (error) {
      alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  // Receptionist - update doctor fees
  const handleUpdateDoctorFees = async () => {
    if (!selectedBill || doctorFeeAmount < 0) {
      alert('Please enter a valid doctor fee amount')
      return
    }

    try {
      const token = localStorage.getItem('hp_access_token')
      if (!token) return

      const response = await fetch(`/api/billing/${selectedBill.id}/doctor-fees`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ doctor_fees: doctorFeeAmount })
      })

      if (response.ok) {
        await loadBills()
        setShowDoctorFeeModal(false)
        setDoctorFeeAmount(0)
        setSelectedBill(null)
        alert('Doctor fees updated successfully!')
      } else {
        const err = await response.json()
        alert(`Error: ${err.error || 'Failed to update doctor fees'}`)
      }
    } catch (error) {
      alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  const downloadInvoicePDF = async (billId: string) => {
    try {
      const token = localStorage.getItem('hp_access_token')
      if (!token) return

      const response = await fetch(`/api/billing/${billId}/invoice`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })

      if (response.ok) {
        const blob = await response.blob()
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `invoice_${billId}.pdf`
        document.body.appendChild(a)
        a.click()
        window.URL.revokeObjectURL(url)
        document.body.removeChild(a)
      } else {
        alert('Failed to download invoice')
      }
    } catch (error) {
      alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'paid':
        return 'bg-green-500/20 text-green-400'
      case 'partial':
        return 'bg-blue-500/20 text-blue-400'
      case 'overdue':
        return 'bg-red-500/20 text-red-400'
      default:
        return 'bg-yellow-500/20 text-yellow-400'
    }
  }

  const calculateTotals = (bill: Bill) => {
    const subtotal = bill.total_amount || 0
    const discountAmount = bill.discount || discount
    const taxAmount = bill.tax || tax
    const insurance = bill.insurance_coverage || insuranceCoverage
    const amountPaid = bill.amount_paid || 0
    const finalAmount = subtotal - discountAmount + taxAmount - insurance
    const pending = Math.max(0, finalAmount - amountPaid)
    
    return { subtotal, discountAmount, taxAmount, insurance, finalAmount, pending, amountPaid }
  }

  const totalBilled = bills.reduce((sum, bill) => sum + (calculateTotals(bill).finalAmount || 0), 0)
  const totalPending = bills
    .filter(b => (b.status || 'pending') !== 'paid')
    .reduce((sum, bill) => sum + (calculateTotals(bill).pending || 0), 0)

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold text-white">💳 Billing & Invoices</h2>
        {canCreateBills && (
          <Button
            onClick={() => setShowCreateModal(true)}
            className="bg-blue-600 hover:bg-blue-700 text-white gap-2"
          >
            <Plus size={18} />
            New Bill
          </Button>
        )}
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="border-l-4 border-green-500">
          <p className="text-gray-400 text-sm">Total Billed</p>
          <p className="text-2xl font-bold text-green-400">${totalBilled.toFixed(2)}</p>
        </Card>
        <Card className="border-l-4 border-red-500">
          <p className="text-gray-400 text-sm">Pending Payment</p>
          <p className="text-2xl font-bold text-red-400">${totalPending.toFixed(2)}</p>
        </Card>
        <Card className="border-l-4 border-blue-500">
          <p className="text-gray-400 text-sm">Total Bills</p>
          <p className="text-2xl font-bold text-blue-400">{bills.length}</p>
        </Card>
        <Card className="border-l-4 border-purple-500">
          <p className="text-gray-400 text-sm">Paid Bills</p>
          <p className="text-2xl font-bold text-purple-400">{bills.filter(b => (b.status || '') === 'paid').length}</p>
        </Card>
      </div>

      {/* Bills List */}
      <Card>
        {loading ? (
          <p className="text-gray-400">Loading bills...</p>
        ) : bills.length === 0 ? (
          <p className="text-gray-400">No bills found</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/6 text-gray-400">
                  <th className="px-3 py-3 text-left font-semibold">Patient</th>
                  <th className="px-3 py-3 text-left font-semibold text-blue-400">Doctor Fees</th>
                  <th className="px-3 py-3 text-left font-semibold text-green-400">Lab Fees</th>
                  <th className="px-3 py-3 text-left font-semibold text-purple-400">Pharmacy Fees</th>
                  <th className="px-3 py-3 text-left font-semibold">Total Amount</th>
                  <th className="px-3 py-3 text-left font-semibold">Paid</th>
                  <th className="px-3 py-3 text-left font-semibold">Status</th>
                  <th className="px-3 py-3 text-left font-semibold">Date</th>
                  <th className="px-3 py-3 text-center font-semibold">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/6">
                {bills.map(bill => {
                  const totals = calculateTotals(bill)
                  return (
                    <tr key={bill.id} className="hover:bg-white/2">
                      <td className="px-3 py-4">
                        <div>
                          <p className="font-semibold">{bill.first_name || 'Unknown'} {bill.last_name || ''}</p>
                          <p className="text-xs text-gray-500">ID: {bill.patient_id?.substring(0, 8) || 'N/A'}</p>
                        </div>
                      </td>
                      <td className="px-3 py-4 text-blue-400 font-semibold">${(bill.doctor_fees || 0).toFixed(2)}</td>
                      <td className="px-3 py-4 text-green-400 font-semibold">${(bill.lab_fees || 0).toFixed(2)}</td>
                      <td className="px-3 py-4 text-purple-400 font-semibold">${(bill.pharmacist_fees || 0).toFixed(2)}</td>
                      <td className="px-3 py-4 font-bold text-white">${totals.finalAmount.toFixed(2)}</td>
                      <td className="px-3 py-4 text-cyan-400">${totals.amountPaid.toFixed(2)}</td>
                      <td className="px-3 py-4">
                        <span className={`px-2 py-1 rounded text-xs font-semibold ${getStatusColor(bill.status || 'pending')}`}>
                          {(bill.status || 'pending').charAt(0).toUpperCase() + (bill.status || 'pending').slice(1)}
                        </span>
                      </td>
                      <td className="px-3 py-4 text-xs text-gray-500">{bill.created_at ? new Date(bill.created_at).toLocaleDateString() : 'N/A'}</td>
                      <td className="px-3 py-4">
                        <div className="flex gap-1 justify-center">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setSelectedBill(bill)
                              setShowDetailModal(true)
                            }}
                          >
                            <Eye size={14} />
                          </Button>
                          {canAddCharges && bill.status !== 'paid' && userRole !== 'lab_technician' && userRole !== 'pharmacist' && (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                setSelectedBill(bill)
                                setShowAddChargeModal(true)
                              }}
                            >
                              <Plus size={14} />
                            </Button>
                          )}
                          {userRole === 'lab_technician' && bill.status !== 'paid' && (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                setSelectedBill(bill)
                                setLabFeeAmount(bill.lab_fees || 0)
                                setShowLabFeeModal(true)
                              }}
                              className="text-green-400 hover:text-green-300"
                            >
                              <Edit2 size={14} />
                            </Button>
                          )}
                          {userRole === 'pharmacist' && bill.status !== 'paid' && (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                setSelectedBill(bill)
                                setPharmacyFeeAmount(bill.pharmacist_fees || 0)
                                setShowPharmacyFeeModal(true)
                              }}
                              className="text-purple-400 hover:text-purple-300"
                            >
                              <Edit2 size={14} />
                            </Button>
                          )}
                          {canProcessPayment && bill.status !== 'paid' && (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                setSelectedBill(bill)
                                setShowPaymentModal(true)
                              }}
                            >
                              <CreditCard size={14} />
                            </Button>
                          )}
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => downloadInvoicePDF(bill.id)}
                          >
                            <Download size={14} />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Create Bill Modal */}
      <Modal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        title="Create New Bill"
        size="md"
      >
        <div className="space-y-4">
          <div>
            <label className="text-sm font-semibold text-gray-300">Patient ID (UUID) *</label>
            <input
              type="text"
              value={newBill.patientId}
              onChange={(e) => setNewBill({ ...newBill, patientId: e.target.value })}
              placeholder="Enter patient UUID"
              className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white placeholder-gray-500"
            />
          </div>
          <div>
            <label className="text-sm font-semibold text-gray-300">Patient Name</label>
            <input
              type="text"
              value={newBill.patientName}
              onChange={(e) => setNewBill({ ...newBill, patientName: e.target.value })}
              placeholder="Patient full name"
              className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white placeholder-gray-500"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-sm font-semibold text-gray-300">Assigned Doctor</label>
              <input
                type="text"
                value={newBill.doctorName}
                onChange={(e) => setNewBill({ ...newBill, doctorName: e.target.value })}
                placeholder="Doctor name"
                className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white placeholder-gray-500"
              />
            </div>
            <div>
              <label className="text-sm font-semibold text-gray-300">Department</label>
              <input
                type="text"
                value={newBill.department}
                onChange={(e) => setNewBill({ ...newBill, department: e.target.value })}
                placeholder="e.g., Cardiology"
                className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white placeholder-gray-500"
              />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-sm font-semibold text-gray-300">Admitted Date</label>
              <input
                type="date"
                value={newBill.admittedDate}
                onChange={(e) => setNewBill({ ...newBill, admittedDate: e.target.value })}
                className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white"
              />
            </div>
            <div>
              <label className="text-sm font-semibold text-gray-300">Discharged Date</label>
              <input
                type="date"
                value={newBill.dischargedDate}
                onChange={(e) => setNewBill({ ...newBill, dischargedDate: e.target.value })}
                className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white"
              />
            </div>
          </div>

          {/* Fee Breakdown Sections - Scrollable */}
          <div className="border-t border-white/10 pt-4 mt-4">
            <h4 className="text-sm font-semibold text-white mb-3">Fee Breakdown</h4>
            <div className="grid grid-cols-3 gap-4 max-h-40 overflow-y-auto">
              {/* Doctor Fees - Editable by Receptionist */}
              <div className="bg-blue-500/10 border border-blue-500/20 rounded p-3">
                <label className="text-xs font-semibold text-blue-400">Doctor Fees</label>
                {userRole === 'receptionist' ? (
                  <input
                    type="number"
                    value={newBill.doctorFees}
                    onChange={(e) => setNewBill({ ...newBill, doctorFees: parseFloat(e.target.value) || 0 })}
                    className="w-full mt-1 px-2 py-1 bg-white/5 border border-white/10 rounded text-white text-sm"
                    placeholder="0.00"
                  />
                ) : (
                  <p className="text-white font-semibold mt-1">${newBill.doctorFees.toFixed(2)}</p>
                )}
                <p className="text-xs text-gray-500 mt-1">{userRole === 'receptionist' ? 'Editable' : 'Read-only'}</p>
              </div>

              {/* Lab Fees - Read Only */}
              <div className="bg-green-500/10 border border-green-500/20 rounded p-3">
                <label className="text-xs font-semibold text-green-400">Lab Test Fees</label>
                <p className="text-white font-semibold mt-1">${newBill.labFees.toFixed(2)}</p>
                <p className="text-xs text-gray-500 mt-1">Auto-calculated</p>
              </div>

              {/* Pharmacist Fees - Read Only */}
              <div className="bg-purple-500/10 border border-purple-500/20 rounded p-3">
                <label className="text-xs font-semibold text-purple-400">Pharmacy Fees</label>
                <p className="text-white font-semibold mt-1">${newBill.pharmacistFees.toFixed(2)}</p>
                <p className="text-xs text-gray-500 mt-1">Auto-calculated</p>
              </div>
            </div>

            {/* Total */}
            <div className="mt-3 p-3 bg-white/5 rounded flex justify-between items-center">
              <span className="text-gray-400">Total Amount:</span>
              <span className="text-xl font-bold text-green-400">
                ${(newBill.doctorFees + newBill.labFees + newBill.pharmacistFees).toFixed(2)}
              </span>
            </div>
          </div>

          <div className="flex gap-2 justify-end mt-6">
            <Button onClick={() => setShowCreateModal(false)} variant="ghost">Cancel</Button>
            <Button onClick={handleCreateBill} className="bg-blue-600 hover:bg-blue-700">Create Bill</Button>
          </div>
        </div>
      </Modal>

      {/* Bill Details Modal */}
      <Modal
        isOpen={showDetailModal}
        onClose={() => setShowDetailModal(false)}
        title={`Bill Details - ${selectedBill?.first_name || 'Unknown'} ${selectedBill?.last_name || ''}`}
        size="lg"
      >
        {selectedBill && (
          <div className="space-y-6">
            {/* Bill Summary Panel */}
            <div className="bg-white/5 border border-white/10 rounded-lg p-4">
              <h3 className="font-semibold text-white mb-4">Bill Summary</h3>
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <p className="text-gray-400">Patient Name</p>
                  <p className="text-white font-semibold">{selectedBill.first_name} {selectedBill.last_name}</p>
                </div>
                <div>
                  <p className="text-gray-400">Patient ID</p>
                  <p className="text-white font-semibold">{selectedBill.patient_id}</p>
                </div>
                <div>
                  <p className="text-gray-400">Assigned Doctor</p>
                  <p className="text-white font-semibold">{selectedBill.assigned_doctor || 'N/A'}</p>
                </div>
                <div>
                  <p className="text-gray-400">Department</p>
                  <p className="text-white font-semibold">{selectedBill.department || 'N/A'}</p>
                </div>
                <div>
                  <p className="text-gray-400">Admitted Date</p>
                  <p className="text-white font-semibold">{selectedBill.admitted_date || 'N/A'}</p>
                </div>
                <div>
                  <p className="text-gray-400">Discharged Date</p>
                  <p className="text-white font-semibold">{selectedBill.discharged_date || 'N/A'}</p>
                </div>
              </div>
            </div>

            {/* Fee Breakdown - 3 Scrollable Sections */}
            <div className="bg-white/5 border border-white/10 rounded-lg p-4">
              <h3 className="font-semibold text-white mb-4">Fee Breakdown</h3>
              <div className="grid grid-cols-3 gap-4">
                {/* Doctor Fees Section - Editable by Receptionist */}
                <div className="bg-blue-500/10 border border-blue-500/20 rounded p-3 max-h-40 overflow-y-auto">
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-xs font-semibold text-blue-400">Doctor Fees</span>
                    {userRole === 'receptionist' && selectedBill.status !== 'paid' && (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-blue-400 hover:text-blue-300 h-6 w-6 p-0"
                        onClick={() => {
                          setDoctorFeeAmount(selectedBill.doctor_fees || 0)
                          setShowDoctorFeeModal(true)
                        }}
                      >
                        <Edit2 size={12} />
                      </Button>
                    )}
                  </div>
                  <p className="text-2xl font-bold text-blue-400">${(selectedBill.doctor_fees || 0).toFixed(2)}</p>
                  <p className="text-xs text-gray-500 mt-1">
                    {userRole === 'receptionist' ? 'Click edit to update' : 'Consultation & procedures'}
                  </p>
                </div>

                {/* Lab Fees Section - Read Only (synced from Lab Tech) */}
                <div className="bg-green-500/10 border border-green-500/20 rounded p-3 max-h-40 overflow-y-auto">
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-xs font-semibold text-green-400">Lab Test Fees</span>
                    <span className="text-xs bg-gray-500/20 text-gray-400 px-2 py-0.5 rounded">Auto-synced</span>
                  </div>
                  <p className="text-2xl font-bold text-green-400">${(selectedBill.lab_fees || 0).toFixed(2)}</p>
                  <p className="text-xs text-gray-500 mt-1">Updated by Lab Technician</p>
                </div>

                {/* Pharmacist Fees Section - Read Only (synced from Pharmacist) */}
                <div className="bg-purple-500/10 border border-purple-500/20 rounded p-3 max-h-40 overflow-y-auto">
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-xs font-semibold text-purple-400">Pharmacy Fees</span>
                    <span className="text-xs bg-gray-500/20 text-gray-400 px-2 py-0.5 rounded">Auto-synced</span>
                  </div>
                  <p className="text-2xl font-bold text-purple-400">${(selectedBill.pharmacist_fees || 0).toFixed(2)}</p>
                  <p className="text-xs text-gray-500 mt-1">Updated by Pharmacist</p>
                </div>
              </div>

              {/* Total Amount Auto-Calculated */}
              <div className="mt-4 p-3 bg-white/10 rounded flex justify-between items-center">
                <span className="text-gray-300 font-semibold">Total Amount (Auto-calculated):</span>
                <span className="text-2xl font-bold text-green-400">
                  ${((selectedBill.doctor_fees || 0) + (selectedBill.lab_fees || 0) + (selectedBill.pharmacist_fees || 0)).toFixed(2)}
                </span>
              </div>
            </div>

            {/* Charge Items */}
            <div className="bg-white/5 border border-white/10 rounded-lg p-4">
              <h3 className="font-semibold text-white mb-4">Additional Charges</h3>
              {selectedBill.services && selectedBill.services.length > 0 ? (
                <div className="space-y-3 max-h-40 overflow-y-auto">
                  {selectedBill.services.map((service, idx) => (
                    <div key={idx} className="bg-black/30 rounded p-3 flex justify-between items-start">
                      <div className="flex-1">
                        <p className="text-white font-semibold text-sm">{service.service_name}</p>
                        <p className="text-gray-400 text-xs">{service.description}</p>
                        <p className="text-gray-500 text-xs mt-1">Qty: {service.quantity} × ${service.unit_price.toFixed(2)}</p>
                      </div>
                      <p className="text-green-400 font-semibold">${(service.quantity * service.unit_price).toFixed(2)}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-gray-400 text-sm">No additional charges</p>
              )}
            </div>

            {/* Payment Section */}
            {canViewFullBilling && (
              <div className="bg-white/5 border border-white/10 rounded-lg p-4">
                <h3 className="font-semibold text-white mb-4">Payment Details</h3>
                <div className="space-y-3 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Subtotal:</span>
                    <span className="text-white font-semibold">${(selectedBill.service_total || 0).toFixed(2)}</span>
                  </div>
                  {(discount > 0 || selectedBill.discount) && (
                    <div className="flex justify-between">
                      <span className="text-gray-400">Discount:</span>
                      <span className="text-orange-400">-${(selectedBill.discount || discount).toFixed(2)}</span>
                    </div>
                  )}
                  {(tax > 0 || selectedBill.tax) && (
                    <div className="flex justify-between">
                      <span className="text-gray-400">Tax:</span>
                      <span className="text-white">+${(selectedBill.tax || tax).toFixed(2)}</span>
                    </div>
                  )}
                  {(insuranceCoverage > 0 || selectedBill.insurance_coverage) && (
                    <div className="flex justify-between">
                      <span className="text-gray-400">Insurance Coverage:</span>
                      <span className="text-blue-400">-${(selectedBill.insurance_coverage || insuranceCoverage).toFixed(2)}</span>
                    </div>
                  )}
                  <div className="border-t border-white/10 pt-3 flex justify-between">
                    <span className="text-white font-semibold">Final Amount:</span>
                    <span className="text-green-400 font-bold text-lg">${(selectedBill.total_amount || 0).toFixed(2)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Amount Paid:</span>
                    <span className="text-blue-400 font-semibold">${(selectedBill.amount_paid || 0).toFixed(2)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Pending:</span>
                    <span className="text-red-400 font-semibold">${Math.max(0, (selectedBill.total_amount || 0) - (selectedBill.amount_paid || 0)).toFixed(2)}</span>
                  </div>
                  {selectedBill.payment_method && (
                    <div className="flex justify-between">
                      <span className="text-gray-400">Payment Method:</span>
                      <span className="text-white font-semibold">{selectedBill.payment_method.toUpperCase()}</span>
                    </div>
                  )}
                </div>
              </div>
            )}

            <div className="flex gap-2 justify-end">
              <Button onClick={() => setShowDetailModal(false)} variant="ghost">Close</Button>
              {canProcessPayment && selectedBill.status !== 'paid' && (
                <Button 
                  onClick={() => {
                    setShowDetailModal(false)
                    setShowPaymentModal(true)
                  }} 
                  className="bg-green-600 hover:bg-green-700"
                >
                  <CreditCard size={16} className="mr-2" />
                  Process Payment
                </Button>
              )}
            </div>
          </div>
        )}
      </Modal>

      {/* Add Charge Modal */}
      <Modal
        isOpen={showAddChargeModal}
        onClose={() => setShowAddChargeModal(false)}
        title={userRole === 'lab_technician' ? 'Add Lab Test Fee' : 'Add Charge to Bill'}
        size="md"
      >
        <div className="space-y-4">
          {userRole === 'lab_technician' && (
            <div className="bg-green-500/10 border border-green-500/30 rounded p-3 mb-4">
              <p className="text-sm text-green-400">🧪 Lab Technician: You can only add lab test fees</p>
            </div>
          )}
          <div>
            <label className="text-sm font-semibold text-gray-300">Service Name *</label>
            <select
              value={newCharge.serviceName}
              onChange={(e) => setNewCharge({ ...newCharge, serviceName: e.target.value })}
              className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white"
            >
              <option value="">Select a service</option>
              {userRole === 'lab_technician' ? (
                <>
                  <option value="Lab Test - Blood Work">Lab Test - Blood Work</option>
                  <option value="Lab Test - Urine Analysis">Lab Test - Urine Analysis</option>
                  <option value="Lab Test - CBC">Lab Test - Complete Blood Count (CBC)</option>
                  <option value="Lab Test - Lipid Panel">Lab Test - Lipid Panel</option>
                  <option value="Lab Test - Thyroid Panel">Lab Test - Thyroid Panel</option>
                  <option value="Lab Test - Liver Function">Lab Test - Liver Function</option>
                  <option value="Lab Test - Kidney Function">Lab Test - Kidney Function</option>
                  <option value="Lab Test - Glucose">Lab Test - Glucose Test</option>
                  <option value="Lab Test - Other">Lab Test - Other</option>
                </>
              ) : (
                <>
                  <option value="Consultation Fee">Consultation Fee</option>
                  <option value="Lab Test">Lab Test</option>
                  <option value="CT Scan">CT Scan</option>
                  <option value="X-ray">X-ray</option>
                  <option value="MRI">MRI</option>
                  <option value="Bed Charge">Bed Charge</option>
                  <option value="Procedure">Procedure/Surgery</option>
                  <option value="Medication">Medication Cost</option>
                  <option value="Consumables">Consumables</option>
                  <option value="Emergency">Emergency Charge</option>
                  <option value="Nursing">Nursing Fee</option>
                  <option value="Other">Other Service</option>
                </>
              )}
            </select>
          </div>
          <div>
            <label className="text-sm font-semibold text-gray-300">Description</label>
            <input
              type="text"
              value={newCharge.description}
              onChange={(e) => setNewCharge({ ...newCharge, description: e.target.value })}
              placeholder="Additional details (optional)"
              className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white placeholder-gray-500"
            />
          </div>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="text-sm font-semibold text-gray-300">Quantity *</label>
              <input
                type="number"
                value={newCharge.quantity}
                onChange={(e) => setNewCharge({ ...newCharge, quantity: parseInt(e.target.value) || 1 })}
                min="1"
                className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white"
              />
            </div>
            <div>
              <label className="text-sm font-semibold text-gray-300">Unit Price *</label>
              <input
                type="number"
                value={newCharge.unitPrice}
                onChange={(e) => setNewCharge({ ...newCharge, unitPrice: parseFloat(e.target.value) || 0 })}
                placeholder="0.00"
                className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white"
              />
            </div>
            <div>
              <label className="text-sm font-semibold text-gray-300">Total</label>
              <div className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-green-400 font-semibold">
                ${(newCharge.quantity * newCharge.unitPrice).toFixed(2)}
              </div>
            </div>
          </div>
          <div>
            <label className="text-sm font-semibold text-gray-300">Date of Service</label>
            <input
              type="date"
              value={newCharge.dateOfService}
              onChange={(e) => setNewCharge({ ...newCharge, dateOfService: e.target.value })}
              className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white"
            />
          </div>
          <div className="flex gap-2 justify-end mt-6">
            <Button onClick={() => setShowAddChargeModal(false)} variant="ghost">Cancel</Button>
            <Button onClick={handleAddCharge} className="bg-blue-600 hover:bg-blue-700">Add Charge</Button>
          </div>
        </div>
      </Modal>

      {/* Payment Modal */}
      <Modal
        isOpen={showPaymentModal}
        onClose={() => setShowPaymentModal(false)}
        title={`Process Payment - ${selectedBill?.first_name || 'Unknown'} ${selectedBill?.last_name || ''}`}
        size="md"
      >
        <div className="space-y-4">
          {selectedBill && (
            <>
              <div className="bg-blue-500/10 border border-blue-500/20 rounded p-4">
                <p className="text-sm text-gray-400">Bill Amount</p>
                <p className="text-3xl font-bold text-blue-400">${(selectedBill.total_amount || 0).toFixed(2)}</p>
                <p className="text-xs text-gray-500 mt-2">Paid: ${(selectedBill.amount_paid || 0).toFixed(2)} | Pending: ${Math.max(0, (selectedBill.total_amount || 0) - (selectedBill.amount_paid || 0)).toFixed(2)}</p>
              </div>

              <div>
                <label className="text-sm font-semibold text-gray-300">Payment Amount *</label>
                <input
                  type="number"
                  value={payment.amount}
                  onChange={(e) => setPayment({ ...payment, amount: parseFloat(e.target.value) || 0 })}
                  placeholder="0.00"
                  min="0"
                  max={(selectedBill.total_amount || 0) - (selectedBill.amount_paid || 0)}
                  className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white placeholder-gray-500"
                />
              </div>

              <div>
                <label className="text-sm font-semibold text-gray-300">Payment Method *</label>
                <select
                  value={payment.method}
                  onChange={(e) => setPayment({ ...payment, method: e.target.value })}
                  className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white"
                >
                  <option value="cash">Cash</option>
                  <option value="card">Credit/Debit Card</option>
                  <option value="upi">UPI</option>
                  <option value="insurance">Insurance</option>
                </select>
              </div>

              {canApplyDiscount && (
                <div>
                  <label className="text-sm font-semibold text-gray-300">Discount Reason (Encrypted)</label>
                  <input
                    type="text"
                    value={payment.discountReason}
                    onChange={(e) => setPayment({ ...payment, discountReason: e.target.value })}
                    placeholder="e.g., Senior citizen, Insurance negotiation"
                    className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white placeholder-gray-500"
                  />
                  <p className="text-xs text-gray-500 mt-1">🔒 This field will be encrypted for security</p>
                </div>
              )}

              {payment.method === 'insurance' && (
                <div>
                  <label className="text-sm font-semibold text-gray-300">Insurance Details (Encrypted)</label>
                  <textarea
                    value={payment.insuranceDetails}
                    onChange={(e) => setPayment({ ...payment, insuranceDetails: e.target.value })}
                    placeholder='e.g., {"provider": "XYZ Insurance", "policy_id": "POL123", "coverage_percent": 80}'
                    className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white placeholder-gray-500 font-mono text-xs"
                    rows={3}
                  />
                  <p className="text-xs text-gray-500 mt-1">🔒 This field will be encrypted for security</p>
                </div>
              )}

              {canApplyDiscount && (
                <div>
                  <label className="text-sm font-semibold text-gray-300">Discount Reason (Optional)</label>
                  <input
                    type="text"
                    value={payment.discountReason}
                    onChange={(e) => setPayment({ ...payment, discountReason: e.target.value })}
                    placeholder="Reason for discount if any"
                    className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white placeholder-gray-500"
                  />
                </div>
              )}

              {payment.method === 'insurance' && (
                <div>
                  <label className="text-sm font-semibold text-gray-300">Insurance Details (Optional)</label>
                  <textarea
                    value={payment.insuranceDetails}
                    onChange={(e) => setPayment({ ...payment, insuranceDetails: e.target.value })}
                    placeholder='{"provider":"Name","policyNumber":"12345","amountCovered":"1000"}'
                    className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white placeholder-gray-500 text-xs"
                    rows={2}
                  />
                </div>
              )}

              <div>
                <label className="text-sm font-semibold text-gray-300">Notes (Optional)</label>
                <textarea
                  value={payment.notes}
                  onChange={(e) => setPayment({ ...payment, notes: e.target.value })}
                  placeholder="Any additional notes"
                  className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white placeholder-gray-500"
                  rows={2}
                />
              </div>

              {payment.amount > ((selectedBill.total_amount || 0) - (selectedBill.amount_paid || 0)) && (
                <div className="bg-yellow-500/10 border border-yellow-500/20 rounded p-3 flex gap-2">
                  <AlertCircle size={16} className="text-yellow-400 flex-shrink-0 mt-0.5" />
                  <p className="text-xs text-yellow-300">Payment exceeds pending amount by ${(payment.amount - ((selectedBill.total_amount || 0) - (selectedBill.amount_paid || 0))).toFixed(2)}</p>
                </div>
              )}

              <div className="flex gap-2 justify-end mt-6">
                <Button onClick={() => setShowPaymentModal(false)} variant="ghost">Cancel</Button>
                <Button onClick={handlePayment} className="bg-green-600 hover:bg-green-700">Process Payment</Button>
              </div>
            </>
          )}
        </div>
      </Modal>

      {/* Lab Fee Modal - Lab Technician Only */}
      <Modal
        isOpen={showLabFeeModal}
        onClose={() => setShowLabFeeModal(false)}
        title="Update Lab Test Fees"
        size="md"
      >
        <div className="space-y-4">
          <div className="bg-green-500/10 border border-green-500/30 rounded p-4">
            <div className="flex gap-2">
              <DollarSign size={20} className="text-green-400 flex-shrink-0" />
              <div>
                <h4 className="font-semibold text-white text-sm">Patient: {selectedBill?.first_name} {selectedBill?.last_name}</h4>
                <p className="text-xs text-gray-400 mt-1">Bill ID: {selectedBill?.id?.slice(0, 8)}...</p>
                <p className="text-xs text-gray-400">Current Lab Fees: ${(selectedBill?.lab_fees || 0).toFixed(2)}</p>
              </div>
            </div>
          </div>

          <div>
            <label className="text-sm font-semibold text-gray-300">Lab Test Fee Amount ($) *</label>
            <input
              type="number"
              value={labFeeAmount}
              onChange={(e) => setLabFeeAmount(parseFloat(e.target.value) || 0)}
              placeholder="Enter lab test fee"
              min="0"
              step="0.01"
              className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white placeholder-gray-500"
            />
            <p className="text-xs text-gray-500 mt-1">This fee will be added to the patient's bill and reflected in the receptionist's billing view.</p>
          </div>

          <div className="bg-blue-500/10 border border-blue-500/20 rounded p-3">
            <p className="text-xs text-blue-300">
              <strong>Note:</strong> Lab fees are automatically synced with the receptionist's billing system.
              The total bill amount will be updated accordingly.
            </p>
          </div>

          <div className="flex gap-2 justify-end mt-6">
            <Button onClick={() => setShowLabFeeModal(false)} variant="ghost">Cancel</Button>
            <Button onClick={handleUpdateLabFees} className="bg-green-600 hover:bg-green-700">Update Lab Fees</Button>
          </div>
        </div>
      </Modal>

      {/* Pharmacy Fee Modal - Pharmacist Only */}
      <Modal
        isOpen={showPharmacyFeeModal}
        onClose={() => setShowPharmacyFeeModal(false)}
        title="Update Pharmacy Fees"
        size="md"
      >
        <div className="space-y-4">
          <div className="bg-purple-500/10 border border-purple-500/30 rounded p-4">
            <div className="flex gap-2">
              <DollarSign size={20} className="text-purple-400 flex-shrink-0" />
              <div>
                <h4 className="font-semibold text-white text-sm">Patient: {selectedBill?.first_name} {selectedBill?.last_name}</h4>
                <p className="text-xs text-gray-400 mt-1">Bill ID: {selectedBill?.id?.slice(0, 8)}...</p>
                <p className="text-xs text-gray-400">Current Pharmacy Fees: ${(selectedBill?.pharmacist_fees || 0).toFixed(2)}</p>
              </div>
            </div>
          </div>

          <div>
            <label className="text-sm font-semibold text-gray-300">Pharmacy/Prescription Fee Amount ($) *</label>
            <input
              type="number"
              value={pharmacyFeeAmount}
              onChange={(e) => setPharmacyFeeAmount(parseFloat(e.target.value) || 0)}
              placeholder="Enter pharmacy fee"
              min="0"
              step="0.01"
              className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white placeholder-gray-500"
            />
            <p className="text-xs text-gray-500 mt-1">This fee will be added to the patient's bill for filled prescriptions.</p>
          </div>

          <div className="bg-blue-500/10 border border-blue-500/20 rounded p-3">
            <p className="text-xs text-blue-300">
              <strong>Note:</strong> Pharmacy fees are automatically synced with the receptionist's billing system.
              The total bill amount will be updated accordingly.
            </p>
          </div>

          <div className="flex gap-2 justify-end mt-6">
            <Button onClick={() => setShowPharmacyFeeModal(false)} variant="ghost">Cancel</Button>
            <Button onClick={handleUpdatePharmacyFees} className="bg-purple-600 hover:bg-purple-700">Update Pharmacy Fees</Button>
          </div>
        </div>
      </Modal>

      {/* Doctor Fee Modal - Receptionist Only */}
      <Modal
        isOpen={showDoctorFeeModal}
        onClose={() => setShowDoctorFeeModal(false)}
        title="Update Doctor Fees"
        size="md"
      >
        <div className="space-y-4">
          <div className="bg-blue-500/10 border border-blue-500/30 rounded p-4">
            <div className="flex gap-2">
              <DollarSign size={20} className="text-blue-400 flex-shrink-0" />
              <div>
                <h4 className="font-semibold text-white text-sm">Patient: {selectedBill?.first_name} {selectedBill?.last_name}</h4>
                <p className="text-xs text-gray-400 mt-1">Bill ID: {selectedBill?.id?.slice(0, 8)}...</p>
                <p className="text-xs text-gray-400">Current Doctor Fees: ${(selectedBill?.doctor_fees || 0).toFixed(2)}</p>
              </div>
            </div>
          </div>

          <div>
            <label className="text-sm font-semibold text-gray-300">Doctor Fee Amount ($) *</label>
            <input
              type="number"
              value={doctorFeeAmount}
              onChange={(e) => setDoctorFeeAmount(parseFloat(e.target.value) || 0)}
              placeholder="Enter doctor fee"
              min="0"
              step="0.01"
              className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white placeholder-gray-500"
            />
            <p className="text-xs text-gray-500 mt-1">This fee includes consultation and procedure charges.</p>
          </div>

          <div className="bg-yellow-500/10 border border-yellow-500/20 rounded p-3">
            <p className="text-xs text-yellow-300">
              <strong>Note:</strong> Only receptionist can edit doctor fees.
              Lab Test Fees and Pharmacy Fees are automatically synced from their respective modules.
            </p>
          </div>

          <div className="flex gap-2 justify-end mt-6">
            <Button onClick={() => setShowDoctorFeeModal(false)} variant="ghost">Cancel</Button>
            <Button onClick={handleUpdateDoctorFees} className="bg-blue-600 hover:bg-blue-700">Update Doctor Fees</Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}

export default BillingNew

import React, { useState, useEffect } from 'react'
import { Plus, DollarSign, Printer, Eye, CreditCard, AlertCircle } from 'lucide-react'
import Card from './Card'
import Button from './Button'
import Modal from './Modal'

interface BillingService {
  id: string
  description: string
  quantity: number
  unit_price: number
  total: number
}

interface Bill {
  id: string
  patient_id: string
  first_name: string
  last_name: string
  total_amount: number
  discount_amount: number
  final_amount: number
  status: 'pending' | 'partial' | 'paid' | 'overdue'
  payment_date?: string
  services?: BillingService[]
  created_at: string
}

interface BillingProps {
  userEmail: string
  userName: string
  userRole: string
  hasViewPermission: boolean
}

const Billing: React.FC<BillingProps> = ({
  userEmail,
  userName,
  userRole,
  hasViewPermission
}) => {
  const [bills, setBills] = useState<Bill[]>([])
  const [loading, setLoading] = useState(true)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [showServiceModal, setShowServiceModal] = useState(false)
  const [showPaymentModal, setShowPaymentModal] = useState(false)
  const [selectedBill, setSelectedBill] = useState<Bill | null>(null)
  const [newBill, setNewBill] = useState({ patientId: '', totalAmount: 0 })
  const [service, setService] = useState({ description: '', quantity: 1, unitPrice: 0 })
  const [discount, setDiscount] = useState(0)
  const [paymentAmount, setPaymentAmount] = useState(0)

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

  const handleCreateBill = async () => {
    if (!newBill.patientId || newBill.totalAmount <= 0) {
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
          total_amount: newBill.totalAmount,
          discount_amount: discount
        })
      })

      if (response.ok) {
        const data = await response.json()
        setBills([data.data, ...bills])
        setShowCreateModal(false)
        setNewBill({ patientId: '', totalAmount: 0 })
        setDiscount(0)
        alert('Bill created successfully!')
      }
    } catch (error) {
      alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  const handleAddService = async () => {
    if (!service.description || service.quantity <= 0 || service.unitPrice <= 0) {
      alert('Please fill in all fields')
      return
    }

    if (!selectedBill) return

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
          description: service.description,
          quantity: service.quantity,
          unit_price: service.unitPrice
        })
      })

      if (response.ok) {
        await loadBills()
        setShowServiceModal(false)
        setService({ description: '', quantity: 1, unitPrice: 0 })
        alert('Service added successfully!')
      }
    } catch (error) {
      alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  const handlePayment = async () => {
    if (!selectedBill || paymentAmount <= 0) {
      alert('Please enter payment amount')
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
          payment_amount: paymentAmount
        })
      })

      if (response.ok) {
        await loadBills()
        setShowPaymentModal(false)
        setPaymentAmount(0)
        setSelectedBill(null)
        alert('Payment processed successfully!')
      }
    } catch (error) {
      alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  const canCreateBills = ['admin', 'accountant'].includes(userRole)

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

  const totalBillAmount = bills.reduce((sum, bill) => sum + bill.final_amount, 0)
  const pendingAmount = bills
    .filter(b => b.status !== 'paid')
    .reduce((sum, bill) => sum + bill.final_amount, 0)

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold text-white">Billing & Invoices</h2>
        {canCreateBills && (
          <Button
            onClick={() => setShowCreateModal(true)}
            className="bg-green-600 hover:bg-green-700 text-white gap-2"
          >
            <Plus size={18} />
            Create Bill
          </Button>
        )}
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="border-l-4 border-green-500">
          <p className="text-gray-400 text-sm">Total Billed</p>
          <p className="text-3xl font-bold text-green-400">${totalBillAmount.toFixed(2)}</p>
        </Card>
        <Card className="border-l-4 border-red-500">
          <p className="text-gray-400 text-sm">Pending Payment</p>
          <p className="text-3xl font-bold text-red-400">${pendingAmount.toFixed(2)}</p>
        </Card>
        <Card className="border-l-4 border-blue-500">
          <p className="text-gray-400 text-sm">Total Bills</p>
          <p className="text-3xl font-bold text-blue-400">{bills.length}</p>
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
                  <th className="px-6 py-3 text-left font-semibold">Patient</th>
                  <th className="px-6 py-3 text-left font-semibold">Amount</th>
                  <th className="px-6 py-3 text-left font-semibold">Discount</th>
                  <th className="px-6 py-3 text-left font-semibold">Final</th>
                  <th className="px-6 py-3 text-left font-semibold">Status</th>
                  <th className="px-6 py-3 text-left font-semibold">Date</th>
                  <th className="px-6 py-3 text-left font-semibold">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/6">
                {bills.map(bill => (
                  <tr key={bill.id} className="hover:bg-white/2">
                    <td className="px-6 py-4">{bill.first_name} {bill.last_name}</td>
                    <td className="px-6 py-4">${bill.total_amount.toFixed(2)}</td>
                    <td className="px-6 py-4 text-orange-400">${bill.discount_amount.toFixed(2)}</td>
                    <td className="px-6 py-4 font-semibold">${bill.final_amount.toFixed(2)}</td>
                    <td className="px-6 py-4">
                      <span className={`px-3 py-1 rounded-full text-xs font-semibold ${getStatusColor(bill.status)}`}>
                        {bill.status.charAt(0).toUpperCase() + bill.status.slice(1)}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-gray-400 text-xs">{new Date(bill.created_at).toLocaleDateString()}</td>
                    <td className="px-6 py-4">
                      <div className="flex gap-2">
                        {canCreateBills && (
                          <>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                setSelectedBill(bill)
                                setShowServiceModal(true)
                              }}
                              className="gap-1"
                            >
                              <Plus size={14} />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                setSelectedBill(bill)
                                setShowPaymentModal(true)
                              }}
                              className="gap-1"
                            >
                              <CreditCard size={14} />
                            </Button>
                          </>
                        )}
                        {bill.status !== 'paid' && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setSelectedBill(bill)
                              setShowPaymentModal(true)
                            }}
                            className="gap-1"
                          >
                            <DollarSign size={14} />
                            Pay
                          </Button>
                        )}
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => alert('Invoice PDF would be generated')}
                          className="gap-1"
                        >
                          <Printer size={14} />
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
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
            <label className="text-sm font-semibold text-gray-300">Patient ID (UUID)</label>
            <input
              type="text"
              value={newBill.patientId}
              onChange={(e) => setNewBill({ ...newBill, patientId: e.target.value })}
              placeholder="Enter patient UUID"
              className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white placeholder-gray-500"
            />
          </div>
          <div>
            <label className="text-sm font-semibold text-gray-300">Total Amount</label>
            <input
              type="number"
              value={newBill.totalAmount}
              onChange={(e) => setNewBill({ ...newBill, totalAmount: parseFloat(e.target.value) || 0 })}
              placeholder="0.00"
              className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white placeholder-gray-500"
            />
          </div>
          <div>
            <label className="text-sm font-semibold text-gray-300">Discount Amount</label>
            <input
              type="number"
              value={discount}
              onChange={(e) => setDiscount(parseFloat(e.target.value) || 0)}
              placeholder="0.00"
              className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white placeholder-gray-500"
            />
          </div>
          <div className="bg-white/5 border border-white/10 rounded p-3">
            <p className="text-sm text-gray-400">Final Amount: <span className="text-green-400 font-semibold">${(newBill.totalAmount - discount).toFixed(2)}</span></p>
          </div>
          <div className="flex gap-2 justify-end mt-6">
            <Button onClick={() => setShowCreateModal(false)} variant="ghost">Cancel</Button>
            <Button onClick={handleCreateBill} className="bg-green-600 hover:bg-green-700">Create Bill</Button>
          </div>
        </div>
      </Modal>

      {/* Add Service Modal */}
      <Modal
        isOpen={showServiceModal}
        onClose={() => setShowServiceModal(false)}
        title={`Add Service to Bill`}
        size="md"
      >
        <div className="space-y-4">
          <div>
            <label className="text-sm font-semibold text-gray-300">Service Description</label>
            <input
              type="text"
              value={service.description}
              onChange={(e) => setService({ ...service, description: e.target.value })}
              placeholder="e.g., Consultation, Lab Test"
              className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white placeholder-gray-500"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-sm font-semibold text-gray-300">Quantity</label>
              <input
                type="number"
                value={service.quantity}
                onChange={(e) => setService({ ...service, quantity: parseInt(e.target.value) || 1 })}
                className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white"
              />
            </div>
            <div>
              <label className="text-sm font-semibold text-gray-300">Unit Price</label>
              <input
                type="number"
                value={service.unitPrice}
                onChange={(e) => setService({ ...service, unitPrice: parseFloat(e.target.value) || 0 })}
                placeholder="0.00"
                className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white"
              />
            </div>
          </div>
          <div className="bg-white/5 border border-white/10 rounded p-3">
            <p className="text-sm text-gray-400">Total: <span className="text-green-400 font-semibold">${(service.quantity * service.unitPrice).toFixed(2)}</span></p>
          </div>
          <div className="flex gap-2 justify-end mt-6">
            <Button onClick={() => setShowServiceModal(false)} variant="ghost">Cancel</Button>
            <Button onClick={handleAddService} className="bg-blue-600 hover:bg-blue-700">Add Service</Button>
          </div>
        </div>
      </Modal>

      {/* Payment Modal */}
      <Modal
        isOpen={showPaymentModal}
        onClose={() => setShowPaymentModal(false)}
        title={`Process Payment - ${selectedBill?.first_name} ${selectedBill?.last_name}`}
        size="md"
      >
        <div className="space-y-4">
          <div className="bg-blue-500/10 border border-blue-500/20 rounded p-4">
            <p className="text-sm text-gray-400">Bill Amount</p>
            <p className="text-2xl font-bold text-blue-400">${selectedBill?.final_amount.toFixed(2)}</p>
          </div>
          <div>
            <label className="text-sm font-semibold text-gray-300">Payment Amount</label>
            <input
              type="number"
              value={paymentAmount}
              onChange={(e) => setPaymentAmount(parseFloat(e.target.value) || 0)}
              placeholder="0.00"
              className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white placeholder-gray-500"
            />
          </div>
          {paymentAmount > (selectedBill?.final_amount || 0) && (
            <div className="bg-yellow-500/10 border border-yellow-500/20 rounded p-3 flex gap-2">
              <AlertCircle size={16} className="text-yellow-400 flex-shrink-0" />
              <p className="text-xs text-yellow-300">Payment exceeds bill amount by ${(paymentAmount - (selectedBill?.final_amount || 0)).toFixed(2)}</p>
            </div>
          )}
          <div className="flex gap-2 justify-end mt-6">
            <Button onClick={() => setShowPaymentModal(false)} variant="ghost">Cancel</Button>
            <Button onClick={handlePayment} className="bg-green-600 hover:bg-green-700">Process Payment</Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}

export default Billing

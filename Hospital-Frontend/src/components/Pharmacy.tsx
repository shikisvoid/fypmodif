import React, { useState, useEffect } from 'react'
import { Plus, Edit, AlertTriangle, Pill, Package } from 'lucide-react'
import Card from './Card'
import Button from './Button'
import Modal from './Modal'

interface Medication {
  id: string
  medicine_name: string
  generic_name?: string
  manufacturer?: string
  quantity_in_stock: number
  reorder_level: number
  unit_price: number
  expiry_date?: string
  batch_number?: string
  alert_threshold: number
  low_stock?: boolean
  last_updated?: string
}

interface Prescription {
  id: string
  patient_id: string
  first_name: string
  last_name: string
  medicines: Array<{
    medicine: string
    dosage: string
    frequency: string
    duration: string
  }>
  status: 'active' | 'inactive' | 'expired'
  filled_date?: string
  created_at: string
}

interface PharmacyProps {
  userEmail: string
  userName: string
  userRole: string
  hasViewPermission: boolean
}

const Pharmacy: React.FC<PharmacyProps> = ({
  userEmail,
  userName,
  userRole,
  hasViewPermission
}) => {
  const [medications, setMedications] = useState<Medication[]>([])
  const [prescriptions, setPrescriptions] = useState<Prescription[]>([])
  const [activeTab, setActiveTab] = useState<'inventory' | 'prescriptions'>('inventory')
  const [loading, setLoading] = useState(true)
  const [showAddModal, setShowAddModal] = useState(false)
  const [showEditModal, setShowEditModal] = useState(false)
  const [selectedMedication, setSelectedMedication] = useState<Medication | null>(null)
  const [newMedication, setNewMedication] = useState({
    medicineName: '',
    genericName: '',
    manufacturer: '',
    stockQuantity: 0,
    reorderLevel: 10,
    unitPrice: 0,
    alertThreshold: 20,
    expiryDate: ''
  })
  const [dashboardStats, setDashboardStats] = useState({
    pendingPrescriptions: 0,
    dispensedToday: 0,
    lowStockItems: 0,
    expiringSoon: 0
  })
  const [editedMedication, setEditedMedication] = useState({
    stockQuantity: 0,
    unitPrice: 0
  })

  useEffect(() => {
    loadData()
  }, [activeTab, userRole])

  const loadData = async () => {
    try {
      setLoading(true)
      const token = localStorage.getItem('hp_access_token')
      if (!token) {
        setLoading(false)
        return
      }

      // Load dashboard stats
      const dashRes = await fetch('/api/pharmacy/dashboard', {
        headers: { 'Authorization': `Bearer ${token}` }
      })
      if (dashRes.ok) {
        const dashData = await dashRes.json()
        if (dashData.success) {
          setDashboardStats(dashData.stats)
        }
      }

      if (activeTab === 'inventory') {
        // Load real inventory from backend
        const invRes = await fetch('/api/pharmacy/inventory', {
          headers: { 'Authorization': `Bearer ${token}` }
        })
        if (invRes.ok) {
          const invData = await invRes.json()
          setMedications(invData.inventory || [])
        }
      } else {
        const response = await fetch('/api/prescriptions', {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        })

        if (response.ok) {
          const data = await response.json()
          setPrescriptions(data.data || [])
        }
      }
    } catch (error) {
      console.error('Failed to load data:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleAddMedication = async () => {
    if (!newMedication.medicineName || newMedication.stockQuantity < 0 || newMedication.unitPrice < 0) {
      alert('Please fill in required fields')
      return
    }

    // Check stock threshold alert
    if (newMedication.stockQuantity <= newMedication.alertThreshold) {
      const proceed = window.confirm(`⚠️ LOW STOCK ALERT: Stock quantity (${newMedication.stockQuantity}) is at or below the alert threshold (${newMedication.alertThreshold}). Continue adding?`)
      if (!proceed) return
    }

    try {
      const token = localStorage.getItem('hp_access_token')
      if (!token) return

      // Call real backend API
      const response = await fetch('/api/pharmacy/inventory', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          medicine_name: newMedication.medicineName,
          quantity_in_stock: newMedication.stockQuantity,
          reorder_level: newMedication.reorderLevel,
          unit_price: newMedication.unitPrice,
          alert_threshold: newMedication.alertThreshold,
          expiry_date: newMedication.expiryDate || null
        })
      })

      if (response.ok) {
        await loadData()
        setShowAddModal(false)
        setNewMedication({
          medicineName: '',
          genericName: '',
          manufacturer: '',
          stockQuantity: 0,
          reorderLevel: 10,
          unitPrice: 0,
          alertThreshold: 20,
          expiryDate: ''
        })
        alert('Medication added successfully!')
      } else {
        const err = await response.json()
        alert(`Error: ${err.error || 'Failed to add medication'}`)
      }
    } catch (error) {
      alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  const handleEditMedication = async () => {
    if (!selectedMedication) return

    try {
      const token = localStorage.getItem('hp_access_token')
      if (!token) return

      // Call real backend API
      const response = await fetch(`/api/pharmacy/inventory/${selectedMedication.id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          quantity_in_stock: editedMedication.stockQuantity,
          unit_price: editedMedication.unitPrice
        })
      })

      if (response.ok) {
        await loadData()
        setShowEditModal(false)
        setSelectedMedication(null)
        alert('Medication updated successfully!')
      } else {
        const err = await response.json()
        alert(`Error: ${err.error || 'Failed to update medication'}`)
      }
    } catch (error) {
      alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  const handleFillPrescription = async (prescription: Prescription) => {
    try {
      const token = localStorage.getItem('hp_access_token')
      if (!token) return

      // Use dispense endpoint for pharmacist
      const response = await fetch(`/api/prescriptions/${prescription.id}/dispense`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          pharmacist_fees: 50 // Default dispensing fee
        })
      })

      if (response.ok) {
        await loadData()
        alert('Prescription dispensed successfully!')
      } else {
        const err = await response.json()
        alert(`Error: ${err.error || 'Failed to dispense prescription'}`)
      }
    } catch (error) {
      alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  const canManageInventory = ['pharmacist', 'admin'].includes(userRole)
  const lowStockMeds = medications.filter(m => m.quantity_in_stock <= m.alert_threshold)
  const totalInventoryValue = medications.reduce((sum, med) => sum + (med.quantity_in_stock * med.unit_price), 0)

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold text-white">Pharmacy Management</h2>
        {canManageInventory && activeTab === 'inventory' && (
          <Button
            onClick={() => setShowAddModal(true)}
            className="bg-blue-600 hover:bg-blue-700 text-white gap-2"
          >
            <Plus size={18} />
            Add Medication
          </Button>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-white/10">
        <button
          onClick={() => {
            setActiveTab('inventory')
            loadData()
          }}
          className={`px-6 py-3 font-semibold text-sm border-b-2 transition ${
            activeTab === 'inventory'
              ? 'border-blue-600 text-blue-400'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          <Package size={16} className="inline mr-2" />
          Inventory
        </button>
        <button
          onClick={() => {
            setActiveTab('prescriptions')
            loadData()
          }}
          className={`px-6 py-3 font-semibold text-sm border-b-2 transition ${
            activeTab === 'prescriptions'
              ? 'border-blue-600 text-blue-400'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          <Pill size={16} className="inline mr-2" />
          Prescriptions
        </button>
      </div>

      {/* Dashboard Stats - Dynamic from Backend */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="border-l-4 border-blue-500">
          <p className="text-gray-400 text-sm">Pending Prescriptions</p>
          <p className="text-3xl font-bold text-blue-400">{dashboardStats.pendingPrescriptions}</p>
          <p className="text-xs text-yellow-400 mt-1">To dispense</p>
        </Card>
        <Card className="border-l-4 border-green-500">
          <p className="text-gray-400 text-sm">Dispensed Today</p>
          <p className="text-3xl font-bold text-green-400">{dashboardStats.dispensedToday}</p>
          <p className="text-xs text-green-400 mt-1">Completed</p>
        </Card>
        <Card className="border-l-4 border-orange-500">
          <p className="text-gray-400 text-sm">Low Stock Items</p>
          <p className="text-3xl font-bold text-orange-400">{dashboardStats.lowStockItems}</p>
          <p className="text-xs text-orange-400 mt-1">Reorder needed</p>
        </Card>
        <Card className="border-l-4 border-red-500">
          <p className="text-gray-400 text-sm">Expiring Soon</p>
          <p className="text-3xl font-bold text-red-400">{dashboardStats.expiringSoon}</p>
          <p className="text-xs text-red-400 mt-1">Within 30 days</p>
        </Card>
      </div>

      {/* Inventory Tab */}
      {activeTab === 'inventory' && (
        <>
          {/* Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card className="border-l-4 border-blue-500">
              <p className="text-gray-400 text-sm">Total Medications</p>
              <p className="text-3xl font-bold text-blue-400">{medications.length}</p>
            </Card>
            <Card className="border-l-4 border-red-500">
              <p className="text-gray-400 text-sm">Low Stock Items</p>
              <p className="text-3xl font-bold text-red-400">{lowStockMeds.length}</p>
            </Card>
            <Card className="border-l-4 border-green-500">
              <p className="text-gray-400 text-sm">Inventory Value</p>
              <p className="text-3xl font-bold text-green-400">${totalInventoryValue.toFixed(2)}</p>
            </Card>
          </div>

          {/* Low Stock Alert */}
          {lowStockMeds.length > 0 && (
            <div className="bg-red-500/10 border border-red-500/20 rounded p-4 flex gap-3">
              <AlertTriangle size={20} className="text-red-400 flex-shrink-0" />
              <div>
                <p className="font-semibold text-red-400">Low Stock Alert</p>
                <p className="text-sm text-red-300 mt-1">
                  {lowStockMeds.map(m => m.medicine_name).join(', ')} need reordering
                </p>
              </div>
            </div>
          )}

          {/* Medications Table */}
          <Card>
            {loading ? (
              <p className="text-gray-400">Loading medications...</p>
            ) : medications.length === 0 ? (
              <p className="text-gray-400">No medications in inventory</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-white/6 text-gray-400">
                      <th className="px-6 py-3 text-left font-semibold">Medicine Name</th>
                      <th className="px-6 py-3 text-left font-semibold">Generic Name</th>
                      <th className="px-6 py-3 text-left font-semibold">Stock</th>
                      <th className="px-6 py-3 text-left font-semibold">Reorder Level</th>
                      <th className="px-6 py-3 text-left font-semibold">Unit Price</th>
                      <th className="px-6 py-3 text-left font-semibold">Manufacturer</th>
                      <th className="px-6 py-3 text-left font-semibold">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/6">
                    {medications.map(med => (
                      <tr key={med.id} className={`hover:bg-white/2 ${med.low_stock ? 'bg-red-500/10' : ''}`}>
                        <td className="px-6 py-4 font-semibold">
                          {med.medicine_name}
                          {med.low_stock && <span className="ml-2 text-xs bg-red-500/20 text-red-400 px-2 py-1 rounded">LOW STOCK</span>}
                        </td>
                        <td className="px-6 py-4 text-gray-400">{med.generic_name || 'N/A'}</td>
                        <td className="px-6 py-4">
                          <span className={med.quantity_in_stock <= med.alert_threshold ? 'text-red-400 font-semibold' : 'text-green-400'}>
                            {med.quantity_in_stock} units
                          </span>
                        </td>
                        <td className="px-6 py-4 text-gray-400">{med.reorder_level}</td>
                        <td className="px-6 py-4">${parseFloat(String(med.unit_price || 0)).toFixed(2)}</td>
                        <td className="px-6 py-4 text-gray-400 text-xs">{med.expiry_date ? new Date(med.expiry_date).toLocaleDateString() : 'N/A'}</td>
                        <td className="px-6 py-4">
                          {canManageInventory && (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                setSelectedMedication(med)
                                setEditedMedication({
                                  stockQuantity: med.quantity_in_stock,
                                  unitPrice: med.unit_price
                                })
                                setShowEditModal(true)
                              }}
                              className="gap-1"
                            >
                              <Edit size={14} />
                              Edit
                            </Button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </>
      )}

      {/* Prescriptions Tab */}
      {activeTab === 'prescriptions' && (
        <Card>
          {loading ? (
            <p className="text-gray-400">Loading prescriptions...</p>
          ) : prescriptions.length === 0 ? (
            <p className="text-gray-400">No prescriptions to fill</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-white/6 text-gray-400">
                    <th className="px-6 py-3 text-left font-semibold">Patient</th>
                    <th className="px-6 py-3 text-left font-semibold">Medicines</th>
                    <th className="px-6 py-3 text-left font-semibold">Status</th>
                    <th className="px-6 py-3 text-left font-semibold">Date</th>
                    <th className="px-6 py-3 text-left font-semibold">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/6">
                  {prescriptions.map(rx => (
                    <tr key={rx.id} className="hover:bg-white/2">
                      <td className="px-6 py-4">{rx.first_name} {rx.last_name}</td>
                      <td className="px-6 py-4 text-xs">
                        {rx.medicines.map((m, i) => (
                          <div key={i} className="text-gray-300">
                            {m.medicine} - {m.dosage} {m.frequency}
                          </div>
                        ))}
                      </td>
                      <td className="px-6 py-4">
                        <span className={`px-3 py-1 rounded-full text-xs font-semibold ${
                          rx.status === 'active' ? 'bg-blue-500/20 text-blue-400' :
                          rx.status === 'expired' ? 'bg-red-500/20 text-red-400' :
                          'bg-gray-500/20 text-gray-400'
                        }`}>
                          {rx.status.charAt(0).toUpperCase() + rx.status.slice(1)}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-gray-400 text-xs">{new Date(rx.created_at).toLocaleDateString()}</td>
                      <td className="px-6 py-4">
                        {rx.status === 'active' && canManageInventory && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleFillPrescription(rx)}
                            className="gap-1"
                          >
                            <Plus size={14} />
                            Fill
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}

      {/* Add Medication Modal */}
      <Modal
        isOpen={showAddModal}
        onClose={() => setShowAddModal(false)}
        title="Add New Medication"
        size="md"
      >
        <div className="space-y-4">
          <div>
            <label className="text-sm font-semibold text-gray-300">Medicine Name *</label>
            <input
              type="text"
              value={newMedication.medicineName}
              onChange={(e) => setNewMedication({ ...newMedication, medicineName: e.target.value })}
              placeholder="e.g., Aspirin"
              className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white placeholder-gray-500"
            />
          </div>
          <div>
            <label className="text-sm font-semibold text-gray-300">Generic Name</label>
            <input
              type="text"
              value={newMedication.genericName}
              onChange={(e) => setNewMedication({ ...newMedication, genericName: e.target.value })}
              placeholder="e.g., Acetylsalicylic Acid"
              className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white placeholder-gray-500"
            />
          </div>
          <div>
            <label className="text-sm font-semibold text-gray-300">Manufacturer</label>
            <input
              type="text"
              value={newMedication.manufacturer}
              onChange={(e) => setNewMedication({ ...newMedication, manufacturer: e.target.value })}
              placeholder="Manufacturer name"
              className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white placeholder-gray-500"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-sm font-semibold text-gray-300">Stock Quantity *</label>
              <input
                type="number"
                value={newMedication.stockQuantity}
                onChange={(e) => setNewMedication({ ...newMedication, stockQuantity: parseInt(e.target.value) || 0 })}
                className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white"
              />
            </div>
            <div>
              <label className="text-sm font-semibold text-gray-300">Reorder Level</label>
              <input
                type="number"
                value={newMedication.reorderLevel}
                onChange={(e) => setNewMedication({ ...newMedication, reorderLevel: parseInt(e.target.value) || 10 })}
                className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white"
              />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-sm font-semibold text-gray-300">Unit Price *</label>
              <input
                type="number"
                value={newMedication.unitPrice}
                onChange={(e) => setNewMedication({ ...newMedication, unitPrice: parseFloat(e.target.value) || 0 })}
                placeholder="0.00"
                className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white placeholder-gray-500"
              />
            </div>
            <div>
              <label className="text-sm font-semibold text-gray-300">Alert Threshold *</label>
              <input
                type="number"
                value={newMedication.alertThreshold}
                onChange={(e) => setNewMedication({ ...newMedication, alertThreshold: parseInt(e.target.value) || 20 })}
                className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white"
              />
              <p className="text-xs text-gray-500 mt-1">Alert when stock falls below this</p>
            </div>
          </div>
          <div>
            <label className="text-sm font-semibold text-gray-300">Expiry Date</label>
            <input
              type="date"
              value={newMedication.expiryDate}
              onChange={(e) => setNewMedication({ ...newMedication, expiryDate: e.target.value })}
              className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white"
            />
          </div>
          {newMedication.stockQuantity > 0 && newMedication.stockQuantity <= newMedication.alertThreshold && (
            <div className="bg-yellow-500/10 border border-yellow-500/20 rounded p-3 flex gap-2 items-center">
              <AlertTriangle size={16} className="text-yellow-400" />
              <p className="text-sm text-yellow-400">Warning: Stock quantity is at or below alert threshold!</p>
            </div>
          )}
          <div className="flex gap-2 justify-end mt-6">
            <Button onClick={() => setShowAddModal(false)} variant="ghost">Cancel</Button>
            <Button onClick={handleAddMedication} className="bg-blue-600 hover:bg-blue-700">Add Medication</Button>
          </div>
        </div>
      </Modal>

      {/* Edit Medication Modal */}
      <Modal
        isOpen={showEditModal}
        onClose={() => setShowEditModal(false)}
        title={`Edit: ${selectedMedication?.medicine_name}`}
        size="md"
      >
        <div className="space-y-4">
          <div>
            <label className="text-sm font-semibold text-gray-300">Stock Quantity</label>
            <input
              type="number"
              value={editedMedication.stockQuantity}
              onChange={(e) => setEditedMedication({ ...editedMedication, stockQuantity: parseInt(e.target.value) || 0 })}
              className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white"
            />
          </div>
          <div>
            <label className="text-sm font-semibold text-gray-300">Unit Price</label>
            <input
              type="number"
              value={editedMedication.unitPrice}
              onChange={(e) => setEditedMedication({ ...editedMedication, unitPrice: parseFloat(e.target.value) || 0 })}
              placeholder="0.00"
              className="w-full mt-2 px-3 py-2 bg-white/5 border border-white/10 rounded text-white placeholder-gray-500"
            />
          </div>
          <div className="flex gap-2 justify-end mt-6">
            <Button onClick={() => setShowEditModal(false)} variant="ghost">Cancel</Button>
            <Button onClick={handleEditMedication} className="bg-blue-600 hover:bg-blue-700">Update</Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}

export default Pharmacy

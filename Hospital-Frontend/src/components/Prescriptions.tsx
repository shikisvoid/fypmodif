import React, { useState, useEffect } from 'react'
import { Plus, Pill, User, Search, RefreshCw, Clock, CheckCircle } from 'lucide-react'
import Card from './Card'
import Button from './Button'
import Modal from './Modal'

interface Medicine {
  medicine: string
  dosage: string
  frequency: string
  duration: string
}

interface Prescription {
  id: string
  patient_id: string
  first_name: string
  last_name: string
  meds: Medicine[]
  status: 'active' | 'filled' | 'expired'
  notes?: string
  created_at: string
  prescribed_by_name?: string
}

interface Patient {
  id: string
  first_name: string
  last_name: string
}

interface PrescriptionsProps {
  userRole: string
  userName: string
}

const Prescriptions: React.FC<PrescriptionsProps> = ({ userRole, userName }) => {
  const [prescriptions, setPrescriptions] = useState<Prescription[]>([])
  const [patients, setPatients] = useState<Patient[]>([])
  const [loading, setLoading] = useState(true)
  const [showAddModal, setShowAddModal] = useState(false)
  const [selectedPatientId, setSelectedPatientId] = useState('')
  const [searchTerm, setSearchTerm] = useState('')
  const [medicines, setMedicines] = useState<Medicine[]>([{ medicine: '', dosage: '', frequency: '', duration: '' }])
  const [notes, setNotes] = useState('')

  useEffect(() => {
    loadData()
  }, [])

  const loadData = async () => {
    try {
      setLoading(true)
      const token = localStorage.getItem('hp_access_token')
      if (!token) return

      // Load prescriptions
      const presRes = await fetch('/api/prescriptions', {
        headers: { 'Authorization': `Bearer ${token}` }
      })
      if (presRes.ok) {
        const data = await presRes.json()
        setPrescriptions(data.data || [])
      }

      // Load patients for dropdown
      const patRes = await fetch('/api/patients', {
        headers: { 'Authorization': `Bearer ${token}` }
      })
      if (patRes.ok) {
        const data = await patRes.json()
        // Backend returns { success: true, patients: [...] }
        const patientList = data.patients || data.data || data || []
        setPatients(patientList.map((p: any) => ({
          id: p.id,
          first_name: p.firstName || p.first_name || p.name?.split(' ')[0] || '',
          last_name: p.lastName || p.last_name || p.name?.split(' ')[1] || ''
        })))
      }
    } catch (error) {
      console.error('Failed to load data:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleAddMedicine = () => {
    setMedicines([...medicines, { medicine: '', dosage: '', frequency: '', duration: '' }])
  }

  const handleRemoveMedicine = (index: number) => {
    if (medicines.length > 1) {
      setMedicines(medicines.filter((_, i) => i !== index))
    }
  }

  const handleMedicineChange = (index: number, field: keyof Medicine, value: string) => {
    const updated = [...medicines]
    updated[index][field] = value
    setMedicines(updated)
  }

  const handleCreatePrescription = async () => {
    if (!selectedPatientId || medicines.some(m => !m.medicine || !m.dosage)) {
      alert('Please select a patient and fill in medicine details')
      return
    }

    try {
      const token = localStorage.getItem('hp_access_token')
      if (!token) return

      const response = await fetch('/api/prescriptions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          patient_id: selectedPatientId,
          meds: medicines,
          notes: notes
        })
      })

      if (response.ok) {
        await loadData()
        setShowAddModal(false)
        setSelectedPatientId('')
        setMedicines([{ medicine: '', dosage: '', frequency: '', duration: '' }])
        setNotes('')
        alert('Prescription created successfully! Sent to pharmacist.')
      } else {
        const err = await response.json()
        alert(`Error: ${err.error || 'Failed to create prescription'}`)
      }
    } catch (error) {
      alert(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  const filteredPrescriptions = prescriptions.filter(rx =>
    `${rx.first_name} ${rx.last_name}`.toLowerCase().includes(searchTerm.toLowerCase())
  )

  const canPrescribe = ['doctor', 'admin'].includes(userRole)

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Pill size={28} className="text-green-400" />
          Prescriptions
        </h2>
        {canPrescribe && (
          <Button onClick={() => setShowAddModal(true)} className="bg-green-600 hover:bg-green-700 text-white gap-2">
            <Plus size={18} />
            New Prescription
          </Button>
        )}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="border-l-4 border-blue-500">
          <p className="text-gray-400 text-sm">Total Prescriptions</p>
          <p className="text-3xl font-bold text-blue-400">{prescriptions.length}</p>
        </Card>
        <Card className="border-l-4 border-green-500">
          <p className="text-gray-400 text-sm">Active</p>
          <p className="text-3xl font-bold text-green-400">{prescriptions.filter(p => p.status === 'active').length}</p>
        </Card>
        <Card className="border-l-4 border-purple-500">
          <p className="text-gray-400 text-sm">Filled</p>
          <p className="text-3xl font-bold text-purple-400">{prescriptions.filter(p => p.status === 'filled').length}</p>
        </Card>
      </div>

      {/* Search */}
      <Card>
        <div className="flex items-center gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={18} />
            <input
              type="text"
              placeholder="Search by patient name..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
            />
          </div>
          <Button onClick={loadData} className="bg-gray-600 hover:bg-gray-500 text-white gap-2">
            <RefreshCw size={18} />
            Refresh
          </Button>
        </div>
      </Card>

      {/* Prescriptions List */}
      <Card>
        {loading ? (
          <div className="text-center py-8 text-gray-400">Loading prescriptions...</div>
        ) : filteredPrescriptions.length === 0 ? (
          <div className="text-center py-8 text-gray-400">No prescriptions found</div>
        ) : (
          <div className="space-y-4">
            {filteredPrescriptions.map((rx) => (
              <div key={rx.id} className="bg-gray-700 rounded-lg p-4 border border-gray-600">
                <div className="flex justify-between items-start mb-3">
                  <div className="flex items-center gap-3">
                    <User className="text-blue-400" size={24} />
                    <div>
                      <h3 className="text-white font-semibold">{rx.first_name} {rx.last_name}</h3>
                      <p className="text-gray-400 text-sm">
                        Prescribed by: {rx.prescribed_by_name || 'Unknown'}
                      </p>
                    </div>
                  </div>
                  <span className={`px-3 py-1 rounded-full text-sm ${
                    rx.status === 'active' ? 'bg-green-600 text-white' :
                    rx.status === 'filled' ? 'bg-purple-600 text-white' :
                    'bg-gray-600 text-gray-300'
                  }`}>
                    {rx.status === 'active' && <Clock size={14} className="inline mr-1" />}
                    {rx.status === 'filled' && <CheckCircle size={14} className="inline mr-1" />}
                    {rx.status.charAt(0).toUpperCase() + rx.status.slice(1)}
                  </span>
                </div>
                <div className="bg-gray-800 rounded p-3">
                  <h4 className="text-gray-300 text-sm font-medium mb-2">Medications:</h4>
                  <div className="space-y-2">
                    {(Array.isArray(rx.meds) ? rx.meds : JSON.parse(rx.meds || '[]')).map((med: Medicine, idx: number) => (
                      <div key={idx} className="flex items-center gap-2 text-sm">
                        <Pill size={14} className="text-green-400" />
                        <span className="text-white">{med.medicine}</span>
                        <span className="text-gray-400">- {med.dosage}</span>
                        <span className="text-gray-500">({med.frequency}, {med.duration})</span>
                      </div>
                    ))}
                  </div>
                  {rx.notes && (
                    <p className="text-gray-400 text-sm mt-2 border-t border-gray-700 pt-2">
                      Notes: {rx.notes}
                    </p>
                  )}
                </div>
                <p className="text-gray-500 text-xs mt-2">
                  Created: {new Date(rx.created_at).toLocaleString()}
                </p>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Add Prescription Modal */}
      <Modal isOpen={showAddModal} title="Create New Prescription" onClose={() => setShowAddModal(false)} size="lg">
          <div className="space-y-4">
            <div>
              <label className="block text-gray-300 text-sm mb-1">Select Patient *</label>
              <select
                value={selectedPatientId}
                onChange={(e) => setSelectedPatientId(e.target.value)}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
              >
                <option value="">-- Select Patient --</option>
                {patients.map((p) => (
                  <option key={p.id} value={p.id}>{p.first_name} {p.last_name}</option>
                ))}
              </select>
            </div>

            <div>
              <div className="flex items-center justify-between mb-3">
                <label className="block text-gray-300 text-sm font-semibold">Medications *</label>
                <span className="text-xs text-gray-400">{medicines.length} medicine(s) added</span>
              </div>

              {/* Medicine Cards */}
              <div className="space-y-3 max-h-64 overflow-y-auto pr-2">
                {medicines.map((med, idx) => (
                  <div key={idx} className="bg-gradient-to-r from-gray-700 to-gray-750 rounded-xl p-4 border border-gray-600 shadow-lg relative">
                    {/* Card Header */}
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center gap-2">
                        <div className="w-8 h-8 bg-green-600 rounded-full flex items-center justify-center">
                          <Pill size={16} className="text-white" />
                        </div>
                        <span className="text-green-400 font-semibold text-sm">Medicine #{idx + 1}</span>
                      </div>
                      {medicines.length > 1 && (
                        <button
                          onClick={() => handleRemoveMedicine(idx)}
                          className="text-red-400 hover:text-red-300 hover:bg-red-900/30 p-1 rounded transition-colors"
                          title="Remove medicine"
                        >
                          ✕
                        </button>
                      )}
                    </div>

                    {/* Medicine Name - Full Width */}
                    <div className="mb-3">
                      <label className="text-xs text-gray-400 mb-1 block">Medicine Name</label>
                      <input
                        type="text"
                        placeholder="e.g., Amoxicillin, Paracetamol"
                        value={med.medicine}
                        onChange={(e) => handleMedicineChange(idx, 'medicine', e.target.value)}
                        className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white text-sm focus:border-green-500 focus:ring-1 focus:ring-green-500 transition-colors"
                      />
                    </div>

                    {/* Dosage and Frequency Row */}
                    <div className="grid grid-cols-2 gap-3 mb-3">
                      <div>
                        <label className="text-xs text-gray-400 mb-1 block">Dosage</label>
                        <input
                          type="text"
                          placeholder="e.g., 500mg"
                          value={med.dosage}
                          onChange={(e) => handleMedicineChange(idx, 'dosage', e.target.value)}
                          className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white text-sm focus:border-green-500 focus:ring-1 focus:ring-green-500 transition-colors"
                        />
                      </div>
                      <div>
                        <label className="text-xs text-gray-400 mb-1 block">Frequency</label>
                        <select
                          value={med.frequency}
                          onChange={(e) => handleMedicineChange(idx, 'frequency', e.target.value)}
                          className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white text-sm focus:border-green-500 focus:ring-1 focus:ring-green-500 transition-colors"
                        >
                          <option value="">Select...</option>
                          <option value="Once daily">Once daily</option>
                          <option value="Twice daily">Twice daily</option>
                          <option value="3x daily">3x daily</option>
                          <option value="4x daily">4x daily</option>
                          <option value="Every 4 hours">Every 4 hours</option>
                          <option value="Every 6 hours">Every 6 hours</option>
                          <option value="Every 8 hours">Every 8 hours</option>
                          <option value="Before meals">Before meals</option>
                          <option value="After meals">After meals</option>
                          <option value="At bedtime">At bedtime</option>
                          <option value="As needed">As needed</option>
                        </select>
                      </div>
                    </div>

                    {/* Duration */}
                    <div>
                      <label className="text-xs text-gray-400 mb-1 block">Duration</label>
                      <select
                        value={med.duration}
                        onChange={(e) => handleMedicineChange(idx, 'duration', e.target.value)}
                        className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white text-sm focus:border-green-500 focus:ring-1 focus:ring-green-500 transition-colors"
                      >
                        <option value="">Select...</option>
                        <option value="3 days">3 days</option>
                        <option value="5 days">5 days</option>
                        <option value="7 days">7 days</option>
                        <option value="10 days">10 days</option>
                        <option value="14 days">14 days</option>
                        <option value="21 days">21 days</option>
                        <option value="30 days">30 days</option>
                        <option value="60 days">60 days</option>
                        <option value="90 days">90 days</option>
                        <option value="Continuous">Continuous</option>
                        <option value="Until finished">Until finished</option>
                      </select>
                    </div>
                  </div>
                ))}
              </div>

              {/* Add Medicine Button */}
              <button
                onClick={handleAddMedicine}
                className="mt-4 w-full py-3 border-2 border-dashed border-green-600 rounded-xl text-green-400 hover:bg-green-900/20 hover:border-green-500 transition-all flex items-center justify-center gap-2"
              >
                <Plus size={18} />
                Add Another Medicine
              </button>
            </div>

            <div>
              <label className="block text-gray-300 text-sm mb-1">Notes</label>
              <textarea
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="Additional instructions..."
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
                rows={3}
              />
            </div>

            <div className="flex justify-end gap-2 pt-4">
              <Button onClick={() => setShowAddModal(false)} className="bg-gray-600 hover:bg-gray-500 text-white">
                Cancel
              </Button>
              <Button onClick={handleCreatePrescription} className="bg-green-600 hover:bg-green-700 text-white">
                Create Prescription
              </Button>
            </div>
          </div>
        </Modal>
    </div>
  )
}

export default Prescriptions


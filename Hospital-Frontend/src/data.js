// Mock users and data used by the demo
// NOTE: MFA is ENABLED for all users. Password for all doctors: Doctor@123
// All users require TOTP verification via authenticator app
export const USERS_DB = {
  'admin@hospital.com': {
    password: 'Admin@123',
    role: 'admin',
    name: 'Dr. Sarah Admin',
    mfaEnabled: true
  },
  // 4 Doctor Accounts
  'sherin_Dr@hospital.com': {
    password: 'Doctor@123',
    role: 'doctor',
    name: 'Dr. Sherin Kumar',
    department: 'General Medicine',
    mfaEnabled: true
  },
  'Toufeeq_Dr@hospital.com': {
    password: 'Doctor@123',
    role: 'doctor',
    name: 'Dr. Toufeeq Ahmed',
    department: 'Cardiology',
    mfaEnabled: true
  },
  'Varun_Dr@hospital.com': {
    password: 'Doctor@123',
    role: 'doctor',
    name: 'Dr. Varun Reddy',
    department: 'Orthopedics',
    mfaEnabled: true
  },
  'Harini_Dr@hospital.com': {
    password: 'Doctor@123',
    role: 'doctor',
    name: 'Dr. Harini Priya',
    department: 'Pediatrics',
    mfaEnabled: true
  },
  'doctor@hospital.com': {
    password: 'Doctor@123',
    role: 'doctor',
    name: 'Dr. John Smith',
    department: 'General',
    mfaEnabled: true
  },
  'nurse@hospital.com': {
    password: 'Nurse@123',
    role: 'nurse',
    name: 'Nurse Emily Johnson',
    mfaEnabled: true
  },
  'receptionist@hospital.com': {
    password: 'Reception@123',
    role: 'receptionist',
    name: 'Mike Reception',
    mfaEnabled: true
  },
  'labtech@hospital.com': {
    password: 'LabTech@123',
    role: 'lab_technician',
    name: 'Lab Tech Rachel Wilson',
    mfaEnabled: true
  },
  'pharmacist@hospital.com': {
    password: 'Pharmacist@123',
    role: 'pharmacist',
    name: 'Pharmacist David Lee',
    mfaEnabled: true
  },
  'accountant@hospital.com': {
    password: 'Accountant@123',
    role: 'accountant',
    name: 'Accountant Patricia Brown',
    mfaEnabled: true
  },
  'patient@hospital.com': {
    password: 'Patient@123',
    role: 'patient',
    name: 'John Patient',
    mfaEnabled: true
  }
}

export const ROLE_PERMISSIONS = {
  admin: {
    canViewPatients: true,
    canEditPatients: false, // Admin views only
    canDeletePatients: false,
    canViewAppointments: true, // View only
    canManageAppointments: false, // Cannot schedule appointments
    canViewRecords: true,
    canEditRecords: false,
    canManageUsers: true,
    canViewReports: true,
    canAccessSettings: true,
    canViewBilling: true, // View only
    canEditBilling: false, // Cannot add new bills
    canManageBilling: false,
    canViewLabs: true, // View lab reports
    canManageLabs: false,
    canViewPharmacy: true, // View pharmacy
    canManagePharmacy: false, // Remove Add Medication access
    canViewAuditLogs: true,
    // Encryption permissions - Admin can view decrypted patient fields
    canDecryptLogs: true,
    canDecryptMedical: true, // Admin can view decrypted patient data
    canDecryptBilling: true
  },
  doctor: {
    canViewPatients: true,
    canEditPatients: true,
    canDeletePatients: false,
    canViewAppointments: true, // Can view and toggle appointments
    canManageAppointments: false, // Cannot schedule - only accept/reject
    canViewRecords: true,
    canEditRecords: true,
    canManageUsers: false,
    canViewReports: true,
    canAccessSettings: false,
    canViewBilling: false, // Doctor should NOT view/edit billing
    canEditBilling: false,
    canManageBilling: false,
    canViewLabs: true, // View lab reports
    canManageLabs: false, // Can prescribe tests only
    canViewPharmacy: false, // Remove inventory view
    canManagePharmacy: false,
    canPrescribe: true, // Doctor can prescribe
    // Encryption permissions - Doctor can decrypt all medical data
    canDecryptMedical: true,
    canDecryptLabReports: true,
    canDecryptPrescriptions: true,
    canDecryptVitals: true,
    canDecryptDiagnosis: true
  },
  nurse: {
    canViewPatients: true,
    canEditPatients: false,
    canDeletePatients: false,
    canViewAppointments: false, // Nurse cannot view appointments
    canManageAppointments: false,
    canViewRecords: true,
    canEditRecords: false,
    canManageUsers: false,
    canViewReports: false,
    canAccessSettings: false,
    canViewBilling: false, // Nurse cannot view billing
    canEditBilling: false,
    canManageBilling: false,
    canViewLabs: true, // Can view lab reports
    canManageLabs: false,
    canViewPharmacy: false,
    canManagePharmacy: false,
    // Encryption permissions - Nurse can decrypt patient files
    canDecryptVitals: true,
    canDecryptMedication: true,
    canDecryptNursingNotes: true,
    canDecryptMedical: true, // Nurse can decrypt patient files
    canDecryptPrescriptions: false,
    canDecryptLabReports: true // Nurse can view lab reports
  },
  receptionist: {
    canViewPatients: true,
    canEditPatients: true, // Receptionist can edit patient records
    canDeletePatients: false,
    canViewAppointments: true,
    canManageAppointments: true, // Full appointment management
    canViewRecords: true,
    canEditRecords: true, // Can edit patient info
    canManageUsers: false,
    canViewReports: false,
    canAccessSettings: false,
    canViewBilling: true,
    canEditBilling: true, // Can edit doctor fees only
    canManageBilling: true,
    canViewLabs: false,
    canManageLabs: false,
    canViewPharmacy: false,
    canManagePharmacy: false,
    canReceiveNotifications: true, // Receives appointment notifications
    // Encryption permissions - Receptionist can only decrypt demographic data
    canDecryptDemographics: true,
    canDecryptMedical: false,
    canDecryptLabReports: false,
    canDecryptPrescriptions: false
  },
  lab_technician: {
    canViewPatients: true,
    canEditPatients: false,
    canDeletePatients: false,
    canViewAppointments: false,
    canManageAppointments: false,
    canViewRecords: true,
    canEditRecords: false,
    canManageUsers: false,
    canViewReports: false,
    canAccessSettings: false,
    canViewBilling: true, // Lab tech can view billing to add lab fees
    canEditBilling: true, // Lab tech can add lab fees
    canManageBilling: false,
    canViewLabs: true,
    canManageLabs: true,
    canViewPharmacy: false,
    canManagePharmacy: false,
    // Encryption permissions - Lab tech can decrypt test type and patient name only
    canDecryptTestType: true,
    canDecryptPatientName: true,
    canDecryptMedical: false,
    canDecryptDiagnosis: false,
    canDecryptPrescriptions: false,
    canEncryptLabResults: true
  },
  pharmacist: {
    canViewPatients: true,
    canEditPatients: false,
    canDeletePatients: false,
    canViewAppointments: false,
    canManageAppointments: false,
    canViewRecords: false,
    canEditRecords: false,
    canManageUsers: false,
    canViewReports: false,
    canAccessSettings: false,
    canViewBilling: true, // Pharmacist can view billing to add pharmacy fees
    canEditBilling: true, // Pharmacist can add pharmacy fees
    canManageBilling: false,
    canViewLabs: false,
    canManageLabs: false,
    canViewPharmacy: true,
    canManagePharmacy: true,
    // Encryption permissions - Pharmacist can decrypt medicine section only
    canDecryptMedicine: true,
    canDecryptDosage: true,
    canDecryptMedical: false,
    canDecryptDiagnosis: false,
    canDecryptLabReports: false
  },
  accountant: {
    canViewPatients: false, // Accountant has NO access to patient records
    canEditPatients: false,
    canDeletePatients: false,
    canViewAppointments: false,
    canManageAppointments: false,
    canViewRecords: false,
    canEditRecords: false,
    canManageUsers: false,
    canViewReports: true, // Can view financial reports
    canAccessSettings: false,
    canViewBilling: true, // View billing summaries only
    canEditBilling: false, // Cannot edit billing - read only
    canManageBilling: false, // No billing management
    canViewLabs: false,
    canManageLabs: false,
    canViewPharmacy: false,
    canManagePharmacy: false,
    // Encryption permissions - Accountant can decrypt billing data only
    canDecryptBilling: true,
    canDecryptInvoices: true,
    canDecryptInsurance: true,
    canDecryptMedical: false,
    canDecryptLabReports: false,
    canDecryptPrescriptions: false
  },
  patient: {
    canViewPatients: false,
    canEditPatients: false,
    canDeletePatients: false,
    canViewAppointments: false,
    canManageAppointments: false,
    canViewRecords: true,
    canEditRecords: false,
    canManageUsers: false,
    canViewReports: false,
    canAccessSettings: false,
    canViewBilling: true,
    canEditBilling: false,
    canManageBilling: false,
    canViewLabs: false,
    canManageLabs: false,
    canViewPharmacy: false,
    canManagePharmacy: false,
    // Encryption permissions - Patient can decrypt own medical data
    canDecryptOwnMedical: true,
    canDecryptOwnBilling: true,
    canDecryptMedical: false
  }
}

export const MOCK_PATIENTS = [
  { id: 1, name: 'Alice Brown', age: 45, condition: 'Hypertension', lastVisit: '2025-11-15' },
  { id: 2, name: 'Bob Wilson', age: 62, condition: 'Diabetes Type 2', lastVisit: '2025-11-14' },
  { id: 3, name: 'Carol Davis', age: 38, condition: 'Asthma', lastVisit: '2025-11-16' },
  { id: 4, name: 'David Lee', age: 55, condition: 'Arthritis', lastVisit: '2025-11-10' }
]

export const MOCK_APPOINTMENTS = [
  { id: 1, patient: 'Alice Brown', doctor: 'Dr. John Smith', date: '2025-11-20', time: '10:00 AM', status: 'Scheduled' },
  { id: 2, patient: 'Bob Wilson', doctor: 'Dr. Sarah Admin', date: '2025-11-20', time: '11:30 AM', status: 'Scheduled' },
  { id: 3, patient: 'Carol Davis', doctor: 'Dr. John Smith', date: '2025-11-21', time: '09:00 AM', status: 'Scheduled' },
  { id: 4, patient: 'David Lee', doctor: 'Dr. Sarah Admin', date: '2025-11-19', time: '02:00 PM', status: 'Completed' }
]

/**
 * Seed file: Add comprehensive data for all modules
 * Run with: npx knex seed:run --env development
 */

exports.seed = async function(knex) {
  // Delete existing data in correct order (respecting foreign keys)
  await knex('audit_logs').del();
  await knex('files').del();
  await knex('vitals').del();
  await knex('prescriptions').del();
  await knex('lab_tests').del();
  await knex('appointments').del();
  // Only delete patients when explicitly allowed by env var to avoid accidental data loss
  if (process.env.ALLOW_SEED_PATIENT_DESTRUCTIVE === 'true') {
    await knex('patients').del();
  } else {
    console.log('Skipping deletion of patients: set ALLOW_SEED_PATIENT_DESTRUCTIVE=true to allow');
  }
  await knex('users').del();

  // Insert Users
  const users = await knex('users').insert([
    {
      id: '550e8400-e29b-41d4-a716-446655440001',
      name: 'Dr. John Smith',
      email: 'doctor@hospital.com',
      role: 'doctor',
      mfa_enabled: 'true',
      mfa_secret: 'JBSWY3DPEBLW64TMMQ======',
      created_at: new Date(),
      updated_at: new Date(),
    },
    {
      id: '550e8400-e29b-41d4-a716-446655440002',
      name: 'Dr. Sarah Admin',
      email: 'admin@hospital.com',
      role: 'admin',
      mfa_enabled: 'true',
      mfa_secret: 'JBSWY3DPEBLW64TMMQ======',
      created_at: new Date(),
      updated_at: new Date(),
    },
    {
      id: '550e8400-e29b-41d4-a716-446655440003',
      name: 'Jane Nurse',
      email: 'nurse@hospital.com',
      role: 'nurse',
      mfa_enabled: 'false',
      created_at: new Date(),
      updated_at: new Date(),
    },
    {
      id: '550e8400-e29b-41d4-a716-446655440004',
      name: 'Lab Tech David',
      email: 'labtech@hospital.com',
      role: 'lab_technician',
      mfa_enabled: 'false',
      created_at: new Date(),
      updated_at: new Date(),
    },
    {
      id: '550e8400-e29b-41d4-a716-446655440005',
      name: 'Accountant Amy',
      email: 'accountant@hospital.com',
      role: 'accountant',
      mfa_enabled: 'false',
      created_at: new Date(),
      updated_at: new Date(),
    },
    {
      id: '550e8400-e29b-41d4-a716-446655440006',
      name: 'Pharmacist Phil',
      email: 'pharmacist@hospital.com',
      role: 'pharmacist',
      mfa_enabled: 'false',
      created_at: new Date(),
      updated_at: new Date(),
    },
  ]);

  // Insert Patients
  const patientRows = [
    {
      id: '550e8400-e29b-41d4-a716-446655550001',
      mrn: 'MRN-001-2024',
      first_name: 'Alice',
      last_name: 'Brown',
      dob: '1980-05-15',
      gender: 'Female',
      contact: JSON.stringify({
        phone: '+1-555-0101',
        email: 'alice.brown@email.com',
        address: '123 Main St, Springfield, IL'
      }),
      insurance: JSON.stringify({
        provider: 'Blue Cross Blue Shield',
        policy_id: 'BCBS-123456'
      }),
      allergies: JSON.stringify(['Penicillin', 'Shellfish']),
      medical_history: JSON.stringify({ conditions: ['Hypertension', 'Type 2 Diabetes'], medications: [{ name: 'Lisinopril', dosage: '10mg' }, { name: 'Metformin', dosage: '500mg' }] }),
      emergency_contact: 'Bob Brown (+1-555-0102)',
      created_at: new Date(),
      updated_at: new Date(),
    },
    {
      id: '550e8400-e29b-41d4-a716-446655550002',
      mrn: 'MRN-002-2024',
      first_name: 'Bob',
      last_name: 'Wilson',
      dob: '1975-08-22',
      gender: 'Male',
      contact: JSON.stringify({
        phone: '+1-555-0103',
        email: 'bob.wilson@email.com',
        address: '456 Oak Ave, Springfield, IL'
      }),
      insurance: JSON.stringify({
        provider: 'Aetna',
        policy_id: 'AETNA-789012'
      }),
      allergies: JSON.stringify(['Sulfa drugs']),
      medical_history: JSON.stringify({ conditions: ['Type 2 Diabetes', 'High Cholesterol'], medications: [{ name: 'Metformin', dosage: '1000mg' }, { name: 'Atorvastatin', dosage: '20mg' }] }),
      emergency_contact: 'Carol Wilson (+1-555-0104)',
      created_at: new Date(),
      updated_at: new Date(),
    },
    {
      id: '550e8400-e29b-41d4-a716-446655550003',
      mrn: 'MRN-003-2024',
      first_name: 'Carol',
      last_name: 'Davis',
      dob: '1990-03-10',
      gender: 'Female',
      contact: JSON.stringify({
        phone: '+1-555-0105',
        email: 'carol.davis@email.com',
        address: '789 Pine Ln, Springfield, IL'
      }),
      insurance: JSON.stringify({
        provider: 'Cigna',
        policy_id: 'CIGNA-345678'
      }),
      allergies: JSON.stringify(['Aspirin', 'NSAIDs']),
      medical_history: JSON.stringify({ conditions: ['Asthma', 'Seasonal allergies'], medications: [{ name: 'Albuterol', dosage: '2 puffs' }, { name: 'Fluticasone', dosage: '110mcg' }] }),
      emergency_contact: 'David Davis (+1-555-0106)',
      created_at: new Date(),
      updated_at: new Date(),
    },
    {
      id: '550e8400-e29b-41d4-a716-446655550004',
      mrn: 'MRN-004-2024',
      first_name: 'David',
      last_name: 'Lee',
      dob: '1988-11-30',
      gender: 'Male',
      contact: JSON.stringify({
        phone: '+1-555-0107',
        email: 'david.lee@email.com',
        address: '321 Elm St, Springfield, IL'
      }),
      insurance: JSON.stringify({
        provider: 'UnitedHealthcare',
        policy_id: 'UHC-567890'
      }),
      allergies: JSON.stringify([]),
      medical_history: JSON.stringify({ conditions: ['Osteoarthritis', 'Chronic back pain'], medications: [{ name: 'Ibuprofen', dosage: '400mg' }] }),
      emergency_contact: 'Emma Lee (+1-555-0108)',
      created_at: new Date(),
      updated_at: new Date(),
    },
  ];

  let patients;
  if (process.env.ALLOW_SEED_PATIENT_DESTRUCTIVE === 'true') {
    patients = await knex('patients').insert(patientRows);
  } else {
    // When not allowed to delete patients, insert but ignore conflicts to avoid duplicate key errors
    await knex('patients').insert(patientRows).onConflict('id').ignore();
    // Fetch the rows we care about so downstream code relying on `patients.length` still works
    patients = await knex('patients').whereIn('id', patientRows.map(p => p.id));
  }

  // Insert Appointments
  const appointments = await knex('appointments').insert([
    {
      id: '550e8400-e29b-41d4-a716-446655660001',
      patient_id: '550e8400-e29b-41d4-a716-446655550001',
      doctor_id: '550e8400-e29b-41d4-a716-446655440001',
      scheduled_at: new Date('2024-11-30 09:00:00'),
      appointment_type: 'Checkup',
      status: 'scheduled',
      notes: 'Annual checkup and diabetes management review',
      created_at: new Date(),
      updated_at: new Date(),
    },
    {
      id: '550e8400-e29b-41d4-a716-446655660002',
      patient_id: '550e8400-e29b-41d4-a716-446655550002',
      doctor_id: '550e8400-e29b-41d4-a716-446655440001',
      scheduled_at: new Date('2024-11-28 10:30:00'),
      appointment_type: 'Follow-up',
      status: 'completed',
      notes: 'Cholesterol level check',
      created_at: new Date(),
      updated_at: new Date(),
    },
    {
      id: '550e8400-e29b-41d4-a716-446655660003',
      patient_id: '550e8400-e29b-41d4-a716-446655550003',
      doctor_id: '550e8400-e29b-41d4-a716-446655440001',
      scheduled_at: new Date('2024-12-02 14:00:00'),
      appointment_type: 'Consultation',
      status: 'scheduled',
      notes: 'Asthma management and breathing test',
      created_at: new Date(),
      updated_at: new Date(),
    },
    {
      id: '550e8400-e29b-41d4-a716-446655660004',
      patient_id: '550e8400-e29b-41d4-a716-446655550004',
      doctor_id: '550e8400-e29b-41d4-a716-446655440001',
      scheduled_at: new Date('2024-12-05 15:30:00'),
      appointment_type: 'Physical Therapy',
      status: 'scheduled',
      notes: 'Back pain management session',
      created_at: new Date(),
      updated_at: new Date(),
    },
  ]);

  // Insert Lab Tests
  const labTests = await knex('lab_tests').insert([
    {
      id: '550e8400-e29b-41d4-a716-446655770001',
      patient_id: '550e8400-e29b-41d4-a716-446655550001',
      requested_by: '550e8400-e29b-41d4-a716-446655440001',
      test_name: 'Complete Blood Count',
      status: 'completed',
      result_data: JSON.stringify({
        wbc: '7.2 K/uL',
        rbc: '4.8 M/uL',
        hemoglobin: '14.2 g/dL',
        hematocrit: '42%',
        platelets: '250 K/uL'
      }),
      result_pdf_key: 'labs/cbc-alice-2024-11-25.pdf',
      completed_at: new Date('2024-11-25 16:00:00'),
      notes: 'All values within normal range',
      created_at: new Date(),
      updated_at: new Date(),
    },
    {
      id: '550e8400-e29b-41d4-a716-446655770002',
      patient_id: '550e8400-e29b-41d4-a716-446655550002',
      requested_by: '550e8400-e29b-41d4-a716-446655440001',
      test_name: 'Lipid Panel',
      status: 'completed',
      result_data: JSON.stringify({
        total_cholesterol: '185 mg/dL',
        ldl: '110 mg/dL',
        hdl: '50 mg/dL',
        triglycerides: '100 mg/dL'
      }),
      result_pdf_key: 'labs/lipid-bob-2024-11-24.pdf',
      completed_at: new Date('2024-11-24 14:30:00'),
      notes: 'Cholesterol levels improved with current medication',
      created_at: new Date(),
      updated_at: new Date(),
    },
    {
      id: '550e8400-e29b-41d4-a716-446655770003',
      patient_id: '550e8400-e29b-41d4-a716-446655550001',
      requested_by: '550e8400-e29b-41d4-a716-446655440001',
      test_name: 'Hemoglobin A1C',
      status: 'pending',
      result_data: null,
      result_pdf_key: null,
      completed_at: null,
      notes: 'Diabetes screening test ordered',
      created_at: new Date(),
      updated_at: new Date(),
    },
    {
      id: '550e8400-e29b-41d4-a716-446655770004',
      patient_id: '550e8400-e29b-41d4-a716-446655550003',
      requested_by: '550e8400-e29b-41d4-a716-446655440001',
      test_name: 'Pulmonary Function Test',
      status: 'pending',
      result_data: null,
      result_pdf_key: null,
      completed_at: null,
      notes: 'Asthma assessment test',
      created_at: new Date(),
      updated_at: new Date(),
    },
  ]);

  // Insert Vitals
  const vitals = await knex('vitals').insert([
    {
      id: '550e8400-e29b-41d4-a716-446655880001',
      patient_id: '550e8400-e29b-41d4-a716-446655550001',
      recorded_by: '550e8400-e29b-41d4-a716-446655440003',
      recorded_at: new Date('2024-11-27 09:30:00'),
      metrics: JSON.stringify({
        blood_pressure: '135/85 mmHg',
        heart_rate: 72,
        respiratory_rate: 18,
        temperature: '98.6°F',
        weight: 155,
        height: 65,
        oxygen_saturation: '98%'
      }),
      created_at: new Date(),
    },
    {
      id: '550e8400-e29b-41d4-a716-446655880002',
      patient_id: '550e8400-e29b-41d4-a716-446655550002',
      recorded_by: '550e8400-e29b-41d4-a716-446655440003',
      recorded_at: new Date('2024-11-26 14:00:00'),
      metrics: JSON.stringify({
        blood_pressure: '128/82 mmHg',
        heart_rate: 68,
        respiratory_rate: 16,
        temperature: '98.4°F',
        weight: 180,
        height: 70,
        oxygen_saturation: '99%'
      }),
      created_at: new Date(),
    },
    {
      id: '550e8400-e29b-41d4-a716-446655880003',
      patient_id: '550e8400-e29b-41d4-a716-446655550003',
      recorded_by: '550e8400-e29b-41d4-a716-446655440003',
      recorded_at: new Date('2024-11-27 11:00:00'),
      metrics: JSON.stringify({
        blood_pressure: '118/76 mmHg',
        heart_rate: 70,
        respiratory_rate: 18,
        temperature: '98.5°F',
        weight: 130,
        height: 64,
        oxygen_saturation: '97%'
      }),
      created_at: new Date(),
    },
  ]);

  // Insert Prescriptions
  const prescriptions = await knex('prescriptions').insert([
    {
      id: '550e8400-e29b-41d4-a716-446655990001',
      patient_id: '550e8400-e29b-41d4-a716-446655550001',
      prescribed_by: '550e8400-e29b-41d4-a716-446655440001',
      status: 'active',
      meds: JSON.stringify([
        {
          name: 'Lisinopril',
          dosage: '10mg',
          frequency: 'Once daily',
          duration: '30 days',
          quantity: 30
        },
        {
          name: 'Metformin',
          dosage: '500mg',
          frequency: 'Twice daily',
          duration: '30 days',
          quantity: 60
        }
      ]),
      notes: 'Take with food. Monitor blood sugar levels',
      created_at: new Date(),
      updated_at: new Date(),
    },
    {
      id: '550e8400-e29b-41d4-a716-446655990002',
      patient_id: '550e8400-e29b-41d4-a716-446655550002',
      prescribed_by: '550e8400-e29b-41d4-a716-446655440001',
      status: 'active',
      meds: JSON.stringify([
        {
          name: 'Atorvastatin',
          dosage: '20mg',
          frequency: 'Once daily',
          duration: '30 days',
          quantity: 30
        },
        {
          name: 'Metformin',
          dosage: '1000mg',
          frequency: 'Twice daily',
          duration: '30 days',
          quantity: 60
        }
      ]),
      notes: 'Take at same time each day. Avoid grapefruit juice',
      created_at: new Date(),
      updated_at: new Date(),
    },
    {
      id: '550e8400-e29b-41d4-a716-446655990003',
      patient_id: '550e8400-e29b-41d4-a716-446655550003',
      prescribed_by: '550e8400-e29b-41d4-a716-446655440001',
      status: 'active',
      meds: JSON.stringify([
        {
          name: 'Fluticasone Propionate',
          dosage: '110mcg',
          frequency: 'Twice daily',
          duration: '30 days',
          quantity: 60
        },
        {
          name: 'Albuterol',
          dosage: '90mcg',
          frequency: 'As needed',
          duration: '30 days',
          quantity: 120
        }
      ]),
      notes: 'Use controller inhaler daily. Use rescue inhaler as needed for shortness of breath',
      created_at: new Date(),
      updated_at: new Date(),
    },
  ]);

  console.log('✅ Database seeded successfully!');
  console.log(`   - ${users.length} users created`);
  console.log(`   - ${patients.length} patients created`);
  console.log(`   - ${appointments.length} appointments created`);
  console.log(`   - ${labTests.length} lab tests created`);
  console.log(`   - ${vitals.length} vital records created`);
  console.log(`   - ${prescriptions.length} prescriptions created`);
};

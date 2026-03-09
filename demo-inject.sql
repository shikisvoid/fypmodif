-- Demo: Inject suspicious audit log entries to trigger EDR detection rules
-- This script simulates malicious database activity

DO $$
DECLARE
  acct_id uuid;
BEGIN
  SELECT id INTO acct_id FROM users WHERE email = 'accountant@hospital.com';

  -- RULE TRIGGER: DB_UNAUTHORIZED_TABLE_ACCESS
  -- Accountant accessing lab_tests (not in their allowed tables)
  INSERT INTO audit_logs (actor_id, action, resource_type, status, details) VALUES
    (acct_id, 'READ', 'lab_tests', 'success', '{"reason":"accountant snooping lab results"}'),
    (acct_id, 'READ', 'lab_tests', 'success', '{"reason":"accountant snooping lab results"}'),
    (acct_id, 'READ', 'lab_results', 'success', '{"reason":"accountant accessing lab results"}'),
    (acct_id, 'UPDATE', 'lab_tests', 'success', '{"reason":"accountant modifying lab data"}');

  -- RULE TRIGGER: DB_MASS_DELETE (7 deletes on patients table, threshold is 5)
  INSERT INTO audit_logs (actor_id, action, resource_type, status, details) VALUES
    (acct_id, 'DELETE', 'patients', 'success', '{"bulk_delete":true,"record":1}'),
    (acct_id, 'DELETE', 'patients', 'success', '{"bulk_delete":true,"record":2}'),
    (acct_id, 'DELETE', 'patients', 'success', '{"bulk_delete":true,"record":3}'),
    (acct_id, 'DELETE', 'patients', 'success', '{"bulk_delete":true,"record":4}'),
    (acct_id, 'DELETE', 'patients', 'success', '{"bulk_delete":true,"record":5}'),
    (acct_id, 'DELETE', 'patients', 'success', '{"bulk_delete":true,"record":6}'),
    (acct_id, 'DELETE', 'patients', 'success', '{"bulk_delete":true,"record":7}');

  -- RULE TRIGGER: DB_BULK_DATA_READ (25 reads on patients, threshold is 20)
  INSERT INTO audit_logs (actor_id, action, resource_type, status, details) VALUES
    (acct_id, 'READ', 'patients', 'success', '{"export_attempt":true,"page":1}'),
    (acct_id, 'READ', 'patients', 'success', '{"export_attempt":true,"page":2}'),
    (acct_id, 'READ', 'patients', 'success', '{"export_attempt":true,"page":3}'),
    (acct_id, 'READ', 'patients', 'success', '{"export_attempt":true,"page":4}'),
    (acct_id, 'READ', 'patients', 'success', '{"export_attempt":true,"page":5}'),
    (acct_id, 'READ', 'patients', 'success', '{"export_attempt":true,"page":6}'),
    (acct_id, 'READ', 'patients', 'success', '{"export_attempt":true,"page":7}'),
    (acct_id, 'READ', 'patients', 'success', '{"export_attempt":true,"page":8}'),
    (acct_id, 'READ', 'patients', 'success', '{"export_attempt":true,"page":9}'),
    (acct_id, 'READ', 'patients', 'success', '{"export_attempt":true,"page":10}'),
    (acct_id, 'READ', 'patients', 'success', '{"export_attempt":true,"page":11}'),
    (acct_id, 'READ', 'patients', 'success', '{"export_attempt":true,"page":12}'),
    (acct_id, 'READ', 'patients', 'success', '{"export_attempt":true,"page":13}'),
    (acct_id, 'READ', 'patients', 'success', '{"export_attempt":true,"page":14}'),
    (acct_id, 'READ', 'patients', 'success', '{"export_attempt":true,"page":15}'),
    (acct_id, 'READ', 'patients', 'success', '{"export_attempt":true,"page":16}'),
    (acct_id, 'READ', 'patients', 'success', '{"export_attempt":true,"page":17}'),
    (acct_id, 'READ', 'patients', 'success', '{"export_attempt":true,"page":18}'),
    (acct_id, 'READ', 'patients', 'success', '{"export_attempt":true,"page":19}'),
    (acct_id, 'READ', 'patients', 'success', '{"export_attempt":true,"page":20}'),
    (acct_id, 'READ', 'patients', 'success', '{"export_attempt":true,"page":21}'),
    (acct_id, 'READ', 'patients', 'success', '{"export_attempt":true,"page":22}'),
    (acct_id, 'READ', 'patients', 'success', '{"export_attempt":true,"page":23}'),
    (acct_id, 'READ', 'patients', 'success', '{"export_attempt":true,"page":24}'),
    (acct_id, 'READ', 'patients', 'success', '{"export_attempt":true,"page":25}'),
    (acct_id, 'EXPORT', 'patients', 'success', '{"full_export":true}');

  RAISE NOTICE 'Injected: 4 unauthorized access + 7 mass deletes + 26 bulk reads = 37 suspicious audit entries';
END $$;

SELECT count(*) AS total_audit_entries FROM audit_logs;


// Quick telemetry check script
const http = require('http');
http.get('http://127.0.0.1:9090/telemetry', (res) => {
  let d = '';
  res.on('data', c => d += c);
  res.on('end', () => {
    const p = JSON.parse(d);
    const items = p.recentTelemetry || [];
    console.log('Total telemetry items:', items.length);
    const withDb = items.filter(i => i.dbActivity && i.dbActivity.alerts && i.dbActivity.alerts.length > 0);
    console.log('Items with DB alerts:', withDb.length);
    if (withDb.length > 0) {
      for (const item of withDb) {
        console.log(`\n--- Host: ${item.hostId} | Role: ${item.userRole} ---`);
        for (const a of item.dbActivity.alerts) {
          console.log(`  [${a.severity}] ${a.type} | table=${a.table||'N/A'} actor=${a.actorEmail||'N/A'}`);
        }
      }
    } else {
      console.log('No DB alert items found in recent telemetry.');
      // Show a sample item structure
      if (items.length > 0) {
        const sample = items[items.length - 1];
        console.log('\nSample item keys:', Object.keys(sample));
        if (sample.dbActivity) {
          console.log('dbActivity:', JSON.stringify(sample.dbActivity).substring(0, 500));
        }
      }
    }
  });
}).on('error', (e) => console.error('Error:', e.message));


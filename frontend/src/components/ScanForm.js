import { useState } from 'react';

export default function ScanForm({ onScan, loading }) {
  const [target, setTarget] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (target.trim()) onScan(target.trim());
  };

  return (
    <form onSubmit={handleSubmit} style={{ display: 'flex', gap: 8 }}>
      <input
        value={target}
        onChange={(e) => setTarget(e.target.value)}
        placeholder="Enter domain or IP (e.g. example.com)"
        style={{ flex: 1, padding: '10px 14px', fontSize: 16, borderRadius: 6, border: '1px solid #333', background: '#1a1a2e', color: '#fff' }}
      />
      <button
        type="submit"
        disabled={loading}
        style={{ padding: '10px 24px', fontSize: 16, borderRadius: 6, background: '#e94560', color: '#fff', border: 'none', cursor: loading ? 'not-allowed' : 'pointer' }}
      >
        {loading ? 'Scanning...' : 'Scan'}
      </button>
    </form>
  );
}

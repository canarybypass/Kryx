import { useState } from 'react';

export default function ScanForm({ onScan, loading }) {
  const [target, setTarget] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (target.trim()) onScan(target.trim());
  };

  return (
    <form onSubmit={handleSubmit} style={styles.form}>
      <input
        value={target}
        onChange={(e) => setTarget(e.target.value)}
        placeholder="Enter domain, IP, or URL (e.g. example.com, https://target.com)"
        style={styles.input}
        autoFocus
      />
      <button type="submit" disabled={loading} style={styles.button}>
        {loading ? 'Scanning...' : 'Scan'}
      </button>
    </form>
  );
}

const styles = {
  form: {
    display: 'flex',
    gap: 8,
  },
  input: {
    flex: 1,
    padding: '12px 16px',
    fontSize: 16,
    borderRadius: 8,
    border: '1px solid #333',
    background: '#1a1a2e',
    color: '#fff',
    outline: 'none',
  },
  button: {
    padding: '12px 32px',
    fontSize: 16,
    borderRadius: 8,
    background: '#e94560',
    color: '#fff',
    border: 'none',
    cursor: 'pointer',
    fontWeight: 'bold',
    transition: 'opacity 0.2s',
  },
};
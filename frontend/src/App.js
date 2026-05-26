import { useState } from 'react';
import ScanForm from './components/ScanForm';
import Results from './components/Results';
import { runScan } from './services/api';

export default function App() {
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);

  const handleScan = async (target) => {
    setLoading(true);
    setError(null);
    setResults(null);
    try {
      const { data } = await runScan(target);
      setResults(data);
    } catch (e) {
      setError(e.response?.data?.detail || 'Scan failed. Check backend.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', background: '#0f0f1a', color: '#fff', fontFamily: 'monospace', padding: '40px 24px', maxWidth: 900, margin: '0 auto' }}>
      <h1 style={{ color: '#e94560', marginBottom: 8 }}>⚡ Hexor</h1>
      <p style={{ color: '#888', marginBottom: 32 }}>AI-powered penetration testing assistant</p>
      <ScanForm onScan={handleScan} loading={loading} />
      {error && <p style={{ color: '#e94560', marginTop: 16 }}>{error}</p>}
      {loading && <p style={{ color: '#888', marginTop: 24 }}>🔍 Running recon and analysis...</p>}
      <Results data={results} />
    </div>
  );
}

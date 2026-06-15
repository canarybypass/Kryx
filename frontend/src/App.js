import { useState, useEffect, useRef } from 'react';
import ScanForm from './components/ScanForm';
import Results from './components/Results';
import LiveProgress from './components/LiveProgress';
import { runScan, createScanSocket } from './services/api';

export default function App() {
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [progress, setProgress] = useState([]);
  const [stage, setStage] = useState(null);
  const wsRef = useRef(null);

  const handleScan = async (target) => {
    setLoading(true);
    setError(null);
    setResults(null);
    setProgress([]);
    setStage(null);
    try {
      const ws = createScanSocket();
      wsRef.current = ws;
      await new Promise((resolve, reject) => {
        ws.onopen = () => ws.send(JSON.stringify({ target, max_hunters: 8 }));
        ws.onmessage = (event) => {
          const msg = JSON.parse(event.data);
          const { event: evt, data } = msg;
          switch (evt) {
            case 'status':
              setStage(data);
              setProgress((p) => [...p, { type: 'status', text: 'Stage: ' + data, ts: Date.now() }]);
              break;
            case 'hunter_step':
              setProgress((p) => [...p, { type: 'hunter', text: '[' + data.attack_class + '] ' + data.tool, ts: Date.now() }]);
              break;
            case 'complete':
              setResults(data); setLoading(false); setStage('done'); ws.close(); resolve(data);
              break;
            case 'error':
              setError(data); setLoading(false); ws.close(); reject(new Error(data));
              break;
          }
        };
        ws.onerror = (err) => { ws.close(); reject(err); };
        setTimeout(() => { if (loading) { ws.close(); reject(new Error('timeout')); } }, 300000);
      });
    } catch (e) {
      console.error('WebSocket failed, falling back to REST', e);
      try {
        const { data } = await runScan(target);
        setResults(data);
      } catch (e2) {
        setError(e2.response?.data?.detail || 'Scan failed.');
      } finally {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    return () => { if (wsRef.current) wsRef.current.close(); };
  }, []);

  return (
    <div style={s.container}>
      <h1 style={s.title}>Kryx</h1>
      <p style={s.subtitle}>AI-powered penetration testing - multi-agent harness</p>
      <ScanForm onScan={handleScan} loading={loading} />
      {error && <p style={s.error}>{error}</p>}
      {loading && stage && <p style={s.stage}>Stage: <strong>{stage}</strong></p>}
      {loading && <LiveProgress items={progress} />}
      <Results data={results} />
    </div>
  );
}

const s = {
  container: { minHeight: '100vh', background: '#0f0f1a', color: '#fff', fontFamily: 'monospace', padding: '40px 24px', maxWidth: 1000, margin: '0 auto' },
  title: { color: '#e94560', marginBottom: 8, fontSize: 32 },
  subtitle: { color: '#888', marginBottom: 32 },
  error: { color: '#e94560', marginTop: 16 },
  stage: { color: '#ffd166', marginTop: 24 },
};
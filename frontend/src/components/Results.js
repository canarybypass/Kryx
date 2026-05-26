import ReactMarkdown from 'react-markdown';

const SEVERITY_COLOR = { critical: '#e94560', high: '#ff6b35', medium: '#ffd166', low: '#06d6a0' };

export default function Results({ data }) {
  if (!data) return null;

  return (
    <div style={{ marginTop: 32 }}>
      <h2 style={{ color: '#e94560' }}>Target: {data.target}</h2>

      <h3>Vulnerabilities ({data.vulnerabilities.length})</h3>
      {data.vulnerabilities.map((v, i) => (
        <div key={i} style={{ border: `1px solid ${SEVERITY_COLOR[v.severity] || '#555'}`, borderRadius: 8, padding: 16, marginBottom: 12 }}>
          <strong style={{ color: SEVERITY_COLOR[v.severity] }}>[{v.severity?.toUpperCase()}]</strong> {v.name}
          <p style={{ margin: '8px 0 4px', color: '#ccc' }}>{v.description}</p>
          <p style={{ margin: 0, color: '#aaa', fontSize: 14 }}>💡 {v.recommendation}</p>
        </div>
      ))}

      <h3>Full Report</h3>
      <div style={{ background: '#1a1a2e', padding: 24, borderRadius: 8, color: '#ccc', lineHeight: 1.7 }}>
        <ReactMarkdown>{data.report}</ReactMarkdown>
      </div>
    </div>
  );
}

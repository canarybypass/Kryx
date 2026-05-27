import ReactMarkdown from 'react-markdown';

const SEV = { critical: '#ff0040', high: '#e94560', medium: '#ffd166', low: '#06d6a0' };

export default function Results({ data }) {
  if (!data) return null;

  return (
    <div style={{ marginTop: 32 }}>
      <h2 style={{ color: '#e94560' }}>Target: {data.target}</h2>
      {data.summary && <p style={{ color: '#ccc', lineHeight: 1.6 }}>{data.summary}</p>}

      {data.attack_chains?.length > 0 && (
        <>
          <h3 style={{ color: '#ffd166', marginTop: 24 }}>⛓ Attack Chains ({data.attack_chains.length})</h3>
          {data.attack_chains.map((c, i) => (
            <div key={i} style={{ border: `1px solid ${SEV[c.severity] || '#555'}`, borderRadius: 8, padding: 16, marginBottom: 12, background: '#0d0d1a' }}>
              <div style={{ marginBottom: 8 }}>
                <strong style={{ color: SEV[c.severity] }}>[{c.severity?.toUpperCase()}]</strong>
                {c.verified && <span style={{ color: '#06d6a0', fontSize: 12, marginLeft: 8 }}>✓ VERIFIED</span>}
              </div>
              <div style={{ color: '#aaa', fontSize: 13, marginBottom: 8 }}>
                {c.chain?.map((step, j) => (
                  <span key={j}>{step}{j < c.chain.length - 1 ? ' → ' : ''}</span>
                ))}
              </div>
              <p style={{ color: '#ccc', margin: '4px 0' }}>{c.description}</p>
              <p style={{ color: '#888', fontSize: 13, margin: 0 }}>💥 Impact: {c.impact}</p>
            </div>
          ))}
        </>
      )}

      {data.vulnerabilities?.length > 0 && (
        <>
          <h3 style={{ marginTop: 24 }}>Vulnerabilities ({data.vulnerabilities.length})</h3>
          {data.vulnerabilities.map((v, i) => (
            <div key={i} style={{ border: `1px solid ${SEV[v.severity] || '#555'}`, borderRadius: 8, padding: 16, marginBottom: 12 }}>
              <strong style={{ color: SEV[v.severity] }}>[{v.severity?.toUpperCase()}]</strong> {v.name}
              {v.cve && <span style={{ color: '#888', fontSize: 12, marginLeft: 8 }}>{v.cve}</span>}
              <p style={{ margin: '8px 0 4px', color: '#ccc' }}>{v.description}</p>
              {v.evidence && <p style={{ margin: '4px 0', color: '#888', fontSize: 13 }}>🔍 Evidence: {v.evidence}</p>}
              <p style={{ margin: '4px 0 0', color: '#aaa', fontSize: 13 }}>💡 {v.recommendation}</p>
            </div>
          ))}
        </>
      )}

      {data.report && (
        <>
          <h3 style={{ marginTop: 24 }}>Full Report</h3>
          <div style={{ background: '#0d0d1a', padding: 24, borderRadius: 8, color: '#ccc', lineHeight: 1.7 }}>
            <ReactMarkdown>{data.report}</ReactMarkdown>
          </div>
        </>
      )}
    </div>
  );
}

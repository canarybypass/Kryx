import ReactMarkdown from 'react-markdown';

const SEV = { critical: '#ff0040', high: '#e94560', medium: '#ffd166', low: '#06d6a0' };

function severityCard(severity) {
  return {
    border: '1px solid ' + (SEV[severity] || '#555'),
    borderRadius: 8,
    padding: 16,
    marginBottom: 12,
    background: '#0d0d1a',
  };
}

export default function Results({ data }) {
  if (!data) return null;

  const vulns = data.vulnerabilities || [];
  const chains = data.attack_chains || [];
  const stats = data.stats || {};

  return (
    <div style={{ marginTop: 32 }}>
      <h2 style={{ color: '#e94560' }}>Target: {data.target}</h2>

      {data.summary && <p style={{ color: '#ccc', lineHeight: 1.6, marginTop: 12 }}>{data.summary}</p>}

      {Object.keys(stats).length > 0 && (
        <div style={s.statsRow}>
          <span style={s.stat}>Findings: {stats.total_findings}</span>
          <span style={s.stat}>Validated: {stats.validated}</span>
          <span style={s.stat}>Chains: {stats.chains}</span>
        </div>
      )}

      {chains.length > 0 && (
        <>
          <h3 style={{ color: '#ffd166', marginTop: 24 }}>Attack Chains ({chains.length})</h3>
          {chains.map((c, i) => (
            <div key={i} style={severityCard(c.severity)}>
              <div style={{ marginBottom: 8 }}>
                <strong style={{ color: SEV[c.severity] }}>[{c.severity ? c.severity.toUpperCase() : 'UNKNOWN'}]</strong>
                <span style={{ marginLeft: 12 }}>{c.name}</span>
              </div>
              {(c.steps || []).map((step, j) => (
                <div key={j} style={{ color: '#aaa', fontSize: 13, marginBottom: 4 }}>
                  {step.step}. {step.action} → {step.result}
                </div>
              ))}
              {c.final_impact && <p style={{ color: '#ffd166', fontSize: 13, margin: '8px 0 0' }}>Impact: {c.final_impact}</p>}
            </div>
          ))}
        </>
      )}

      {vulns.length > 0 && (
        <>
          <h3 style={{ marginTop: 24 }}>Vulnerabilities ({vulns.length})</h3>
          {vulns.map((v, i) => (
            <div key={i} style={severityCard(v.severity)}>
              <div style={{ marginBottom: 4 }}>
                <strong style={{ color: SEV[v.severity] }}>[{v.severity ? v.severity.toUpperCase() : 'UNKNOWN'}]</strong> {v.name}
                {v.cve && <span style={{ color: '#888', fontSize: 12, marginLeft: 8 }}>{v.cve}</span>}
                {v.validated && <span style={{ color: '#06d6a0', fontSize: 12, marginLeft: 8 }}>VERIFIED</span>}
              </div>
              <p style={{ margin: '8px 0 4px', color: '#ccc' }}>{v.description}</p>
              {v.evidence && <p style={{ margin: '4px 0', color: '#888', fontSize: 13 }}>Evidence: {v.evidence}</p>}
              <p style={{ margin: '4px 0 0', color: '#aaa', fontSize: 13 }}>{v.recommendation}</p>
            </div>
          ))}
        </>
      )}

      {data.report && (
        <>
          <h3 style={{ marginTop: 24 }}>Full Report</h3>
          <div style={s.report}>
            <ReactMarkdown>{data.report}</ReactMarkdown>
          </div>
        </>
      )}
    </div>
  );
}

const s = {
  statsRow: {
    display: 'flex',
    gap: 24,
    marginTop: 16,
    padding: 12,
    background: '#0d0d1a',
    borderRadius: 8,
  },
  stat: {
    color: '#888',
    fontSize: 14,
  },
  report: {
    background: '#0d0d1a',
    padding: 24,
    borderRadius: 8,
    color: '#ccc',
    lineHeight: 1.7,
  },
};
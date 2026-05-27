export default function LiveProgress({ items }) {
  if (!items || items.length === 0) return null;

  const recent = items.slice(-20);

  return (
    <div style={styles.container}>
      {recent.map((item, i) => (
        <div key={i} style={{ ...styles.item, ...styles[item.type] }}>
          <span style={styles.ts}>{new Date(item.ts).toLocaleTimeString()}</span>
          <span>{item.text}</span>
        </div>
      ))}
    </div>
  );
}

const styles = {
  container: {
    maxHeight: 300,
    overflowY: 'auto',
    background: '#0d0d1a',
    borderRadius: 8,
    padding: 12,
    fontFamily: 'monospace',
    fontSize: 12,
    lineHeight: 1.6,
  },
  item: {
    padding: '2px 0',
    display: 'flex',
    gap: 8,
  },
  ts: {
    color: '#555',
    minWidth: 70,
    flexShrink: 0,
  },
  status: { color: '#ffd166' },
  hunter: { color: '#06d6a0' },
  info: { color: '#888' },
  error: { color: '#e94560' },
};
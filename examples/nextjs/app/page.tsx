import { getKeyStore } from '@/lib/keystore';

export default async function HomePage() {
  const keyStore = await getKeyStore();
  const secretKeys = keyStore.keys();
  const secretCount = keyStore.keys().length;

  return (
    <main style={{ maxWidth: '800px', margin: '0 auto' }}>
      <h1 style={{
        fontSize: '2.5rem',
        marginBottom: '0.5rem',
        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
        WebkitBackgroundClip: 'text',
        WebkitTextFillColor: 'transparent',
      }}>
        🔐 Secret Keystore Demo
      </h1>

      <p style={{ color: '#888', marginBottom: '2rem' }}>
        Next.js application with secure secret management
      </p>

      <div style={{
        background: '#1a1a1a',
        borderRadius: '12px',
        padding: '1.5rem',
        marginBottom: '1.5rem',
        border: '1px solid #333',
      }}>
        <h2 style={{ margin: '0 0 1rem 0', fontSize: '1.25rem' }}>
          Keystore Status
        </h2>
        <div style={{ display: 'flex', gap: '2rem' }}>
          <div>
            <div style={{ color: '#888', fontSize: '0.875rem' }}>Secrets Loaded</div>
            <div style={{ fontSize: '2rem', fontWeight: 'bold', color: '#22c55e' }}>
              {secretCount}
            </div>
          </div>
          <div>
            <div style={{ color: '#888', fontSize: '0.875rem' }}>Status</div>
            <div style={{ fontSize: '1rem', color: '#22c55e', marginTop: '0.5rem' }}>
              ✓ Initialized
            </div>
          </div>
        </div>
      </div>

      <div style={{
        background: '#1a1a1a',
        borderRadius: '12px',
        padding: '1.5rem',
        marginBottom: '1.5rem',
        border: '1px solid #333',
      }}>
        <h2 style={{ margin: '0 0 1rem 0', fontSize: '1.25rem' }}>
          Available Secret Keys
        </h2>
        {secretKeys.length > 0 ? (
          <ul style={{ margin: 0, paddingLeft: '1.5rem' }}>
            {secretKeys.map((key) => (
              <li key={key} style={{ marginBottom: '0.5rem' }}>
                <code style={{
                  background: '#2a2a2a',
                  padding: '0.25rem 0.5rem',
                  borderRadius: '4px',
                  fontSize: '0.875rem',
                }}>
                  {key}
                </code>
              </li>
            ))}
          </ul>
        ) : (
          <p style={{ color: '#888', margin: 0 }}>
            No secrets loaded. Run <code>npm run encrypt:keys</code> first.
          </p>
        )}
      </div>

      <div style={{
        background: '#1a1a1a',
        borderRadius: '12px',
        padding: '1.5rem',
        border: '1px solid #333',
      }}>
        <h2 style={{ margin: '0 0 1rem 0', fontSize: '1.25rem' }}>
          API Endpoints
        </h2>
        <ul style={{ margin: 0, paddingLeft: '1.5rem' }}>
          <li style={{ marginBottom: '0.5rem' }}>
            <a href="/api/secrets" style={{ color: '#667eea' }}>
              GET /api/secrets
            </a>
            {' '}- List all secret keys
          </li>
          <li style={{ marginBottom: '0.5rem' }}>
            <a href="/api/secrets/API_KEY" style={{ color: '#667eea' }}>
              GET /api/secrets/[key]
            </a>
            {' '}- Check specific secret (masked)
          </li>
        </ul>
      </div>

      <p style={{
        marginTop: '2rem',
        color: '#666',
        fontSize: '0.875rem',
        textAlign: 'center',
      }}>
        Secrets are decrypted via AWS KMS and stored securely in memory.
        <br />
        They are never exposed to the client or stored in process.env.
      </p>
    </main>
  );
}


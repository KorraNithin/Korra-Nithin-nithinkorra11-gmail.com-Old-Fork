import { useEffect, useState } from 'react';
import { api } from './api.js';

// Public route, /invite/:token. Deliberately does NOT use the token/cookie the accept
// call returns -- after a successful accept we hand back to Login (login-form), we do
// not auto-authenticate into the console. See DECISIONS.md.
export default function InviteAccept({ token, onDone }) {
  const [invite, setInvite] = useState(null);
  const [loadError, setLoadError] = useState(false);
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [submitError, setSubmitError] = useState(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    api(`/invites/${token}`)
      .then((data) => { if (!cancelled) setInvite(data); })
      .catch(() => { if (!cancelled) setLoadError(true); });
    return () => { cancelled = true; };
  }, [token]);

  async function submit(e) {
    e.preventDefault();
    setSubmitError(null);
    setBusy(true);
    try {
      await api(`/invites/${token}/accept`, { method: 'POST', body: { name, password } });
      onDone();
    } catch (err) {
      setSubmitError(err.message);
    } finally {
      setBusy(false);
    }
  }

  if (loadError) {
    return (
      <div style={styles.page}>
        <p data-testid="invite-error" role="alert" style={styles.error}>
          This invite link is no longer valid.
        </p>
      </div>
    );
  }

  if (!invite) return null;

  return (
    <div style={styles.page}>
      <form onSubmit={submit} style={styles.card}>
        <h1 style={{ margin: '0 0 8px' }}>Join {invite.orgName}</h1>
        <p style={{ margin: 0, color: '#555' }}>
          Role: <span data-testid="invite-role">{invite.role}</span>
        </p>
        <label style={styles.label}>
          Email
          <input data-testid="invite-email" value={invite.email} readOnly style={styles.input} />
        </label>
        <label style={styles.label}>
          Your name
          <input data-testid="invite-name" value={name} onChange={(e) => setName(e.target.value)} style={styles.input} />
        </label>
        <label style={styles.label}>
          Choose a password
          <input
            data-testid="invite-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={styles.input}
          />
        </label>
        <button data-testid="invite-submit" type="submit" disabled={busy} style={styles.button}>
          {busy ? 'Joining…' : 'Join'}
        </button>
        {submitError && <p role="alert" style={styles.error}>{submitError}</p>}
      </form>
    </div>
  );
}

const styles = {
  page: { display: 'flex', minHeight: '100vh', alignItems: 'center', justifyContent: 'center', background: '#f4f5f7', fontFamily: 'ui-sans-serif, system-ui, sans-serif' },
  card: { background: '#fff', padding: 32, borderRadius: 12, boxShadow: '0 1px 4px rgba(0,0,0,0.1)', width: 340, display: 'flex', flexDirection: 'column', gap: 14 },
  label: { display: 'flex', flexDirection: 'column', gap: 4, fontSize: 14, color: '#333' },
  input: { padding: '8px 10px', borderRadius: 6, border: '1px solid #ccc', fontSize: 14 },
  button: { padding: '10px 12px', borderRadius: 6, border: 'none', background: '#2455e6', color: '#fff', fontSize: 14, cursor: 'pointer' },
  error: { color: '#b3261e', fontSize: 13, margin: 0 },
};
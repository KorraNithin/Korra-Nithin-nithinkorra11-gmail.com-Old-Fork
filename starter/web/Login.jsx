import { useState } from 'react';
import { api, setToken } from './api.js';

// UI-INVENTORY.md §4: the error is announced (role="alert"), stays on screen until the
// next attempt, carries data-error-code, and never improves on the server's message --
// an unknown account and a wrong password read identically, because telling them apart
// is an account-enumeration oracle.
export default function Login({ onSuccess }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setError(null);

    if (!email.trim() || !password) {
      setError({ code: 'VALIDATION', message: 'email and password are both required' });
      return;
    }

    setBusy(true);
    try {
      const payload = await api('/auth/login', { method: 'POST', body: { email: email.trim(), password } });
      setToken(payload.token);
      onSuccess(payload);
    } catch (err) {
      setError({ code: err.code, message: err.message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div data-testid="login-form" style={styles.page}>
      <form onSubmit={submit} style={styles.card}>
        <h1 style={styles.title}>RemoteOps</h1>
        <label style={styles.label}>
          Email
          <input
            data-testid="login-email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            style={styles.input}
          />
        </label>
        <label style={styles.label}>
          Password
          <input
            data-testid="login-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={styles.input}
          />
        </label>
        <button data-testid="login-submit" type="submit" disabled={busy} style={styles.button}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
        {error && (
          <p data-testid="login-error" data-error-code={error.code} role="alert" style={styles.error}>
            {error.message}
          </p>
        )}
      </form>
    </div>
  );
}

const styles = {
  page: { display: 'flex', minHeight: '100vh', alignItems: 'center', justifyContent: 'center', background: '#f4f5f7', fontFamily: 'ui-sans-serif, system-ui, sans-serif' },
  card: { background: '#fff', padding: 32, borderRadius: 12, boxShadow: '0 1px 4px rgba(0,0,0,0.1)', width: 320, display: 'flex', flexDirection: 'column', gap: 14 },
  title: { margin: '0 0 8px' },
  label: { display: 'flex', flexDirection: 'column', gap: 4, fontSize: 14, color: '#333' },
  input: { padding: '8px 10px', borderRadius: 6, border: '1px solid #ccc', fontSize: 14 },
  button: { padding: '10px 12px', borderRadius: 6, border: 'none', background: '#2455e6', color: '#fff', fontSize: 14, cursor: 'pointer' },
  error: { color: '#b3261e', fontSize: 13, margin: 0 },
};
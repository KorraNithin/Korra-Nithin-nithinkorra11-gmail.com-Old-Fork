import { useEffect, useRef, useState } from 'react';
import { api, setToken } from './api.js';
import Login from './Login.jsx';
import InviteAccept from './InviteAccept.jsx';
import Console from './Console.jsx';

// No router is installed (none in package.json), so routing is deliberately this
// simple: read the path ONCE on the true initial mount, and otherwise move between
// screens with plain React state, never a full navigation. That distinction matters:
// a REAL reload re-runs the session-restore effect below (so "reload restores the
// session from the refresh cookie" works); a client-side screen change after
// redeeming an invite must NOT re-trigger it (so a freshly-set refresh cookie from
// accept() doesn't silently auto-log the person in when the UI wants to show the
// login form next). See DECISIONS.md.
export default function App() {
  const [screen, setScreen] = useState('loading'); // 'loading' | 'login' | 'invite' | 'console'
  const [auth, setAuth] = useState(null);
  const [inviteToken, setInviteToken] = useState(null);
  // /auth/refresh ROTATES the refresh cookie: the token it was called with becomes
  // invalid the moment it responds. If this effect ever ran twice for the same mount
  // (StrictMode double-invokes effects), both calls would race on the SAME original
  // cookie -- whichever commits first is fine, but the second now presents an
  // already-rotated token, which correctly trips the reuse-detection in
  // /auth/refresh (AUTH-DATA-MODEL.md §10) and revokes the whole family, INCLUDING
  // the one the first call just issued. The first call's success already landed in
  // state; the second call's rejection lands after it and wins, flipping the screen
  // back to 'login'. A ref guard makes the attempt run at most once no matter how
  // many times the effect itself fires.
  const attemptedRestore = useRef(false);

  useEffect(() => {
    const match = window.location.pathname.match(/^\/invite\/(.+)$/);
    if (match) {
      setInviteToken(match[1]);
      setScreen('invite');
      return;
    }

    if (attemptedRestore.current) return;
    attemptedRestore.current = true;

    api('/auth/refresh', { method: 'POST' })
      .then((payload) => {
        setToken(payload.token);
        setAuth(payload);
        setScreen('console');
      })
      .catch(() => setScreen('login'));
  }, []);

  function handleLoginSuccess(payload) {
    setAuth(payload);
    setScreen('console');
  }

  function handleInviteDone() {
    window.history.replaceState({}, '', '/');
    setScreen('login');
  }

  function handleLogout() {
    setToken(null);
    setAuth(null);
    setScreen('login');
  }

  if (screen === 'loading') return null;
  if (screen === 'invite') return <InviteAccept token={inviteToken} onDone={handleInviteDone} />;
  if (screen === 'console' && auth) return <Console auth={auth} setAuth={setAuth} onLogout={handleLogout} />;
  return <Login onSuccess={handleLoginSuccess} />;
}
import { useEffect, useState } from 'react';
import { api, setToken } from './api.js';

// UI-INVENTORY.md §1: present or absent, never disabled. This is the ONE place that
// decision is made, and it reads a permissions map the SERVER computed -- there is no
// role-to-permission table in this file, on purpose. `permissions` here is either the
// org-level map (auth.permissions) for org-scoped actions, or a per-device map
// (device.permissions) for device-scoped actions -- same shape either way.
function Gated({ permKey, permissions, testId, onClick, children, extraAttrs }) {
  if (permissions?.[permKey]?.effect !== 'allow') return null;
  return (
    <button data-testid={testId} data-permission={permKey} data-state="unlocked" onClick={onClick} {...extraAttrs}>
      {children}
    </button>
  );
}

// Deterministic, not hardcoded: any theme string (including a personalised org we've
// never seen) gets a distinct, consistent background colour, satisfying "switching
// orgs measurably changes the rendered appearance" without a fixed palette.
function themeBackground(theme) {
  let hash = 0;
  for (const ch of String(theme)) hash = (hash * 31 + ch.charCodeAt(0)) >>> 0;
  return `hsl(${hash % 360}, 60%, 94%)`;
}

const CARD_LABELS = { devices: 'Devices', people: 'People', grants: 'Grants', sessions: 'Sessions', audit: 'Audit', admin: 'Admin' };

export default function Console({ auth, setAuth, onLogout }) {
  const [view, setView] = useState('devices');
  const perms = auth.permissions;
  const has = (key) => perms[key]?.effect === 'allow';

  const cards = [
    { key: 'devices', show: has('device:list') },
    { key: 'people', show: has('user:read') },
    { key: 'grants', show: has('user:read') },
    { key: 'sessions', show: has('session:view') },
    { key: 'audit', show: has('audit:read') },
    { key: 'admin', show: has('org:update') || has('org:delete') },
  ];

  async function switchOrg(orgId) {
    const payload = await api('/auth/token', { method: 'POST', body: { orgId } });
    setToken(payload.token);
    setAuth(payload);
    setView('devices');
  }

  async function createOrg() {
    const name = window.prompt('Organization name?');
    if (!name) return;
    const created = await api('/orgs', { method: 'POST', body: { name } });
    await switchOrg(created.id);
  }

  const currentOrg = auth.orgs.find((o) => o.id === auth.orgId);
  const theme = currentOrg?.theme ?? 'slate';

  return (
    <div
      data-testid="app-shell"
      data-org-id={auth.orgId}
      data-org-theme={theme}
      style={{ ...styles.shell, backgroundColor: themeBackground(theme) }}
    >
      <aside style={styles.sidebar}>
        <div style={styles.orgList}>
          {auth.orgs.map((o) => (
            <button
              key={o.id}
              data-testid="org-option"
              data-org-id={o.id}
              onClick={() => switchOrg(o.id)}
              style={{ ...styles.orgButton, fontWeight: o.id === auth.orgId ? 700 : 400 }}
            >
              {o.name}
            </button>
          ))}
          <button data-testid="create-org" onClick={createOrg} style={styles.orgButton}>
            + New organization
          </button>
        </div>

        <nav style={styles.nav}>
          {cards.filter((c) => c.show).map((c) => (
            <button
              key={c.key}
              data-testid={`nav-${c.key}`}
              onClick={() => setView(c.key)}
              style={{ ...styles.navButton, background: view === c.key ? '#fff' : 'transparent' }}
            >
              {CARD_LABELS[c.key]}
            </button>
          ))}
        </nav>

        <div style={styles.footer}>
          <div>Signed in as {auth.user.name}</div>
          <div>
            Role: <span data-testid="active-role">{auth.role}</span>
          </div>
          <button data-testid="sign-out" onClick={onLogout} style={styles.signOut}>
            Sign out
          </button>
        </div>
      </aside>

      <main style={styles.main}>
        {view === 'devices' && has('device:list') && <DevicesView auth={auth} />}
        {view === 'people' && has('user:read') && <PeopleView auth={auth} />}
        {view === 'grants' && has('user:read') && <GrantsView auth={auth} />}
        {view === 'sessions' && has('session:view') && <SessionsView auth={auth} />}
        {view === 'audit' && has('audit:read') && <AuditView auth={auth} />}
        {view === 'admin' && (has('org:update') || has('org:delete')) && (
          <AdminView auth={auth} onOrgChanged={(payload) => setAuth(payload)} onOrgDeleted={onLogout} />
        )}
      </main>
    </div>
  );
}

// ============================================================================
// DEVICES
// ============================================================================

function DevicesView({ auth }) {
  const [devices, setDevices] = useState(null);
  const has = (key) => auth.permissions[key]?.effect === 'allow';

  async function load() {
    setDevices(null);
    const data = await api(`/orgs/${auth.orgId}/devices`);
    setDevices(data.devices);
  }
  useEffect(() => { load(); }, [auth.orgId]); // eslint-disable-line react-hooks/exhaustive-deps

  async function addDevice() {
    const name = window.prompt('Device name?');
    if (!name) return;
    const kind = window.prompt('Kind (macos / windows / linux / android / ios)?', 'macos');
    await api(`/orgs/${auth.orgId}/devices`, { method: 'POST', body: { name, kind } });
    await load();
  }

  async function startSession(deviceId, mode) {
    try {
      await api(`/orgs/${auth.orgId}/sessions`, { method: 'POST', body: { deviceId, mode } });
      alert(`${mode} session started.`);
    } catch (err) {
      alert(err.message);
    }
  }

  async function renameDevice(device) {
    const name = window.prompt('New name?', device.name);
    if (!name) return;
    await api(`/orgs/${auth.orgId}/devices/${device.id}`, { method: 'PATCH', body: { name } });
    await load();
  }

  async function decommission(deviceId) {
    if (!window.confirm('Decommission this device?')) return;
    await api(`/orgs/${auth.orgId}/devices/${deviceId}`, { method: 'DELETE' });
    await load();
  }

  if (devices === null) return <p>Loading…</p>;

  return (
    <section>
      <header style={styles.viewHeader}>
        <h2 style={styles.viewTitle}>Devices</h2>
        <Gated permKey="device:provision" permissions={auth.permissions} testId="add-device" onClick={addDevice}>
          Add device
        </Gated>
      </header>

      {devices.length === 0 ? (
        <p data-testid="devices-empty">No devices yet.</p>
      ) : (
        <table style={styles.table}>
          <tbody>
            {devices.map((d) => (
              <tr data-testid="device-row" data-device-id={d.id} key={d.id} style={styles.row}>
                <td style={styles.cell}>
                  <strong>{d.name}</strong>
                  <div style={styles.muted}>{d.kind} · {d.online ? 'online' : 'offline'}</div>
                </td>
                <td style={styles.cell}>
                  <Gated permKey="device:view" permissions={d.permissions} testId="start-view" onClick={() => startSession(d.id, 'view')}>View</Gated>{' '}
                  <Gated permKey="device:control" permissions={d.permissions} testId="start-control" onClick={() => startSession(d.id, 'control')}>Control</Gated>{' '}
                  <Gated permKey="device:terminal" permissions={d.permissions} testId="start-terminal" onClick={() => startSession(d.id, 'terminal')}>Terminal</Gated>{' '}
                  <Gated permKey="device:file_transfer" permissions={d.permissions} testId="transfer-files" onClick={() => alert('File transfer is not implemented in this build.')}>Transfer files</Gated>{' '}
                  <Gated permKey="device:update" permissions={d.permissions} testId="rename-device" onClick={() => renameDevice(d)}>Rename</Gated>{' '}
                  <Gated permKey="device:provision" permissions={d.permissions} testId="decommission-device" onClick={() => decommission(d.id)}>Decommission</Gated>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

// ============================================================================
// PEOPLE
// ============================================================================

function PeopleView({ auth }) {
  const [members, setMembers] = useState(null);
  const [roles, setRoles] = useState([]);

  async function load() {
    setMembers(null);
    const [m, r] = await Promise.all([api(`/orgs/${auth.orgId}/members`), api('/roles')]);
    setMembers(m.members);
    setRoles(r.roles);
  }
  useEffect(() => { load(); }, [auth.orgId]); // eslint-disable-line react-hooks/exhaustive-deps

  async function invite() {
    const email = window.prompt('Email to invite?');
    if (!email) return;
    const role = window.prompt(`Role (${roles.map((r) => r.key).join(' / ')})?`, 'viewer');
    if (!role) return;
    try {
      const created = await api(`/orgs/${auth.orgId}/invites`, { method: 'POST', body: { email, role } });
      alert(`Invite created. Link: /invite/${created.inviteToken}`);
    } catch (err) {
      alert(err.message);
    }
  }

  async function changeRole(userId, role) {
    try {
      await api(`/orgs/${auth.orgId}/members/${userId}`, { method: 'PATCH', body: { role } });
      await load();
    } catch (err) {
      alert(err.message);
    }
  }

  async function toggleSuspend(member) {
    if (member.status === 'suspended') {
      await api(`/orgs/${auth.orgId}/members/${member.userId}/suspend`, { method: 'DELETE' });
    } else {
      await api(`/orgs/${auth.orgId}/members/${member.userId}/suspend`, { method: 'POST' });
    }
    await load();
  }

  async function removeMember(userId) {
    if (!window.confirm('Remove this member?')) return;
    await api(`/orgs/${auth.orgId}/members/${userId}`, { method: 'DELETE' });
    await load();
  }

  if (members === null) return <p>Loading…</p>;

  return (
    <section>
      <header style={styles.viewHeader}>
        <h2 style={styles.viewTitle}>People</h2>
        <Gated permKey="user:invite" permissions={auth.permissions} testId="invite-user" onClick={invite}>Invite</Gated>
      </header>
      <table style={styles.table}>
        <tbody>
          {members.map((m) => (
            <tr data-testid="user-row" data-user-id={m.userId} key={m.userId} style={styles.row}>
              <td style={styles.cell}>
                <strong>{m.name}</strong>
                <div style={styles.muted}>{m.email} · {m.status}</div>
              </td>
              <td style={styles.cell}>
                {auth.permissions['user:role:update']?.effect === 'allow' && m.userId !== auth.user.id ? (
                  <select data-testid="role-select" value={m.role} onChange={(e) => changeRole(m.userId, e.target.value)}>
                    {roles.map((r) => <option key={r.key} value={r.key}>{r.key}</option>)}
                  </select>
                ) : (
                  <span>{m.role}</span>
                )}
                {' '}
                <Gated permKey="user:remove" permissions={auth.permissions} testId="suspend-user" onClick={() => toggleSuspend(m)}>
                  {m.status === 'suspended' ? 'Reinstate' : 'Suspend'}
                </Gated>{' '}
                <Gated permKey="user:remove" permissions={auth.permissions} testId="remove-user" onClick={() => removeMember(m.userId)}>Remove</Gated>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

// ============================================================================
// GRANTS
// ============================================================================

function GrantsView({ auth }) {
  const [grants, setGrants] = useState(null);
  const [members, setMembers] = useState([]);
  const [devices, setDevices] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ userId: '', deviceId: '', effect: 'allow', permissions: [] });

  async function load() {
    setGrants(null);
    const [g, m, d] = await Promise.all([
      api(`/orgs/${auth.orgId}/grants`),
      api(`/orgs/${auth.orgId}/members`),
      api(`/orgs/${auth.orgId}/devices`),
    ]);
    setGrants(g.grants);
    setMembers(m.members);
    setDevices(d.devices);
  }
  useEffect(() => { load(); }, [auth.orgId]); // eslint-disable-line react-hooks/exhaustive-deps

  function togglePerm(key) {
    setForm((f) => ({
      ...f,
      permissions: f.permissions.includes(key) ? f.permissions.filter((p) => p !== key) : [...f.permissions, key],
    }));
  }

  async function submitGrant(e) {
    e.preventDefault();
    try {
      await api(`/orgs/${auth.orgId}/grants`, {
        method: 'POST',
        body: {
          userId: form.userId,
          deviceId: form.deviceId || null,
          effect: form.effect,
          permissions: form.permissions,
        },
      });
      setShowForm(false);
      setForm({ userId: '', deviceId: '', effect: 'allow', permissions: [] });
      await load();
    } catch (err) {
      alert(err.message);
    }
  }

  async function revoke(id) {
    await api(`/orgs/${auth.orgId}/grants/${id}`, { method: 'DELETE' });
    await load();
  }

  if (grants === null) return <p>Loading…</p>;

  // The catalogue, read from what the server already resolved for us -- every
  // permission key appears in auth.permissions regardless of allow/deny, so this
  // never hardcodes the permission list (personalisation-safe).
  const catalogue = Object.keys(auth.permissions);

  return (
    <section>
      <header style={styles.viewHeader}>
        <h2 style={styles.viewTitle}>Grants</h2>
        <Gated permKey="grant:create" permissions={auth.permissions} testId="new-grant" onClick={() => setShowForm(true)}>New grant</Gated>
      </header>

      {showForm && (
        <form onSubmit={submitGrant} style={styles.grantForm}>
          <label>
            User
            <select data-testid="grant-user" value={form.userId} onChange={(e) => setForm((f) => ({ ...f, userId: e.target.value }))} required>
              <option value="" disabled>choose…</option>
              {members.map((m) => <option key={m.userId} value={m.userId}>{m.name}</option>)}
            </select>
          </label>
          <label>
            Device (blank = org-wide)
            <select data-testid="grant-device" value={form.deviceId} onChange={(e) => setForm((f) => ({ ...f, deviceId: e.target.value }))}>
              <option value="">org-wide</option>
              {devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
            </select>
          </label>
          <label>
            Effect
            <select data-testid="grant-effect" value={form.effect} onChange={(e) => setForm((f) => ({ ...f, effect: e.target.value }))}>
              <option value="allow">allow</option>
              <option value="deny">deny</option>
            </select>
          </label>
          <fieldset style={styles.permGrid}>
            {catalogue.map((key) => (
              <label key={key} style={styles.permCheck}>
                <input
                  type="checkbox"
                  data-permission-key={key}
                  checked={form.permissions.includes(key)}
                  onChange={() => togglePerm(key)}
                />
                {key}
              </label>
            ))}
          </fieldset>
          <button data-testid="grant-submit" type="submit">Create grant</button>
        </form>
      )}

      <table style={styles.table}>
        <tbody>
          {grants.map((g) => (
            <tr data-testid="grant-row" data-effect={g.effect} key={g.id} style={styles.row}>
              <td style={styles.cell}>
                <div>{g.userId}{g.deviceId ? ` · ${g.deviceId}` : ' · org-wide'}</div>
                <div style={styles.muted}>{g.effect}: {g.permissions.join(', ')}</div>
              </td>
              <td style={styles.cell}>
                <Gated permKey="grant:revoke" permissions={auth.permissions} testId="revoke-grant" onClick={() => revoke(g.id)}>Revoke</Gated>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

// ============================================================================
// SESSIONS
// ============================================================================

function SessionsView({ auth }) {
  const [sessions, setSessions] = useState(null);
  const [devices, setDevices] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ deviceId: '', mode: 'view' });

  async function load() {
    setSessions(null);
    const [s, d] = await Promise.all([api(`/orgs/${auth.orgId}/sessions`), api(`/orgs/${auth.orgId}/devices`)]);
    setSessions(s.sessions);
    setDevices(d.devices);
  }
  useEffect(() => { load(); }, [auth.orgId]); // eslint-disable-line react-hooks/exhaustive-deps

  async function startSession(e) {
    e.preventDefault();
    try {
      await api(`/orgs/${auth.orgId}/sessions`, { method: 'POST', body: form });
      setShowForm(false);
      await load();
    } catch (err) {
      alert(err.message);
    }
  }

  async function stop(session) {
    await api(`/sessions/${session.id}`, { method: 'DELETE' });
    await load();
  }

  if (sessions === null) return <p>Loading…</p>;

  return (
    <section>
      <header style={styles.viewHeader}>
        <h2 style={styles.viewTitle}>Sessions</h2>
        <Gated permKey="session:start" permissions={auth.permissions} testId="new-session" onClick={() => setShowForm(true)}>Start a session</Gated>
      </header>

      {showForm && (
        <form onSubmit={startSession} style={styles.grantForm}>
          <label>
            Device
            <select value={form.deviceId} onChange={(e) => setForm((f) => ({ ...f, deviceId: e.target.value }))} required>
              <option value="" disabled>choose…</option>
              {devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
            </select>
          </label>
          <label>
            Mode
            <select value={form.mode} onChange={(e) => setForm((f) => ({ ...f, mode: e.target.value }))}>
              <option value="view">view</option>
              <option value="control">control</option>
              <option value="terminal">terminal</option>
            </select>
          </label>
          <button type="submit">Start</button>
        </form>
      )}

      <table style={styles.table}>
        <tbody>
          {sessions.map((s) => {
            const isOwn = s.user_id === auth.user.id;
            const canStop = isOwn || auth.permissions['session:terminate']?.effect === 'allow';
            return (
              <tr data-testid="session-row" data-session-id={s.id} key={s.id} style={styles.row}>
                <td style={styles.cell}>
                  <div>{s.device_id} · {s.mode}</div>
                  <div style={styles.muted}>{s.state}{s.end_reason ? ` (${s.end_reason})` : ''}</div>
                </td>
                <td style={styles.cell}>
                  {s.state === 'active' && canStop && (
                    <button data-testid="stop-session" data-state="unlocked" onClick={() => stop(s)}>Stop</button>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </section>
  );
}

// ============================================================================
// AUDIT
// ============================================================================

function AuditView({ auth }) {
  const [events, setEvents] = useState(null);

  useEffect(() => {
    setEvents(null);
    api(`/orgs/${auth.orgId}/audit`).then((d) => setEvents(d.events));
  }, [auth.orgId]);

  if (events === null) return <p>Loading…</p>;

  return (
    <section>
      <h2 style={styles.viewTitle}>Audit</h2>
      <table style={styles.table}>
        <tbody>
          {events.map((e) => (
            <tr data-testid="audit-row" key={e.id} style={styles.row}>
              <td style={styles.cell}>
                <div>{e.action} · {e.result}</div>
                <div style={styles.muted}>{e.at} {e.reason_code ? `· ${e.reason_code}` : ''}</div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

// ============================================================================
// ADMIN
// ============================================================================

function AdminView({ auth, onOrgChanged, onOrgDeleted }) {
  async function rename() {
    const name = window.prompt('New organization name?');
    if (!name) return;
    await api(`/orgs/${auth.orgId}`, { method: 'PATCH', body: { name } });
    const refreshed = await api('/auth/token', { method: 'POST', body: { orgId: auth.orgId } });
    onOrgChanged(refreshed);
  }

  async function del() {
    if (!window.confirm('Delete this organization? This cannot be undone.')) return;
    await api(`/orgs/${auth.orgId}`, { method: 'DELETE' });
    onOrgDeleted();
  }

  return (
    <section>
      <h2 style={styles.viewTitle}>Admin</h2>
      <Gated permKey="org:update" permissions={auth.permissions} testId="rename-org" onClick={rename}>Rename organization</Gated>{' '}
      <Gated permKey="org:delete" permissions={auth.permissions} testId="delete-org" onClick={del}>Delete organization</Gated>
    </section>
  );
}

// ============================================================================

const styles = {
  shell: { display: 'flex', minHeight: '100vh', fontFamily: 'ui-sans-serif, system-ui, sans-serif' },
  sidebar: { width: 220, padding: 16, display: 'flex', flexDirection: 'column', gap: 16, borderRight: '1px solid rgba(0,0,0,0.08)' },
  orgList: { display: 'flex', flexDirection: 'column', gap: 4 },
  orgButton: { textAlign: 'left', padding: '6px 8px', border: 'none', background: 'transparent', cursor: 'pointer', borderRadius: 6 },
  nav: { display: 'flex', flexDirection: 'column', gap: 4, flex: 1 },
  navButton: { textAlign: 'left', padding: '8px 10px', border: 'none', cursor: 'pointer', borderRadius: 6 },
  footer: { fontSize: 13, borderTop: '1px solid rgba(0,0,0,0.08)', paddingTop: 12, display: 'flex', flexDirection: 'column', gap: 6 },
  signOut: { alignSelf: 'flex-start', border: 'none', background: 'transparent', color: '#b3261e', cursor: 'pointer', padding: 0 },
  main: { flex: 1, padding: 24, overflow: 'auto' },
  viewHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 },
  viewTitle: { margin: 0 },
  table: { width: '100%', borderCollapse: 'collapse' },
  row: { borderBottom: '1px solid rgba(0,0,0,0.06)' },
  cell: { padding: '8px 4px', verticalAlign: 'top' },
  muted: { fontSize: 12, color: '#777' },
  grantForm: { display: 'flex', flexDirection: 'column', gap: 8, padding: 16, background: 'rgba(255,255,255,0.6)', borderRadius: 8, marginBottom: 16, maxWidth: 420 },
  permGrid: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 4, border: 'none', padding: 0, margin: 0 },
  permCheck: { fontSize: 13, display: 'flex', alignItems: 'center', gap: 4 },
};
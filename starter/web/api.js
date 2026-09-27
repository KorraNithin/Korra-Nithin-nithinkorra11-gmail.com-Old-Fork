// The access token lives here, in a module-level variable -- in memory only. Never
// localStorage, never sessionStorage (tests/ui.spec.js checks both are empty). The
// refresh token is an httpOnly cookie the browser sends automatically; JS never sees it.

let accessToken = null;
export const setToken = (t) => { accessToken = t; };
export const getToken = () => accessToken;

export class ApiError extends Error {
  constructor(status, code, message, reason) {
    super(message);
    this.status = status;
    this.code = code;
    this.reason = reason;
  }
}

export async function api(path, { method = 'GET', body } = {}) {
  const headers = { 'content-type': 'application/json' };
  if (accessToken) headers.authorization = `Bearer ${accessToken}`;

  const res = await fetch(`/v1${path}`, {
    method,
    headers,
    credentials: 'same-origin', // send/receive the httpOnly refresh cookie
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  const text = await res.text();
  const json = text ? JSON.parse(text) : {};

  if (!res.ok) {
    const err = json.error ?? {};
    throw new ApiError(res.status, err.code ?? 'ERROR', err.message ?? 'request failed', err.reason ?? null);
  }
  return json;
}
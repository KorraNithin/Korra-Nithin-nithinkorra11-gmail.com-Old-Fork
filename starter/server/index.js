import http from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createRouter } from './router.js';
import { openDatabase } from './db.js';
import { send, sendError, readJson, notFound } from './http.js';
import { authenticate } from './context.js';
import { registerRoutes } from './routes/index.js';

const DEV = process.env.NODE_ENV !== 'production';
const PORT = Number(process.env.PORT ?? 8080);
const SECRET = process.env.JWT_SECRET ?? 'dev-secret-change-me';
// fileURLToPath, not `.pathname` -- on Windows a file:// URL's .pathname keeps a
// leading slash before the drive letter ('/C:/Rhinostream/...'), which join() then
// mishandles, silently pointing every static file lookup at a path that doesn't
// exist. In production this means index.html and the JS bundle 404 on every
// request -- the page loads with an empty <div id="root">, no error, nothing ever
// renders. This is the exact same bug we found and fixed in scripts/load-db.js,
// just in the starter's server/index.js this time -- invisible on Linux/macOS,
// where .pathname doesn't have a drive letter to duplicate.
const DIST = fileURLToPath(new URL('../dist/', import.meta.url));

const db = openDatabase();
const router = createRouter();
registerRoutes(router, { db, secret: SECRET });

// Routes reachable without a token. Everything else requires a valid JWT.
const PUBLIC_ROUTES = new Set([
  'POST /v1/auth/login',
  'POST /v1/auth/refresh',
  'GET /v1/invites/:token',
  'POST /v1/invites/:token/accept',
]);

// ---------------------------------------------------------------------------
// The request pipeline. Read this top to bottom and you know how the app works.
// ---------------------------------------------------------------------------
async function handleApi(req, res, url) {
  const requestId = `req_${crypto.randomUUID().slice(0, 8)}`;

  try {
    const hit = router.match(req.method, url.pathname);
    if (!hit) throw notFound();

    const ctx = { db, secret: SECRET, requestId, query: url.searchParams, body: {}, req };

    const key = `${req.method} ${hit.pattern}`;
    if (!PUBLIC_ROUTES.has(key)) {
      Object.assign(ctx, authenticate(db, SECRET)(req, hit.params));
    }

    if (req.method !== 'GET' && req.method !== 'DELETE') {
      ctx.body = await readJson(req);
    }

    await hit.handler(ctx, hit.params, res);
  } catch (err) {
    sendError(res, err, requestId);
  }
}

// ---------------------------------------------------------------------------
// Production static files. ~25 lines, no dependency, no surprises.
// ---------------------------------------------------------------------------
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
};

async function serveStatic(req, res, url) {
  // normalize() collapses '..' so a crafted path cannot escape dist/.
  const rel = normalize(decodeURIComponent(url.pathname)).replace(/^(\.\.[/\\])+/, '');
  let file = join(DIST, rel);

  try {
    const info = await stat(file);
    if (info.isDirectory()) file = join(file, 'index.html');
  } catch {
    file = join(DIST, 'index.html'); // SPA fallback: let the client router handle it
  }

  try {
    const body = await readFile(file);
    res.writeHead(200, {
      'content-type': MIME[extname(file)] ?? 'application/octet-stream',
      'content-length': body.length,
    });
    res.end(body);
  } catch {
    send(res, 404, { error: { code: 'NOT_FOUND', message: 'not found', reason: null, requestId: null } });
  }
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
let vite = null;
if (DEV) {
  const { createServer } = await import('vite');
  vite = await createServer({ server: { middlewareMode: true }, appType: 'spa' });
  console.log('vite middleware attached (HMR enabled)');
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (url.pathname === '/v1' || url.pathname.startsWith('/v1/')) {
    return handleApi(req, res, url);
  }

  if (vite) return vite.middlewares(req, res, () => send(res, 404, { error: { code: 'NOT_FOUND' } }));
  return serveStatic(req, res, url);
});

server.listen(PORT, () => {
  console.log(`RemoteOps on http://localhost:${PORT}  (${DEV ? 'development' : 'production'})`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    server.close(() => {
      db.close();
      process.exit(0);
    });
  });
}
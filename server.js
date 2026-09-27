require('dotenv').config();

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');

const app = express();
app.set('trust proxy', 1);

const PORT = Number(process.env.PORT || 8080);
const NODE_ENV = process.env.NODE_ENV || 'development';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const ADMIN_TOKEN_SECRET = process.env.ADMIN_TOKEN_SECRET || crypto.randomBytes(32).toString('hex');
const TEMPMAIL_API_BASE = (process.env.TEMPMAIL_API_BASE || 'https://tempmail.id.vn/api/v2').replace(/\/$/, '');
const LINK4M_API_BASE = (process.env.LINK4M_API_BASE || 'https://link4m.co/api-shorten/v2').replace(/\/$/, '');

const allowedOrigins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map((v) => v.trim())
  .filter(Boolean);

const corsOptions = {
  origin(origin, callback) {
    if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('CORS origin not allowed'));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'Cache-Control'],
  credentials: false
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: false, limit: '32kb' }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

const rateBuckets = new Map();
function rateLimit({ windowMs, max }) {
  return (req, res, next) => {
    const now = Date.now();
    const key = `${req.ip}:${req.path}`;
    let bucket = rateBuckets.get(key);
    if (!bucket || now - bucket.start >= windowMs) {
      bucket = { start: now, count: 0 };
    }
    bucket.count += 1;
    rateBuckets.set(key, bucket);
    if (bucket.count > max) {
      return res.status(429).json({ ok: false, error: 'TOO_MANY_REQUESTS', message: 'Thao tác quá nhanh. Vui lòng thử lại sau.' });
    }
    return next();
  };
}

let firebaseConfigured = false;
let db = null;
let firebaseInitError = null;

function initFirebase() {
  if (firebaseConfigured) return;
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (!raw) {
    firebaseInitError = 'Missing FIREBASE_SERVICE_ACCOUNT';
    return;
  }

  try {
    const serviceAccount = JSON.parse(raw);
    initializeApp({
      credential: cert(serviceAccount),
      projectId: process.env.FIREBASE_PROJECT_ID || serviceAccount.project_id || 'tdmdev-1ea99'
    });
    db = getFirestore();
    firebaseConfigured = true;
  } catch (error) {
    firebaseInitError = `Firebase init failed: ${error.message}`;
  }
}

initFirebase();

const DEFAULT_MENUS = [
  {
    title: 'TempMail API v2',
    type: 'iframe',
    url: 'https://tempmail.id.vn/api/v2',
    order: 10
  },
  {
    title: 'TempMail.id.vn',
    type: 'external',
    url: 'https://tempmail.id.vn',
    order: 20
  },
  {
    title: 'Link4M',
    type: 'external',
    url: 'https://link4m.co',
    order: 30
  }
];

function normalizeMenu(id, data) {
  return {
    id,
    title: String(data.title || '').trim(),
    type: data.type === 'iframe' ? 'iframe' : 'external',
    url: String(data.url || '').trim(),
    order: Number.isFinite(Number(data.order)) ? Number(data.order) : 999,
    createdAt: data.createdAt?.toDate ? data.createdAt.toDate().toISOString() : (data.createdAt || null),
    updatedAt: data.updatedAt?.toDate ? data.updatedAt.toDate().toISOString() : (data.updatedAt || null)
  };
}

let menuCache = DEFAULT_MENUS.map((m, index) => normalizeMenu(`default-${index + 1}`, m));
const sseClients = new Set();
let unsubscribeMenu = null;

function broadcastMenus() {
  const payload = `event: menu\ndata: ${JSON.stringify(menuCache)}\n\n`;
  for (const client of sseClients) {
    try {
      client.write(payload);
    } catch (_) {
      sseClients.delete(client);
    }
  }
}

async function loadMenusOnce() {
  if (!db) return menuCache;
  const snap = await db.collection('menus').orderBy('order', 'asc').get();
  if (snap.empty) {
    const batch = db.batch();
    DEFAULT_MENUS.forEach((menu) => {
      const ref = db.collection('menus').doc();
      batch.set(ref, { ...menu, createdAt: FieldValue.serverTimestamp(), updatedAt: FieldValue.serverTimestamp() });
    });
    await batch.commit();
    return loadMenusOnce();
  }
  menuCache = snap.docs.map((doc) => normalizeMenu(doc.id, doc.data())).filter((item) => item.title && item.url);
  return menuCache;
}

function startMenuWatcher() {
  if (!db || unsubscribeMenu) return;
  unsubscribeMenu = db.collection('menus').orderBy('order', 'asc').onSnapshot(
    (snap) => {
      menuCache = snap.docs.map((doc) => normalizeMenu(doc.id, doc.data())).filter((item) => item.title && item.url);
      broadcastMenus();
    },
    (error) => {
      console.error('Firestore menu listener error:', error.message);
    }
  );
}

loadMenusOnce().catch((error) => console.error('Menu bootstrap failed:', error.message)).finally(startMenuWatcher);

function isSafeHttpUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' || url.protocol === 'http:';
  } catch (_) {
    return false;
  }
}

function createAdminToken() {
  const payload = {
    role: 'admin',
    exp: Date.now() + 12 * 60 * 60 * 1000,
    nonce: crypto.randomBytes(8).toString('hex')
  };
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', ADMIN_TOKEN_SECRET).update(encoded).digest('base64url');
  return `${encoded}.${signature}`;
}

function verifyAdminToken(token) {
  try {
    const [encoded, signature] = String(token || '').split('.');
    if (!encoded || !signature) return false;
    const expected = crypto.createHmac('sha256', ADMIN_TOKEN_SECRET).update(encoded).digest('base64url');
    const a = Buffer.from(signature);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    return payload.role === 'admin' && Number(payload.exp) > Date.now();
  } catch (_) {
    return false;
  }
}

function requireAdmin(req, res, next) {
  const auth = req.get('Authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!verifyAdminToken(token)) {
    return res.status(401).json({ ok: false, error: 'UNAUTHORIZED', message: 'Phiên quản trị không hợp lệ hoặc đã hết hạn.' });
  }
  return next();
}

let tempAuth = {
  accessToken: process.env.TEMPMAIL_API_TOKEN || '',
  refreshToken: '',
  expiresAt: 0
};

function unwrapApiData(value) {
  if (value && typeof value === 'object' && value.data !== undefined) return value.data;
  return value;
}

function extractToken(value) {
  const root = unwrapApiData(value) || {};
  return {
    accessToken: root.access_token || root.token || root.accessToken || '',
    refreshToken: root.refresh_token || root.refreshToken || '',
    expiresIn: Number(root.expires_in || root.expiresIn || 3600)
  };
}

async function tempMailLogin() {
  if (!process.env.TEMPMAIL_USERNAME || !process.env.TEMPMAIL_PASSWORD) {
    throw new Error('TEMPMAIL_API_TOKEN hoặc TEMPMAIL_USERNAME/TEMPMAIL_PASSWORD chưa được cấu hình');
  }
  const response = await axios.post(`${TEMPMAIL_API_BASE}/auth/login`, {
    email: process.env.TEMPMAIL_USERNAME,
    password: process.env.TEMPMAIL_PASSWORD
  }, {
    timeout: 15000,
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' }
  });
  const token = extractToken(response.data);
  if (!token.accessToken) throw new Error('TempMail login không trả về access token');
  tempAuth = {
    accessToken: token.accessToken,
    refreshToken: token.refreshToken,
    expiresAt: Date.now() + Math.max(60, token.expiresIn - 30) * 1000
  };
  return tempAuth.accessToken;
}

async function getTempMailToken(forceRefresh = false) {
  if (!forceRefresh && tempAuth.accessToken && (process.env.TEMPMAIL_API_TOKEN || tempAuth.expiresAt > Date.now())) {
    return tempAuth.accessToken;
  }
  return tempMailLogin();
}

async function tempMailRequest(method, path, { data, params } = {}, retried = false) {
  const token = await getTempMailToken(false);
  try {
    const response = await axios({
      method,
      url: `${TEMPMAIL_API_BASE}${path.startsWith('/') ? path : `/${path}`}`,
      data,
      params,
      timeout: 20000,
      headers: {
        Accept: 'application/json',
        ...(data !== undefined ? { 'Content-Type': 'application/json' } : {}),
        Authorization: `Bearer ${token}`
      },
      validateStatus: () => true
    });

    if (response.status === 401 && !retried && !process.env.TEMPMAIL_API_TOKEN) {
      await getTempMailToken(true);
      return tempMailRequest(method, path, { data, params }, true);
    }

    if (response.status < 200 || response.status >= 300) {
      const message = response.data?.message || response.data?.error || `TempMail HTTP ${response.status}`;
      const err = new Error(String(message));
      err.status = response.status;
      err.data = response.data;
      throw err;
    }

    return response.data;
  } catch (error) {
    if (error.response) {
      const message = error.response.data?.message || error.response.data?.error || error.message;
      const wrapped = new Error(String(message));
      wrapped.status = error.response.status;
      wrapped.data = error.response.data;
      throw wrapped;
    }
    throw error;
  }
}

function publicTempMailError(res, error) {
  const upstreamStatus = Number(error.status || 502);
  const status = [400, 401, 403, 404, 429].includes(upstreamStatus) ? upstreamStatus : 502;
  return res.status(status).json({
    ok: false,
    error: 'TEMPMAIL_ERROR',
    message: error.message || 'Không thể kết nối TempMail API',
    upstreamStatus: error.status || null
  });
}

app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'tdm-dev-backend',
    env: NODE_ENV,
    firebaseConfigured,
    firebaseError: firebaseConfigured ? null : firebaseInitError,
    tempMailConfigured: Boolean(process.env.TEMPMAIL_API_TOKEN || (process.env.TEMPMAIL_USERNAME && process.env.TEMPMAIL_PASSWORD)),
    timestamp: new Date().toISOString()
  });
});

app.post('/api/admin/login', rateLimit({ windowMs: 10 * 60 * 1000, max: 15 }), (req, res) => {
  const password = String(req.body?.password || '');
  if (!ADMIN_PASSWORD) {
    return res.status(503).json({ ok: false, error: 'ADMIN_NOT_CONFIGURED', message: 'ADMIN_PASSWORD chưa được cấu hình trên Railway.' });
  }
  const supplied = Buffer.from(password);
  const expected = Buffer.from(ADMIN_PASSWORD);
  if (!password || supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
    return res.status(401).json({ ok: false, error: 'INVALID_PASSWORD', message: 'Mật khẩu quản trị không chính xác.' });
  }
  return res.json({ ok: true, token: createAdminToken(), expiresIn: 12 * 60 * 60 });
});

app.get('/api/menu', async (_req, res) => {
  try {
    if (db) await loadMenusOnce();
    return res.json({ ok: true, menus: menuCache });
  } catch (error) {
    return res.status(500).json({ ok: false, error: 'MENU_READ_ERROR', message: error.message });
  }
});

app.get('/api/menu/stream', async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders?.();
  res.write(`event: menu\ndata: ${JSON.stringify(menuCache)}\n\n`);
  sseClients.add(res);
  const keepAlive = setInterval(() => {
    try { res.write(': ping\n\n'); } catch (_) {}
  }, 25000);
  req.on('close', () => {
    clearInterval(keepAlive);
    sseClients.delete(res);
  });
});

app.post('/api/menu', requireAdmin, async (req, res) => {
  const title = String(req.body?.title || '').trim();
  const type = req.body?.type === 'iframe' ? 'iframe' : 'external';
  const url = String(req.body?.url || '').trim();
  const order = Number(req.body?.order ?? 999);

  if (!title || title.length > 80) return res.status(400).json({ ok: false, message: 'Tên mục phải từ 1–80 ký tự.' });
  if (!isSafeHttpUrl(url)) return res.status(400).json({ ok: false, message: 'URL phải bắt đầu bằng http:// hoặc https://.' });
  if (!Number.isFinite(order) || order < 0 || order > 9999) return res.status(400).json({ ok: false, message: 'Thứ tự không hợp lệ.' });
  if (!db) return res.status(503).json({ ok: false, error: 'FIREBASE_NOT_CONFIGURED', message: 'Firestore chưa được cấu hình.' });

  try {
    const ref = await db.collection('menus').add({
      title,
      type,
      url,
      order,
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp()
    });
    const doc = await ref.get();
    return res.status(201).json({ ok: true, menu: normalizeMenu(doc.id, doc.data()) });
  } catch (error) {
    return res.status(500).json({ ok: false, error: 'MENU_CREATE_ERROR', message: error.message });
  }
});

app.put('/api/menu/:id', requireAdmin, async (req, res) => {
  const id = String(req.params.id || '');
  const title = String(req.body?.title || '').trim();
  const type = req.body?.type === 'iframe' ? 'iframe' : 'external';
  const url = String(req.body?.url || '').trim();
  const order = Number(req.body?.order ?? 999);

  if (!id || !title || title.length > 80) return res.status(400).json({ ok: false, message: 'Dữ liệu menu không hợp lệ.' });
  if (!isSafeHttpUrl(url)) return res.status(400).json({ ok: false, message: 'URL phải bắt đầu bằng http:// hoặc https://.' });
  if (!Number.isFinite(order) || order < 0 || order > 9999) return res.status(400).json({ ok: false, message: 'Thứ tự không hợp lệ.' });
  if (!db) return res.status(503).json({ ok: false, error: 'FIREBASE_NOT_CONFIGURED', message: 'Firestore chưa được cấu hình.' });

  try {
    const ref = db.collection('menus').doc(id);
    if (!(await ref.get()).exists) return res.status(404).json({ ok: false, message: 'Không tìm thấy mục menu.' });
    await ref.update({ title, type, url, order, updatedAt: FieldValue.serverTimestamp() });
    const doc = await ref.get();
    return res.json({ ok: true, menu: normalizeMenu(doc.id, doc.data()) });
  } catch (error) {
    return res.status(500).json({ ok: false, error: 'MENU_UPDATE_ERROR', message: error.message });
  }
});

app.delete('/api/menu/:id', requireAdmin, async (req, res) => {
  const id = String(req.params.id || '');
  if (!db) return res.status(503).json({ ok: false, error: 'FIREBASE_NOT_CONFIGURED', message: 'Firestore chưa được cấu hình.' });
  try {
    const ref = db.collection('menus').doc(id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ ok: false, message: 'Không tìm thấy mục menu.' });
    await ref.delete();
    return res.json({ ok: true, id });
  } catch (error) {
    return res.status(500).json({ ok: false, error: 'MENU_DELETE_ERROR', message: error.message });
  }
});

app.get('/api/tempmail/domains', rateLimit({ windowMs: 60 * 1000, max: 30 }), async (_req, res) => {
  try {
    const payload = await tempMailRequest('GET', '/domain');
    return res.json({ ok: true, data: unwrapApiData(payload) });
  } catch (error) {
    return publicTempMailError(res, error);
  }
});

app.post('/api/tempmail/create', rateLimit({ windowMs: 60 * 1000, max: 30 }), async (req, res) => {
  try {
    const user = String(req.body?.prefix || req.body?.user || '').trim();
    const domain = String(req.body?.domain || '').trim();
    const data = {};
    if (user) data.user = user.slice(0, 48);
    if (domain) data.domain = domain.slice(0, 120);
    const payload = await tempMailRequest('POST', '/email/create', { data });
    return res.json({ ok: true, data: unwrapApiData(payload), raw: payload });
  } catch (error) {
    return publicTempMailError(res, error);
  }
});

app.get('/api/tempmail/inbox', rateLimit({ windowMs: 60 * 1000, max: 120 }), async (req, res) => {
  const email = String(req.query?.email || '').trim();
  const id = String(req.query?.id || '').trim();
  try {
    let payload;
    if (email) {
      payload = await tempMailRequest('GET', `/email/query/${encodeURIComponent(email)}`);
    } else if (id) {
      payload = await tempMailRequest('GET', `/email/${encodeURIComponent(id)}`);
    } else {
      payload = await tempMailRequest('GET', '/email');
    }
    return res.json({ ok: true, data: unwrapApiData(payload), raw: payload });
  } catch (error) {
    return publicTempMailError(res, error);
  }
});

app.get('/api/tempmail/message/:id', rateLimit({ windowMs: 60 * 1000, max: 120 }), async (req, res) => {
  try {
    const payload = await tempMailRequest('GET', `/message/${encodeURIComponent(req.params.id)}`);
    return res.json({ ok: true, data: unwrapApiData(payload), raw: payload });
  } catch (error) {
    return publicTempMailError(res, error);
  }
});

app.post('/api/tempmail/delete', rateLimit({ windowMs: 60 * 1000, max: 30 }), async (req, res) => {
  try {
    const ids = Array.isArray(req.body?.ids) ? req.body.ids.map((v) => String(v)).filter(Boolean) : [];
    const emailIds = Array.isArray(req.body?.emailIds) ? req.body.emailIds.map((v) => String(v)).filter(Boolean) : [];
    const emails = Array.isArray(req.body?.emails) ? req.body.emails.map((v) => String(v)).filter(Boolean) : [];
    if (!ids.length && !emailIds.length && !emails.length) {
      return res.status(400).json({ ok: false, message: 'Thiếu danh sách email cần xóa.' });
    }
    const bodyVariants = [
      { ids: ids.length ? ids : emailIds },
      { email_ids: emailIds.length ? emailIds : ids },
      { emails }
    ];
    let lastError;
    for (const body of bodyVariants) {
      if (Object.values(body)[0].length === 0) continue;
      try {
        const payload = await tempMailRequest('POST', '/email/delete', { data: body });
        return res.json({ ok: true, data: unwrapApiData(payload), raw: payload });
      } catch (error) {
        lastError = error;
        if (![400, 404, 422].includes(Number(error.status))) throw error;
      }
    }
    throw lastError || new Error('TempMail delete failed');
  } catch (error) {
    return publicTempMailError(res, error);
  }
});

app.post('/api/link4m/shorten', rateLimit({ windowMs: 60 * 60 * 1000, max: 120 }), async (req, res) => {
  const apiKey = String(req.body?.apiKey || '').trim();
  const url = String(req.body?.url || '').trim();
  const title = String(req.body?.title || '').trim();

  if (!apiKey) return res.status(400).json({ ok: false, message: 'Vui lòng nhập API Key Link4M.' });
  if (!isSafeHttpUrl(url)) return res.status(400).json({ ok: false, message: 'Link gốc phải là URL http/https hợp lệ.' });
  if (apiKey.length > 300) return res.status(400).json({ ok: false, message: 'API Key quá dài.' });

  try {
    const response = await axios.get(LINK4M_API_BASE, {
      params: { api: apiKey, url },
      timeout: 20000,
      headers: { Accept: 'application/json' },
      validateStatus: () => true
    });

    const payload = response.data;
    if (response.status < 200 || response.status >= 300 || payload?.status === 'error') {
      return res.status([400, 401, 403, 429].includes(response.status) ? response.status : 502).json({
        ok: false,
        error: 'LINK4M_ERROR',
        message: payload?.message || 'Link4M không trả về kết quả thành công.',
        upstreamStatus: response.status,
        data: payload
      });
    }

    return res.json({
      ok: true,
      title: title || 'Link rút gọn',
      data: payload
    });
  } catch (error) {
    return res.status(502).json({ ok: false, error: 'LINK4M_NETWORK_ERROR', message: 'Không kết nối được Link4M.' });
  }
});

app.use((req, res) => {
  res.status(404).json({ ok: false, error: 'NOT_FOUND', message: `Cannot ${req.method} ${req.path}` });
});

app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err.message);
  const status = Number(err.statusCode || err.status || 500);
  res.status(status >= 400 && status < 600 ? status : 500).json({ ok: false, error: 'SERVER_ERROR', message: NODE_ENV === 'production' ? 'Lỗi máy chủ.' : err.message });
});

app.listen(PORT, () => {
  console.log(`TDM Dev backend listening on port ${PORT}`);
  console.log(`Firebase: ${firebaseConfigured ? 'configured' : 'NOT configured'}`);
  console.log(`TempMail: ${process.env.TEMPMAIL_API_TOKEN || (process.env.TEMPMAIL_USERNAME && process.env.TEMPMAIL_PASSWORD) ? 'configured' : 'NOT configured'}`);
});

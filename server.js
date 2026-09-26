'use strict';

require('dotenv').config();

const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');

const app = express();
const PORT = Number(process.env.PORT || 8080);
const NODE_ENV = process.env.NODE_ENV || 'development';

function splitCsv(value) {
  return String(value || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

const allowedOrigins = splitCsv(process.env.FRONTEND_ORIGINS);
const adminPassword = process.env.ADMIN_PASSWORD || '';
const jwtSecret = process.env.JWT_SECRET || '';
const tempMailApiToken = process.env.TEMPMAIL_API_TOKEN || '';
const tempMailApiBaseUrl = (process.env.TEMPMAIL_API_BASE_URL || 'https://tempmail.id.vn/api').replace(/\/$/, '');

// --- SỬA LỖI KHỞI TẠO FIREBASE ADMIN ---
if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
  console.error('[FATAL] FIREBASE_SERVICE_ACCOUNT is missing.');
  process.exit(1);
}

let serviceAccount;
try {
  let rawEnv = process.env.FIREBASE_SERVICE_ACCOUNT.trim();

  // Bỏ dấu ngoặc kép/đơn bao quanh nếu Railway truyền dư
  if ((rawEnv.startsWith("'") && rawEnv.endsWith("'")) || (rawEnv.startsWith('"') && rawEnv.endsWith('"'))) {
    rawEnv = rawEnv.slice(1, -1).trim();
  }

  // Hỗ trợ decode nếu chuỗi truyền vào là Base64
  if (!rawEnv.startsWith('{') && /^[A-Za-z0-9+/=]+$/.test(rawEnv.replace(/\s/g, ''))) {
    rawEnv = Buffer.from(rawEnv, 'base64').toString('utf8');
  }

  serviceAccount = JSON.parse(rawEnv);

  // Xử lý các dấu xuống dòng bị hỏng trong Private Key
  if (serviceAccount.private_key) {
    serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
  }
} catch (error) {
  console.error('[FATAL] FIREBASE_SERVICE_ACCOUNT is not valid JSON:', error.message);
  process.exit(1);
}

try {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
} catch (error) {
  console.error('[FATAL] Firebase Admin initialization failed:', error.message);
  process.exit(1);
}
// ------------------------------------

const db = admin.firestore();
const { FieldValue } = admin.firestore;

if (!jwtSecret) {
  console.warn('[WARN] JWT_SECRET is missing. Admin login will be disabled.');
}
if (!adminPassword) {
  console.warn('[WARN] ADMIN_PASSWORD is missing. Admin login will be disabled.');
}
if (!tempMailApiToken) {
  console.warn('[WARN] TEMPMAIL_API_TOKEN is missing. Temp Mail routes will return configuration errors.');
}

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
      callback(null, true);
      return;
    }
    callback(new Error('CORS origin not allowed.'));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Temp-Session'],
  exposedHeaders: ['Content-Type']
}));
app.use(express.json({ limit: '256kb' }));

const publicLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: 'draft-8',
  legacyHeaders: false
});

const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { success: false, message: 'Quá nhiều lần thử đăng nhập quản trị. Vui lòng thử lại sau.' }
});

app.use('/api', publicLimiter);

function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

function safeMessage(error) {
  return error?.response?.data?.message || error?.response?.data?.error || error?.message || 'Đã xảy ra lỗi.';
}

function requireTempMailConfig(res) {
  if (!tempMailApiToken) {
    res.status(503).json({ success: false, message: 'Backend chưa cấu hình TEMPMAIL_API_TOKEN.' });
    return false;
  }
  return true;
}

function tempMailHeaders() {
  return {
    Accept: 'application/json',
    Authorization: `Bearer ${tempMailApiToken}`,
    'Content-Type': 'application/json'
  };
}

async function callTempMail(path, options = {}) {
  return axios({
    baseURL: tempMailApiBaseUrl,
    url: path,
    timeout: 15000,
    validateStatus: () => true,
    ...options,
    headers: {
      ...tempMailHeaders(),
      ...(options.headers || {})
    }
  });
}

function extractTempMailData(response) {
  const body = response.data;
  if (body && typeof body === 'object' && 'data' in body) return body.data;
  return body;
}

function cleanText(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function validateHttpUrl(value) {
  try {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol)) return false;
    return true;
  } catch {
    return false;
  }
}

function hashSessionId(sessionId) {
  return crypto.createHash('sha256').update(sessionId).digest('hex');
}

function getOrCreateSessionId(req) {
  const provided = String(req.get('X-Temp-Session') || '').trim();
  if (/^[A-Za-z0-9_-]{24,128}$/.test(provided)) return provided;
  return crypto.randomBytes(24).toString('base64url');
}

async function getTempSession(req) {
  const sessionId = String(req.get('X-Temp-Session') || '').trim();
  if (!/^[A-Za-z0-9_-]{24,128}$/.test(sessionId)) return null;
  const ref = db.collection('tempMailSessions').doc(hashSessionId(sessionId));
  const snapshot = await ref.get();
  if (!snapshot.exists) return null;
  return snapshot.data();
}

async function saveTempSession(sessionId, mailbox) {
  const ref = db.collection('tempMailSessions').doc(hashSessionId(sessionId));
  await ref.set({
    sessionIdHash: hashSessionId(sessionId),
    mailId: String(mailbox.id),
    email: cleanText(mailbox.email),
    createdAt: FieldValue.serverTimestamp(),
    updatedAt: FieldValue.serverTimestamp()
  }, { merge: true });
}

async function clearTempSession(sessionId) {
  if (!sessionId) return;
  await db.collection('tempMailSessions').doc(hashSessionId(sessionId)).delete().catch(() => {});
}

function createAdminToken() {
  return jwt.sign({ role: 'admin' }, jwtSecret, {
    issuer: 'tdm-dev',
    audience: 'tdm-dev-admin',
    expiresIn: '8h'
  });
}

function requireAdmin(req, res, next) {
  if (!jwtSecret) {
    return res.status(503).json({ success: false, message: 'JWT_SECRET chưa được cấu hình.' });
  }

  const authorization = String(req.get('Authorization') || '');
  const token = authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
  if (!token) {
    return res.status(401).json({ success: false, message: 'Thiếu phiên quản trị.' });
  }

  try {
    const payload = jwt.verify(token, jwtSecret, {
      issuer: 'tdm-dev',
      audience: 'tdm-dev-admin'
    });
    if (payload.role !== 'admin') throw new Error('Invalid role');
    req.admin = payload;
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Phiên quản trị không hợp lệ hoặc đã hết hạn.' });
  }
}

function parseMenuPayload(body) {
  const title = cleanText(body?.title).slice(0, 120);
  const type = body?.type === 'iframe' ? 'iframe' : 'external';
  const url = cleanText(body?.url).slice(0, 2000);
  const order = Number.isFinite(Number(body?.order)) ? Number(body.order) : 0;
  const enabled = body?.enabled !== false;

  if (!title) throw new Error('Tên mục menu không được để trống.');
  if (!validateHttpUrl(url)) throw new Error('URL phải là địa chỉ HTTP/HTTPS hợp lệ.');
  if (!Number.isInteger(order) || order < 0 || order > 1000000) throw new Error('Order phải là số nguyên từ 0 trở lên.');

  return { title, type, url, order, enabled };
}

async function serializeMenuDoc(doc) {
  const data = doc.data();
  return {
    id: doc.id,
    title: data.title,
    type: data.type,
    url: data.url,
    order: data.order,
    enabled: data.enabled !== false,
    createdAt: data.createdAt?.toDate?.()?.toISOString() || null,
    updatedAt: data.updatedAt?.toDate?.()?.toISOString() || null
  };
}

async function getAllMenus(includeDisabled = false) {
  const snapshot = await db.collection('menus').orderBy('order', 'asc').get();
  const menus = await Promise.all(snapshot.docs.map(serializeMenuDoc));
  return includeDisabled ? menus : menus.filter((item) => item.enabled !== false);
}

async function sendMenuSnapshot(res, includeDisabled = false) {
  try {
    const menus = await getAllMenus(includeDisabled);
    res.write(`event: menus\ndata: ${JSON.stringify({ success: true, menus })}\n\n`);
  } catch (error) {
    res.write(`event: error\ndata: ${JSON.stringify({ success: false, message: safeMessage(error) })}\n\n`);
  }
}

const sseClients = new Map();
let menuUnsubscribe = null;

function startMenuWatcher() {
  if (menuUnsubscribe) return;
  menuUnsubscribe = db.collection('menus').orderBy('order', 'asc').onSnapshot(
    async () => {
      const clients = Array.from(sseClients.values());
      for (const client of clients) {
        await sendMenuSnapshot(client.res, client.includeDisabled);
      }
    },
    (error) => {
      for (const client of sseClients.values()) {
        client.res.write(`event: error\ndata: ${JSON.stringify({ success: false, message: safeMessage(error) })}\n\n`);
      }
    }
  );
}

startMenuWatcher();

app.get('/health', asyncRoute(async (_req, res) => {
  res.json({
    success: true,
    service: 'tdm-dev-backend',
    environment: NODE_ENV,
    firebaseProjectId: serviceAccount.project_id || 'unknown',
    timestamp: new Date().toISOString()
  });
}));

app.get('/api/menu', asyncRoute(async (_req, res) => {
  const menus = await getAllMenus(false);
  res.json({ success: true, menus });
}));

app.get('/api/menu/stream', asyncRoute(async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  const clientId = crypto.randomBytes(12).toString('hex');
  sseClients.set(clientId, { res, includeDisabled: false });
  res.write(`retry: 5000\n\n`);
  await sendMenuSnapshot(res, false);

  const heartbeat = setInterval(() => {
    try {
      res.write(': heartbeat\n\n');
    } catch {
      clearInterval(heartbeat);
    }
  }, 20000);

  req.on('close', () => {
    clearInterval(heartbeat);
    sseClients.delete(clientId);
  });
}));

app.get('/api/auth/verify', asyncRoute(async (req, res) => {
  const authorization = String(req.get('Authorization') || '');
  const token = authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
  if (!token) return res.status(401).json({ success: false, message: 'Thiếu Firebase ID token.' });

  try {
    const decoded = await admin.auth().verifyIdToken(token);
    res.json({
      success: true,
      user: {
        uid: decoded.uid,
        email: decoded.email || null,
        emailVerified: decoded.email_verified === true,
        name: decoded.name || null,
        picture: decoded.picture || null,
        provider: decoded.firebase?.sign_in_provider || null
      }
    });
  } catch {
    res.status(401).json({ success: false, message: 'Firebase ID token không hợp lệ.' });
  }
}));

app.post('/api/admin/login', adminLoginLimiter, asyncRoute(async (req, res) => {
  if (!adminPassword || !jwtSecret) {
    return res.status(503).json({ success: false, message: 'Admin login chưa được cấu hình trên backend.' });
  }

  const password = String(req.body?.password || '');
  if (!password || password !== adminPassword) {
    return res.status(401).json({ success: false, message: 'Mật khẩu quản trị không chính xác.' });
  }

  res.json({ success: true, accessToken: createAdminToken(), expiresIn: 8 * 60 * 60 });
}));

app.get('/api/admin/menus', requireAdmin, asyncRoute(async (_req, res) => {
  const menus = await getAllMenus(true);
  res.json({ success: true, menus });
}));

app.post('/api/admin/menus', requireAdmin, asyncRoute(async (req, res) => {
  const menu = parseMenuPayload(req.body);
  const docRef = await db.collection('menus').add({
    ...menu,
    createdAt: FieldValue.serverTimestamp(),
    updatedAt: FieldValue.serverTimestamp()
  });
  res.status(201).json({ success: true, menu: { id: docRef.id, ...menu } });
}));

app.put('/api/admin/menus/:id', requireAdmin, asyncRoute(async (req, res) => {
  const id = cleanText(req.params.id);
  if (!id || id.length > 128) return res.status(400).json({ success: false, message: 'ID menu không hợp lệ.' });
  const menu = parseMenuPayload(req.body);
  const ref = db.collection('menus').doc(id);
  const existing = await ref.get();
  if (!existing.exists) return res.status(404).json({ success: false, message: 'Không tìm thấy mục menu.' });

  await ref.update({ ...menu, updatedAt: FieldValue.serverTimestamp() });
  res.json({ success: true, menu: { id, ...menu } });
}));

app.delete('/api/admin/menus/:id', requireAdmin, asyncRoute(async (req, res) => {
  const id = cleanText(req.params.id);
  if (!id || id.length > 128) return res.status(400).json({ success: false, message: 'ID menu không hợp lệ.' });
  await db.collection('menus').doc(id).delete();
  res.json({ success: true, message: 'Đã xóa mục menu.' });
}));

app.get('/api/temp-mail/session', asyncRoute(async (req, res) => {
  if (!requireTempMailConfig(res)) return;
  const session = await getTempSession(req);
  res.json({ success: true, session: session || null });
}));

app.post('/api/temp-mail/create', asyncRoute(async (req, res) => {
  if (!requireTempMailConfig(res)) return;

  const sessionId = getOrCreateSessionId(req);
  const user = cleanText(req.body?.user).replace(/[^a-zA-Z0-9._-]/g, '').slice(0, 64);
  const domain = cleanText(req.body?.domain).slice(0, 120);

  const payload = {};
  if (user) payload.user = user;
  if (domain) payload.domain = domain;

  const upstream = await callTempMail('/email/create', {
    method: 'POST',
    data: payload
  });

  if (upstream.status < 200 || upstream.status >= 300) {
    return res.status(upstream.status).json({ success: false, message: safeMessage({ response: upstream }), upstream: upstream.data });
  }

  const data = extractTempMailData(upstream) || {};
  const mailbox = {
    id: data.id ?? data.mail_id ?? data.mailId ?? data.email_id,
    email: data.email ?? data.address ?? data.mail ?? data.username
  };

  if (!mailbox.id || !mailbox.email) {
    return res.status(502).json({ success: false, message: 'TempMail API trả về dữ liệu tạo mail không đúng định dạng.', upstream: upstream.data });
  }

  await saveTempSession(sessionId, mailbox);
  res.setHeader('X-Temp-Session', sessionId);
  res.json({ success: true, mailbox });
}));

app.get('/api/temp-mail/messages', asyncRoute(async (req, res) => {
  if (!requireTempMailConfig(res)) return;
  const session = await getTempSession(req);
  if (!session?.mailId) return res.status(404).json({ success: false, message: 'Chưa có hộp thư trong phiên hiện tại.' });

  const upstream = await callTempMail(`/email/${encodeURIComponent(session.mailId)}`, { method: 'GET' });
  if (upstream.status < 200 || upstream.status >= 300) {
    return res.status(upstream.status).json({ success: false, message: safeMessage({ response: upstream }), upstream: upstream.data });
  }

  res.json({ success: true, mailbox: session, data: extractTempMailData(upstream), upstream: upstream.data });
}));

app.get('/api/temp-mail/message/:messageId', asyncRoute(async (req, res) => {
  if (!requireTempMailConfig(res)) return;
  const session = await getTempSession(req);
  if (!session?.mailId) return res.status(404).json({ success: false, message: 'Chưa có hộp thư trong phiên hiện tại.' });

  const messageId = cleanText(req.params.messageId);
  if (!messageId || messageId.length > 256) return res.status(400).json({ success: false, message: 'Message ID không hợp lệ.' });

  const upstream = await callTempMail(`/message/${encodeURIComponent(messageId)}`, { method: 'GET' });
  if (upstream.status < 200 || upstream.status >= 300) {
    return res.status(upstream.status).json({ success: false, message: safeMessage({ response: upstream }), upstream: upstream.data });
  }

  res.json({ success: true, data: extractTempMailData(upstream), upstream: upstream.data });
}));

app.delete('/api/temp-mail/current', asyncRoute(async (req, res) => {
  if (!requireTempMailConfig(res)) return;
  const sessionId = String(req.get('X-Temp-Session') || '').trim();
  const session = await getTempSession(req);
  if (!session?.mailId) return res.status(404).json({ success: false, message: 'Không có hộp thư hiện tại.' });

  const upstream = await callTempMail(`/email/${encodeURIComponent(session.mailId)}`, { method: 'DELETE' });

  if (upstream.status === 404 || upstream.status === 405 || upstream.status === 501) {
    await clearTempSession(sessionId);
    return res.status(501).json({
      success: false,
      unsupported: true,
      message: 'API TempMail hiện tại không công bố endpoint xóa hộp thư. Phiên cục bộ đã được xóa; hộp thư sẽ hết hạn theo chính sách của TempMail.'
    });
  }

  if (upstream.status < 200 || upstream.status >= 300) {
    return res.status(upstream.status).json({ success: false, message: safeMessage({ response: upstream }), upstream: upstream.data });
  }

  await clearTempSession(sessionId);
  res.json({ success: true, message: 'Đã xóa hộp thư khỏi phiên hiện tại.', upstream: upstream.data });
}));

app.post('/api/link4m/shorten', asyncRoute(async (req, res) => {
  const apiKey = cleanText(req.body?.apiKey).slice(0, 1000);
  const url = cleanText(req.body?.url).slice(0, 4000);
  if (!apiKey) return res.status(400).json({ success: false, message: 'API Key Link4M không được để trống.' });
  if (!validateHttpUrl(url)) return res.status(400).json({ success: false, message: 'URL đích phải là HTTP/HTTPS hợp lệ.' });

  const upstream = await axios.get('https://link4m.co/api-shorten/v2', {
    params: { api: apiKey, url },
    timeout: 15000,
    validateStatus: () => true
  });

  if (upstream.status < 200 || upstream.status >= 300) {
    return res.status(upstream.status).json({ success: false, message: safeMessage({ response: upstream }), upstream: upstream.data });
  }

  const body = upstream.data;
  const candidate = body?.shortenedUrl
    || body?.shorturl
    || body?.shortUrl
    || body?.short
    || body?.link
    || body?.url
    || body?.data?.shortenedUrl
    || body?.data?.shorturl
    || body?.data?.shortUrl
    || body?.data?.short
    || body?.data?.link
    || body?.result?.shortenedUrl
    || body?.result?.shorturl
    || body?.result?.shortUrl;

  if (!candidate) {
    return res.status(502).json({ success: false, message: 'Link4M không trả về URL rút gọn theo định dạng dự kiến.', upstream: body });
  }

  res.json({ success: true, shortUrl: candidate, upstream: body });
}));

app.use((error, _req, res, _next) => {
  if (error?.message === 'CORS origin not allowed.') {
    return res.status(403).json({ success: false, message: 'Origin không được phép.' });
  }
  console.error('[ERROR]', error);
  res.status(error?.status || 500).json({ success: false, message: NODE_ENV === 'production' ? 'Lỗi máy chủ.' : error.message });
});

const server = app.listen(PORT, () => {
  console.log(`[TDM Dev] Backend listening on port ${PORT}`);
  console.log(`[TDM Dev] Firebase project: ${serviceAccount.project_id || 'unknown'}`);
});

process.on('SIGTERM', () => {
  if (menuUnsubscribe) menuUnsubscribe();
  server.close(() => process.exit(0));
});

process.on('SIGINT', () => {
  if (menuUnsubscribe) menuUnsubscribe();
  server.close(() => process.exit(0));
});

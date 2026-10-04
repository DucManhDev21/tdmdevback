const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const nodemailer = require('nodemailer');
const multer = require('multer');
const axios = require('axios');
const crypto = require('crypto');
const net = require('net');

const envResult = dotenv.config();
if (envResult.error && envResult.error.code !== 'ENOENT') {
  console.warn('dotenv warning:', envResult.error.message);
}

const app = express();
// Railway chạy sau reverse proxy: cần thiết để req.ip là IP người dùng thật (rate limit theo từng người, không dùng chung).
app.set('trust proxy', 1);
const port = Number.parseInt(process.env.PORT || '5000', 10);

const allowedOrigins = String(process.env.CORS_ORIGINS || '*')
  .split(',')
  .map((item) => item.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('CORS origin not allowed'));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Accept', 'Authorization', 'X-Mailbox-Token'],
  maxAge: 86400,
}));

app.use(express.json({ limit: '1mb' }));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: (Number.parseInt(process.env.MAX_ATTACHMENT_MB || '10', 10) || 10) * 1024 * 1024,
    files: 1,
  },
});

const adminConfig = {
  tools: {
    link4m: true,
    tempmail: true,
    sendmail: true,
  },
  banner: '',
  updatedAt: null,
};

const requestCounters = new Map();

function nowIso() {
  return new Date().toISOString();
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function jsonError(res, status, message, code = 'ERROR', extra = {}) {
  return res.status(status).json({ success: false, code, message, ...extra });
}

function isValidHttpUrl(value) {
  try {
    const parsed = new URL(value);
    return ['http:', 'https:'].includes(parsed.protocol);
  } catch {
    return false;
  }
}

function getAdminToken(req) {
  const authorization = String(req.get('authorization') || '');
  if (authorization.toLowerCase().startsWith('bearer ')) return authorization.slice(7).trim();
  return String(req.body?.token || req.query?.token || '').trim();
}

function requireAdmin(req, res, next) {
  const expected = String(process.env.ADMIN_TOKEN || '').trim();
  const actual = getAdminToken(req);
  if (!expected || !actual || Buffer.byteLength(actual) !== Buffer.byteLength(expected) || !crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(expected))) {
    return jsonError(res, 401, 'Admin token không hợp lệ.', 'UNAUTHORIZED');
  }
  next();
}

function providerRateLimit(key, limit = 60, windowMs = 60_000) {
  const current = Date.now();
  const state = requestCounters.get(key);
  if (!state || current - state.startedAt >= windowMs) {
    requestCounters.set(key, { startedAt: current, count: 1 });
    return true;
  }
  if (state.count >= limit) return false;
  state.count += 1;
  return true;
}

function getClientKey(req) {
  return String(req.ip || req.headers['x-forwarded-for'] || 'unknown').split(',')[0].trim();
}

function extractShortUrl(payload) {
  if (typeof payload === 'string') {
    const text = payload.trim();
    if (isValidHttpUrl(text)) return text;
    try {
      return extractShortUrl(JSON.parse(text));
    } catch {
      return null;
    }
  }

  const candidates = [
    payload?.shortenedUrl,
    payload?.shortUrl,
    payload?.shortened_url,
    payload?.url,
    payload?.data?.shortenedUrl,
    payload?.data?.shortUrl,
    payload?.data?.shortened_url,
    payload?.data?.url,
    payload?.result?.shortenedUrl,
    payload?.result?.shortUrl,
    payload?.result?.url,
  ];

  const found = candidates.find((value) => typeof value === 'string' && isValidHttpUrl(value));
  return found || null;
}

app.get('/health', (_req, res) => {
  res.json({
    success: true,
    service: 'tdmdev-backend',
    status: 'ok',
    time: nowIso(),
  });
});

app.get('/api/config/public', (_req, res) => {
  res.json({
    success: true,
    tools: adminConfig.tools,
    banner: adminConfig.banner,
    updatedAt: adminConfig.updatedAt,
  });
});

app.post('/api/link4m/shorten', async (req, res) => {
  const { apiKey, url } = req.body || {};
  if (!apiKey || !isValidHttpUrl(url)) {
    return jsonError(res, 400, 'apiKey và url là bắt buộc; url phải là HTTP/HTTPS.', 'VALIDATION_ERROR');
  }
  if (adminConfig.tools.link4m === false) {
    return jsonError(res, 503, 'Công cụ Link4M đang tạm tắt.', 'TOOL_DISABLED');
  }
  if (!providerRateLimit(`link4m:${getClientKey(req)}`)) {
    return jsonError(res, 429, 'Quá nhiều yêu cầu Link4M. Hãy thử lại sau.', 'RATE_LIMITED');
  }

  const apiUrl = 'https://link4m.co/api-shorten/v2';

  try {
    // Link4M endpoint is intentionally fixed to the provider contract:
    // GET https://link4m.co/api-shorten/v2?api=YOUR_API_KEY&url=DESTINATION_URL
    const providerResponse = await axios.get(apiUrl, {
      params: { api: apiKey, url },
      timeout: 20_000,
      headers: { Accept: 'application/json' },
    });

    const shortUrl = extractShortUrl(providerResponse.data);
    if (!shortUrl) {
      return jsonError(res, 502, 'Link4M trả về dữ liệu nhưng không tìm thấy URL rút gọn.', 'PROVIDER_RESPONSE', {
        providerResponse: providerResponse.data,
      });
    }

    return res.json({ success: true, shortUrl });
  } catch (error) {
    const providerMessage = error.response?.data?.message || error.response?.data?.error || error.message;
    return jsonError(res, 502, `Không lấy được link rút gọn từ Link4M: ${providerMessage}`, 'PROVIDER_ERROR');
  }
});

const mailTmSessions = new Map();
const MAIL_TM_BASE_URL = process.env.MAIL_TM_BASE_URL || 'https://api.mail.tm';
const MAIL_TM_SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const MAIL_TM_DETAIL_LIMIT = 10; // mail.tm giới hạn ~8 request/giây/IP, nên chỉ lấy chi tiết cho thư mới nhất.

function pruneMailTmSessions() {
  const cutoff = Date.now() - MAIL_TM_SESSION_TTL_MS;
  for (const [key, session] of mailTmSessions) {
    if (session.createdMs < cutoff) mailTmSessions.delete(key);
  }
}

async function mailTmRequest(config) {
  const response = await axios({
    ...config,
    baseURL: MAIL_TM_BASE_URL,
    timeout: 20_000,
    headers: {
      Accept: 'application/json',
      ...(config.headers || {}),
    },
  });
  return response.data;
}

function mailTmErrorMessage(error) {
  const data = error.response?.data;
  return data?.['hydra:description'] || data?.message || data?.detail || error.message;
}

app.post('/api/tempmail/create', async (req, res) => {
  if (adminConfig.tools.tempmail === false) {
    return jsonError(res, 503, 'Công cụ TempMail đang tạm tắt.', 'TOOL_DISABLED');
  }
  if (!providerRateLimit(`tempmail-create:${getClientKey(req)}`, 30)) {
    return jsonError(res, 429, 'Bạn tạo quá nhiều mailbox. Hãy thử lại sau.', 'RATE_LIMITED');
  }

  try {
    const domainsPayload = await mailTmRequest({ method: 'GET', url: '/domains' });
    const domains = Array.isArray(domainsPayload?.['hydra:member'])
      ? domainsPayload['hydra:member']
      : Array.isArray(domainsPayload?.domains)
        ? domainsPayload.domains
        : Array.isArray(domainsPayload)
          ? domainsPayload
          : [];
    const activeDomains = domains.filter((item) => item?.isActive === true && item?.isPrivate !== true && typeof item?.domain === 'string' && item.domain.trim());
    if (!activeDomains.length) throw new Error('Mail.tm hiện không cung cấp domain công khai đang hoạt động.');

    // Chọn ngẫu nhiên trong các domain công khai đang hoạt động, không cần API key.
    const activeDomain = activeDomains[crypto.randomInt(activeDomains.length)];
    const localPart = `tdm${crypto.randomBytes(7).toString('hex')}`;
    const email = `${localPart}@${activeDomain.domain}`.toLowerCase();
    const password = `${crypto.randomBytes(24).toString('base64url')}A9!`;

    await mailTmRequest({
      method: 'POST',
      url: '/accounts',
      headers: { 'Content-Type': 'application/json' },
      data: { address: email, password },
    });

    const tokenPayload = await mailTmRequest({
      method: 'POST',
      url: '/token',
      headers: { 'Content-Type': 'application/json' },
      data: { address: email, password },
    });
    const token = tokenPayload?.token;
    if (!token) throw new Error('Mail.tm không trả về Bearer Token.');

    pruneMailTmSessions();
    mailTmSessions.set(email, { email, token, createdMs: Date.now() });
    console.log(`[TempMail] Mailbox created: ${email} (domain=${activeDomain.domain})`);
    // Trả token về cho trình duyệt giữ: backend restart/redeploy trên Railway sẽ không làm mất hộp thư nữa.
    return res.json({ success: true, email, token, provider: 'mail.tm' });
  } catch (error) {
    const message = mailTmErrorMessage(error);
    console.error('[TempMail] Mail.tm create failed:', error.response?.status || error.code || '', message);
    return jsonError(res, 502, `Không thể tạo email tạm thời qua Mail.tm: ${message}`, 'TEMPMAIL_PROVIDER_ERROR', {
      providerStatus: error.response?.status || null,
    });
  }
});

app.get('/api/tempmail/messages', async (req, res) => {
  const email = String(req.query.email || '').trim().toLowerCase();
  if (!email) return jsonError(res, 400, 'Query email là bắt buộc.', 'VALIDATION_ERROR');
  if (adminConfig.tools.tempmail === false) return jsonError(res, 503, 'Công cụ TempMail đang tạm tắt.', 'TOOL_DISABLED');
  if (!providerRateLimit(`tempmail-messages:${getClientKey(req)}`, 90)) {
    return jsonError(res, 429, 'Bạn đang refresh hộp thư quá nhanh.', 'RATE_LIMITED');
  }

  // Ưu tiên token do trình duyệt gửi lên; fallback sang phiên lưu trong RAM (tương thích bản cũ).
  const token = String(req.get('x-mailbox-token') || '').trim() || mailTmSessions.get(email)?.token;
  if (!token) {
    return jsonError(res, 404, 'Không tìm thấy phiên hộp thư này. Hãy tạo email mới.', 'MAILBOX_NOT_FOUND');
  }

  try {
    const authHeaders = { Authorization: `Bearer ${token}` };
    const listPayload = await mailTmRequest({ method: 'GET', url: '/messages', headers: authHeaders });
    const messageList = Array.isArray(listPayload?.['hydra:member'])
      ? listPayload['hydra:member']
      : Array.isArray(listPayload?.messages)
        ? listPayload.messages
        : [];

    const toText = (item) => (Array.isArray(item?.to) ? item.to.map((x) => x?.address).filter(Boolean).join(', ') : '');

    const messages = await Promise.all(messageList.slice(0, 30).map(async (message, index) => {
      const summary = {
        id: message?.id,
        subject: message?.subject || '(Không có tiêu đề)',
        from_email: message?.from?.address || '',
        from_name: message?.from?.name || '',
        to: toText(message),
        receivedAt: message?.createdAt || null,
        intro: message?.intro || '',
        content: message?.intro || '',
      };
      if (!message?.id || index >= MAIL_TM_DETAIL_LIMIT) return summary;
      try {
        const detail = await mailTmRequest({
          method: 'GET',
          url: `/messages/${encodeURIComponent(message.id)}`,
          headers: authHeaders,
        });
        const from = detail?.from || message?.from || {};
        return {
          id: detail?.id || message.id,
          subject: detail?.subject || summary.subject,
          from_email: from?.address || '',
          from_name: from?.name || '',
          to: toText(detail) || summary.to,
          receivedAt: detail?.createdAt || summary.receivedAt,
          intro: detail?.intro || summary.intro,
          textBody: detail?.text || '',
          htmlBody: Array.isArray(detail?.html) ? detail.html.join('\n') : (detail?.html || ''),
          content: detail?.text || detail?.intro || '',
        };
      } catch {
        return summary;
      }
    }));

    console.log(`[TempMail] Inbox checked: ${email}; messages=${messageList.length}`);
    return res.json({
      success: true,
      provider: 'mail.tm',
      email,
      totalItems: Number.isFinite(listPayload?.['hydra:totalItems']) ? listPayload['hydra:totalItems'] : messageList.length,
      messages,
      checkedAt: nowIso(),
    });
  } catch (error) {
    const status = error.response?.status;
    const message = mailTmErrorMessage(error);
    console.error('[TempMail] Mail.tm inbox failed:', email, status || error.code || '', message);
    if (status === 401) {
      return jsonError(res, 404, 'Phiên Mail.tm đã hết hạn. Hãy tạo email mới.', 'MAILBOX_NOT_FOUND', { providerStatus: status });
    }
    if (status === 429) {
      return jsonError(res, 429, 'Mail.tm đang giới hạn tốc độ. Đợi vài giây rồi thử lại.', 'RATE_LIMITED', { providerStatus: status });
    }
    return jsonError(res, 502, `Không thể lấy hộp thư Mail.tm: ${message}`, 'TEMPMAIL_PROVIDER_ERROR', { providerStatus: status || null });
  }
});

// ---------------------------------------------------------------------------
// SendMail
// Railway gói Free/Trial/Hobby CHẶN SMTP (cổng 25/465/587) -> nodemailer báo "Connection timeout".
// Vì vậy mặc định gửi qua HTTPS API (Brevo hoặc Resend). SMTP chỉ dùng được trên gói Pro.
// ---------------------------------------------------------------------------
const BREVO_API_URL = process.env.BREVO_API_URL || 'https://api.brevo.com/v3/smtp/email';
const RESEND_API_URL = process.env.RESEND_API_URL || 'https://api.resend.com/emails';

function getMailProvider() {
  const forced = String(process.env.MAIL_PROVIDER || '').trim().toLowerCase();
  if (forced) return forced;
  if (process.env.BREVO_API_KEY) return 'brevo';
  if (process.env.RESEND_API_KEY) return 'resend';
  return 'smtp';
}

function getSender() {
  const email = String(process.env.MAIL_FROM || process.env.GMAIL_USER || '').trim();
  const name = String(process.env.MAIL_FROM_NAME || 'TDM Dev').trim();
  return { email, name };
}

async function sendViaBrevo({ to, subject, body, isHtml, file }) {
  const apiKey = String(process.env.BREVO_API_KEY || '').trim();
  const sender = getSender();
  if (!apiKey) throw new Error('Chưa cấu hình BREVO_API_KEY trên Railway.');
  if (!sender.email) throw new Error('Chưa cấu hình MAIL_FROM (email người gửi đã xác minh trong Brevo).');

  const payload = {
    sender: { name: sender.name, email: sender.email },
    to: [{ email: to }],
    subject,
    ...(isHtml ? { htmlContent: body } : { textContent: body }),
    ...(file ? { attachment: [{ name: file.originalname, content: file.buffer.toString('base64') }] } : {}),
  };
  const response = await axios.post(BREVO_API_URL, payload, {
    headers: { 'api-key': apiKey, accept: 'application/json', 'content-type': 'application/json' },
    timeout: 30_000,
    maxBodyLength: Infinity,
    maxContentLength: Infinity,
  });
  return { messageId: response.data?.messageId || '', accepted: [to], rejected: [] };
}

async function sendViaResend({ to, subject, body, isHtml, file }) {
  const apiKey = String(process.env.RESEND_API_KEY || '').trim();
  const sender = getSender();
  if (!apiKey) throw new Error('Chưa cấu hình RESEND_API_KEY trên Railway.');
  if (!sender.email) throw new Error('Chưa cấu hình MAIL_FROM (địa chỉ thuộc domain đã verify trên Resend).');

  const payload = {
    from: `${sender.name} <${sender.email}>`,
    to: [to],
    subject,
    ...(isHtml ? { html: body } : { text: body }),
    ...(file ? { attachments: [{ filename: file.originalname, content: file.buffer.toString('base64') }] } : {}),
  };
  const response = await axios.post(RESEND_API_URL, payload, {
    headers: { Authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' },
    timeout: 30_000,
    maxBodyLength: Infinity,
    maxContentLength: Infinity,
  });
  return { messageId: response.data?.id || '', accepted: [to], rejected: [] };
}

function buildTransporter(userGmail, userAppPass) {
  const gmailUser = String(userGmail || process.env.GMAIL_USER || '').trim();
  const appPass = String(userAppPass || process.env.GMAIL_APP_PASS || '').trim();
  if (!gmailUser || !appPass || gmailUser === 'your_gmail@gmail.com' || appPass === 'your_16_digit_app_password') {
    throw new Error('Gmail SMTP chưa được cấu hình. Hãy đặt GMAIL_USER và GMAIL_APP_PASS trên Railway.');
  }
  return {
    user: gmailUser,
    transporter: nodemailer.createTransport({
      service: 'gmail',
      auth: { user: gmailUser, pass: appPass },
      connectionTimeout: 10_000,
      greetingTimeout: 10_000,
      socketTimeout: 30_000,
    }),
  };
}

async function sendViaSmtp({ to, subject, body, isHtml, file, userGmail, userAppPass }) {
  const { user, transporter } = buildTransporter(userGmail, userAppPass);
  const info = await transporter.sendMail({
    from: user,
    to,
    subject,
    ...(isHtml ? { html: body } : { text: body }),
    ...(file ? { attachments: [{ filename: file.originalname, content: file.buffer, contentType: file.mimetype }] } : {}),
  });
  return { messageId: info.messageId, accepted: info.accepted, rejected: info.rejected };
}

function describeMailError(error) {
  const data = error.response?.data;
  if (data) return data.message || data.error || data.detail || JSON.stringify(data).slice(0, 300);
  const networkCodes = ['ETIMEDOUT', 'ECONNECTION', 'ESOCKET', 'ECONNREFUSED', 'ENETUNREACH', 'EHOSTUNREACH'];
  if (networkCodes.includes(error.code) || /timeout/i.test(error.message || '')) {
    return `${error.message}. Railway gói Free/Trial/Hobby chặn cổng SMTP; hãy đặt BREVO_API_KEY (hoặc RESEND_API_KEY) để gửi qua HTTPS.`;
  }
  return error.message;
}

app.post('/api/sendmail', upload.single('attachment'), async (req, res) => {
  if (adminConfig.tools.sendmail === false) return jsonError(res, 503, 'Công cụ SendMail đang tạm tắt.', 'TOOL_DISABLED');
  if (!providerRateLimit(`sendmail:${getClientKey(req)}`, 20, 60_000)) {
    return jsonError(res, 429, 'Gửi email quá nhanh. Hãy thử lại sau.', 'RATE_LIMITED');
  }

  const toEmail = String(req.body?.toEmail || '').trim();
  const subject = String(req.body?.subject || '').trim();
  const body = String(req.body?.body || '');
  const isHtml = String(req.body?.isHtml || 'false') === 'true';
  const userGmail = String(req.body?.userGmail || '').trim();
  const userAppPass = String(req.body?.userAppPass || '').trim();

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(toEmail)) return jsonError(res, 400, 'Địa chỉ nhận không hợp lệ.', 'VALIDATION_ERROR');
  if (!subject) return jsonError(res, 400, 'Tiêu đề không được để trống.', 'VALIDATION_ERROR');
  if (!body.trim()) return jsonError(res, 400, 'Nội dung không được để trống.', 'VALIDATION_ERROR');

  const provider = getMailProvider();
  const message = { to: toEmail, subject, body, isHtml, file: req.file, userGmail, userAppPass };

  try {
    let result;
    if (provider === 'brevo') result = await sendViaBrevo(message);
    else if (provider === 'resend') result = await sendViaResend(message);
    else if (provider === 'smtp') result = await sendViaSmtp(message);
    else throw new Error(`MAIL_PROVIDER không hợp lệ: "${provider}" (dùng brevo, resend hoặc smtp).`);

    // Trước đây server luôn giữ response 15 giây. Giờ mặc định 0; đặt SEND_DELAY_MS=15000 nếu muốn giữ hành vi cũ.
    const delayMs = Number.parseInt(process.env.SEND_DELAY_MS || '0', 10) || 0;
    if (delayMs > 0) await sleep(Math.min(delayMs, 60_000));

    console.log(`[SendMail] Sent via ${provider} -> ${toEmail} (id=${result.messageId || 'n/a'})`);
    return res.json({ success: true, message: 'Gửi thành công', provider, ...result });
  } catch (error) {
    console.error(`[SendMail] Failed via ${provider}:`, error.response?.status || error.code || '', describeMailError(error));
    return jsonError(res, 502, `Gửi email thất bại (${provider}): ${describeMailError(error)}`, 'MAIL_SEND_ERROR');
  }
});

function tcpCheck(host, port, timeoutMs = 5000) {
  return new Promise((resolve) => {
    const started = Date.now();
    const socket = net.createConnection({ host, port });
    const done = (result) => { socket.destroy(); resolve({ host, port, ...result, ms: Date.now() - started }); };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => done({ ok: true }));
    socket.once('timeout', () => done({ ok: false, error: 'timeout' }));
    socket.once('error', (err) => done({ ok: false, error: err.code || err.message }));
  });
}

// Chẩn đoán nhanh trên Railway: GET /api/admin/diagnostics?token=ADMIN_TOKEN
app.get('/api/admin/diagnostics', requireAdmin, async (_req, res) => {
  const startedAt = Date.now();
  let mailTm;
  try {
    const response = await axios.get(`${MAIL_TM_BASE_URL}/domains`, { timeout: 10_000 });
    mailTm = { ok: true, status: response.status, ms: Date.now() - startedAt };
  } catch (error) {
    mailTm = { ok: false, status: error.response?.status || null, error: error.code || error.message, ms: Date.now() - startedAt };
  }
  const smtp587 = await tcpCheck('smtp.gmail.com', 587);
  const provider = getMailProvider();
  res.json({
    success: true,
    node: process.version,
    mailProvider: provider,
    config: {
      BREVO_API_KEY: Boolean(process.env.BREVO_API_KEY),
      RESEND_API_KEY: Boolean(process.env.RESEND_API_KEY),
      MAIL_FROM: Boolean(process.env.MAIL_FROM),
      GMAIL_USER: Boolean(process.env.GMAIL_USER),
      GMAIL_APP_PASS: Boolean(process.env.GMAIL_APP_PASS),
      CORS_ORIGINS: allowedOrigins,
    },
    checks: { mailTm, smtpGmail587: smtp587 },
    hint: provider === 'smtp' && !smtp587.ok
      ? 'Cổng SMTP bị chặn (Railway Free/Trial/Hobby). Hãy đặt BREVO_API_KEY + MAIL_FROM.'
      : undefined,
  });
});

app.post('/api/admin/login', (req, res) => {
  const expected = String(process.env.ADMIN_TOKEN || '').trim();
  const token = String(req.body?.token || '').trim();
  if (!expected || !token || Buffer.byteLength(token) !== Buffer.byteLength(expected) || !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected))) {
    return jsonError(res, 401, 'Admin token không hợp lệ.', 'UNAUTHORIZED');
  }
  return res.json({ success: true, message: 'Đăng nhập thành công' });
});

app.get('/api/admin/config', requireAdmin, (_req, res) => {
  res.json({ success: true, ...adminConfig });
});

app.post('/api/admin/config', requireAdmin, (req, res) => {
  const nextTools = req.body?.tools && typeof req.body.tools === 'object' ? req.body.tools : {};
  for (const key of Object.keys(adminConfig.tools)) {
    if (typeof nextTools[key] === 'boolean') adminConfig.tools[key] = nextTools[key];
  }
  if (typeof req.body?.banner === 'string') adminConfig.banner = req.body.banner.slice(0, 500);
  adminConfig.updatedAt = nowIso();
  return res.json({ success: true, ...adminConfig });
});

app.use((error, _req, res, next) => {
  if (res.headersSent) return next(error);
  if (error instanceof multer.MulterError) {
    return jsonError(res, 413, `File upload lỗi: ${error.message}`, 'UPLOAD_ERROR');
  }
  if (error.message === 'CORS origin not allowed') {
    return jsonError(res, 403, 'Origin không được phép bởi CORS.', 'CORS_ERROR');
  }
  console.error(error);
  return jsonError(res, 500, 'Internal server error.', 'INTERNAL_ERROR');
});

app.use((_req, res) => {
  res.status(404).json({ success: false, code: 'NOT_FOUND', message: 'API endpoint not found.' });
});

app.listen(port, () => {
  console.log(`TDM Dev backend listening on port ${port}`);
  console.log(`Health: http://localhost:${port}/health`);
  console.log(`[SendMail] provider=${getMailProvider()}`);
});

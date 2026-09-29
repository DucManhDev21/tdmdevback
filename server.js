const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const nodemailer = require('nodemailer');
const multer = require('multer');
const axios = require('axios');
const crypto = require('crypto');

const envResult = dotenv.config();
if (envResult.error && envResult.error.code !== 'ENOENT') {
  console.warn('dotenv warning:', envResult.error.message);
}

const app = express();
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
  allowedHeaders: ['Content-Type', 'Accept', 'Authorization'],
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

const tempMailSessions = new Map();
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

function splitEmail(email) {
  const [login, ...domainParts] = String(email || '').trim().toLowerCase().split('@');
  const domain = domainParts.join('@');
  if (!login || !domain || domainParts.length < 1) throw new Error('Địa chỉ email tạm không hợp lệ.');
  return { login, domain };
}

async function secMailRequest(config) {
  const token = String(process.env.TEMPMAIL_API_TOKEN || '').trim();
  if (!token) throw new Error('TEMPMAIL_API_TOKEN chưa được cấu hình trên Railway.');
  const baseUrl = 'https://api.1secmail.com';
  const response = await axios({
    ...config,
    baseURL: baseUrl,
    timeout: 20_000,
    headers: {
      Accept: 'application/json',
      ...(config.headers || {}),
    },
  });
  return response.data;
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

  const apiUrl = String(process.env.LINK4M_API_URL || '').trim();
  const method = String(process.env.LINK4M_API_METHOD || 'GET').toUpperCase();
  const apiKeyParam = String(process.env.LINK4M_API_KEY_PARAM || 'api');
  const urlParam = String(process.env.LINK4M_URL_PARAM || 'url');
  const formatParam = String(process.env.LINK4M_FORMAT_PARAM || 'format');
  const formatValue = String(process.env.LINK4M_FORMAT_VALUE || 'json');

  if (!apiUrl) {
    return jsonError(res, 500, 'LINK4M_API_URL chưa được cấu hình.', 'CONFIG_ERROR');
  }

  try {
    const query = {
      [apiKeyParam]: apiKey,
      [urlParam]: url,
      [formatParam]: formatValue,
    };

    let providerResponse;
    if (method === 'POST') {
      providerResponse = await axios.post(apiUrl, new URLSearchParams(query).toString(), {
        timeout: 20_000,
        headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
      });
    } else {
      providerResponse = await axios.get(apiUrl, {
        params: query,
        timeout: 20_000,
        headers: { Accept: 'application/json' },
      });
    }

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

app.post('/api/tempmail/create', async (req, res) => {
  if (adminConfig.tools.tempmail === false) {
    return jsonError(res, 503, 'Công cụ TempMail đang tạm tắt.', 'TOOL_DISABLED');
  }
  if (!providerRateLimit(`tempmail-create:${getClientKey(req)}`, 30)) {
    return jsonError(res, 429, 'Bạn tạo quá nhiều mailbox. Hãy thử lại sau.', 'RATE_LIMITED');
  }

  try {
    const data = await secMailRequest({
      method: 'POST',
      url: `/api/emails/${encodeURIComponent(process.env.TEMPMAIL_API_TOKEN)}`,
    });

    const email = data?.data?.email || data?.email;
    if (!email) throw new Error(data?.message || '1SecMail không trả về email.');

    tempMailSessions.set(email.toLowerCase(), {
      email,
      createdAt: nowIso(),
    });

    return res.json({ success: true, email });
  } catch (error) {
    const message = error.response?.data?.message || error.response?.data?.error || error.message;
    return jsonError(res, 502, `Không thể tạo email tạm thời: ${message}`, 'TEMPMAIL_PROVIDER_ERROR');
  }
});

app.get('/api/tempmail/messages', async (req, res) => {
  const email = String(req.query.email || '').trim().toLowerCase();
  if (!email) return jsonError(res, 400, 'Query email là bắt buộc.', 'VALIDATION_ERROR');
  if (adminConfig.tools.tempmail === false) return jsonError(res, 503, 'Công cụ TempMail đang tạm tắt.', 'TOOL_DISABLED');
  if (!providerRateLimit(`tempmail-messages:${getClientKey(req)}`, 90)) {
    return jsonError(res, 429, 'Bạn đang refresh hộp thư quá nhanh.', 'RATE_LIMITED');
  }

  try {
    const { login, domain } = splitEmail(email);
    const listData = await secMailRequest({
      method: 'GET',
      url: `/api/messages/${encodeURIComponent(process.env.TEMPMAIL_API_TOKEN)}/${encodeURIComponent(email)}`,
    });

    const messageList = Array.isArray(listData?.messages)
      ? listData.messages
      : Array.isArray(listData?.data?.messages)
        ? listData.data.messages
        : Array.isArray(listData)
          ? listData
          : [];

    const messages = await Promise.all(messageList.slice(0, 30).map(async (message) => {
      if (!message?.id) return message;
      try {
        const detail = await secMailRequest({
          method: 'GET',
          url: `/api/messages/${encodeURIComponent(process.env.TEMPMAIL_API_TOKEN)}/message/${encodeURIComponent(message.id)}`,
        });
        return detail?.message || detail?.data?.message || message;
      } catch {
        return message;
      }
    }));

    return res.json({
      success: true,
      email,
      login,
      domain,
      messages,
      checkedAt: nowIso(),
    });
  } catch (error) {
    const message = error.response?.data?.message || error.response?.data?.error || error.message;
    return jsonError(res, 502, `Không thể lấy hộp thư: ${message}`, 'TEMPMAIL_PROVIDER_ERROR');
  }
});

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
      connectionTimeout: 20_000,
      greetingTimeout: 20_000,
      socketTimeout: 30_000,
    }),
  };
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

  try {
    const { user, transporter } = buildTransporter(userGmail, userAppPass);
    const mailOptions = {
      from: user,
      to: toEmail,
      subject,
      ...(isHtml ? { html: body } : { text: body }),
      ...(req.file ? {
        attachments: [{
          filename: req.file.originalname,
          content: req.file.buffer,
          contentType: req.file.mimetype,
        }],
      } : {}),
    };

    const info = await transporter.sendMail(mailOptions);

    // Server delay intentionally mirrors the frontend requirement.
    // The response is held for 15 seconds after the SMTP provider accepts the message.
    await sleep(15_000);

    return res.json({
      success: true,
      message: 'Gửi thành công',
      messageId: info.messageId,
      accepted: info.accepted,
      rejected: info.rejected,
    });
  } catch (error) {
    return jsonError(res, 502, `Gửi email thất bại: ${error.message}`, 'SMTP_ERROR');
  }
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
});

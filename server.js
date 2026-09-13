'use strict';
require('dotenv').config({ quiet: true });
const express = require('express');
const crypto = require('node:crypto');
const path = require('node:path');
const { Pool } = require('pg');

const DAY = 86400000;
const MAX_PHOTO = 5 * 1024 * 1024;
const hash = value => crypto.createHash('sha256').update(String(value)).digest('hex');
const idOk = value => /^[1-9]\d{0,15}$/.test(String(value || ''));
const pinOk = value => typeof value === 'string' && /^\d{4}$/.test(value);
const validBody = value => typeof value === 'string' && value.trim().length > 0 && value.length <= 4096;
const equal = (a, b) => crypto.timingSafeEqual(Buffer.from(hash(a)), Buffer.from(hash(b)));

function configFromEnv(env = process.env) {
  let database;
  try { database = new URL(env.DATABASE_URL); } catch { throw Error('DATABASE_URL must be a PostgreSQL URL'); }
  if (!['postgres:', 'postgresql:'].includes(database.protocol)) throw Error('DATABASE_URL must be a PostgreSQL URL');
  if (!pinOk(env.PHONE_PIN)) throw Error('PHONE_PIN must contain exactly four digits');
  if (!/^\d+:[A-Za-z0-9_-]{20,}$/.test(env.TELEGRAM_BOT_TOKEN || '')) throw Error('TELEGRAM_BOT_TOKEN is invalid');
  if (!/^[A-Za-z0-9_-]{32,256}$/.test(env.TELEGRAM_WEBHOOK_SECRET || '')) throw Error('TELEGRAM_WEBHOOK_SECRET must be 32-256 URL-safe characters');
  if (env.ADMIN_TELEGRAM_ID && !idOk(env.ADMIN_TELEGRAM_ID)) throw Error('ADMIN_TELEGRAM_ID must be a positive private chat ID');
  const port = Number(env.PORT || 10000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw Error('PORT is invalid');
  return { databaseUrl: env.DATABASE_URL, pin: env.PHONE_PIN, botToken: env.TELEGRAM_BOT_TOKEN,
    webhookSecret: env.TELEGRAM_WEBHOOK_SECRET, adminId: env.ADMIN_TELEGRAM_ID || '', port };
}

// ALTER statements upgrade the schema shipped by the original prototype without deleting history.
const schema = `
CREATE TABLE IF NOT EXISTS chats (
  id text PRIMARY KEY, name text NOT NULL, username text NOT NULL DEFAULT '',
  unread integer NOT NULL DEFAULT 0, updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS messages (
  id bigserial PRIMARY KEY, chat_id text REFERENCES chats(id), direction text NOT NULL,
  body text NOT NULL DEFAULT '', photo boolean NOT NULL DEFAULT false, file_id text,
  created_at timestamptz NOT NULL DEFAULT now(), client_id text, UNIQUE(chat_id, client_id)
);
ALTER TABLE chats ADD COLUMN IF NOT EXISTS last_read_id bigint NOT NULL DEFAULT 0;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS delivery text NOT NULL DEFAULT 'sent';
ALTER TABLE messages ADD COLUMN IF NOT EXISTS telegram_message_id bigint;
CREATE INDEX IF NOT EXISTS messages_chat_id_idx ON messages(chat_id, id);
CREATE INDEX IF NOT EXISTS messages_created_idx ON messages(created_at);
CREATE TABLE IF NOT EXISTS sessions(token_hash text PRIMARY KEY, expires_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS telegram_updates(id bigint PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS login_limits(ip text PRIMARY KEY, attempts integer NOT NULL DEFAULT 0, window_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS notifications (
  name text PRIMARY KEY, lease_until timestamptz NOT NULL, cooldown_until timestamptz NOT NULL,
  owner text NOT NULL, status text NOT NULL
);
`;

async function transaction(pool, action) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await action(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    try { await client.query('ROLLBACK'); } catch { /* The connection may already be gone. */ }
    throw error;
  } finally { client.release(); }
}

async function cleanup(pool, now = new Date()) {
  const cutoff = new Date(now.getTime() - 30 * DAY);
  await transaction(pool, async db => {
    await db.query('DELETE FROM messages WHERE created_at < $1', [cutoff]);
    await db.query('DELETE FROM telegram_updates WHERE created_at < $1', [cutoff]);
    await db.query('DELETE FROM sessions WHERE expires_at <= $1', [now]);
    await db.query('DELETE FROM login_limits WHERE window_at < $1', [new Date(now.getTime() - DAY)]);
    // Old empty chats disappear; recent unsupported updates never create a chat.
    await db.query('DELETE FROM chats WHERE updated_at < $1 AND id NOT IN (SELECT chat_id FROM messages)', [cutoff]);
    await db.query("UPDATE messages SET delivery='unknown' WHERE delivery='pending' AND created_at < $1", [new Date(now.getTime() - 60000)]);
  });
}

async function boundedBody(response, maximum) {
  if (Number(response.headers.get('content-length')) > maximum) {
    await response.body?.cancel();
    throw Error('response too large');
  }
  if (!response.body) throw Error('empty response');
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > maximum) throw Error('response too large');
      chunks.push(Buffer.from(value));
    }
    return Buffer.concat(chunks);
  } finally {
    try { await reader.cancel(); } catch { /* Timeout may have already closed the stream. */ }
    reader.releaseLock();
  }
}

function telegramClient(config, fetcher = fetch) {
  return async (method, body) => {
    const response = await fetcher(`https://api.telegram.org/bot${config.botToken}/${method}`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
      signal: AbortSignal.timeout(15000), redirect: 'error'
    });
    const result = JSON.parse((await boundedBody(response, 128 * 1024)).toString('utf8'));
    if (typeof result.ok !== 'boolean') throw Error('invalid Telegram response');
    return result;
  };
}

function createApp({ pool, config = configFromEnv(), telegram = telegramClient(config), fetcher = fetch, clock = () => new Date() }) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1); // Render terminates TLS and supplies the final proxy address.
  app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Referrer-Policy', 'no-referrer');
    res.set('Content-Security-Policy', "default-src 'self'; img-src 'self' blob:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    next();
  });
  app.use(express.json({ limit: '64kb' }));
  const cutoff = () => new Date(clock().getTime() - 30 * DAY);
  async function auth(req, res, next) {
    const token = req.get('authorization')?.match(/^Bearer ([A-Za-z0-9_-]{43})$/)?.[1];
    if (!token) return res.status(401).json({ error: 'Сессия завершена. Введите PIN.' });
    const result = await pool.query('SELECT 1 FROM sessions WHERE token_hash=$1 AND expires_at>$2', [hash(token), clock()]);
    if (!result.rowCount) return res.status(401).json({ error: 'Сессия завершена. Введите PIN.' });
    req.tokenHash = hash(token);
    next();
  }

  async function notifyVisit() {
    if (!config.adminId) return;
    const now = clock(), owner = crypto.randomUUID();
    // Reserve cooldown BEFORE Telegram: timeout/crash must not cause a notification storm.
    const lease = await pool.query(`INSERT INTO notifications(name,lease_until,cooldown_until,owner,status)
      VALUES('visit',$1,$2,$3,'pending') ON CONFLICT(name) DO UPDATE
      SET lease_until=$1,cooldown_until=$2,owner=$3,status='pending'
      WHERE notifications.lease_until <= $4 AND notifications.cooldown_until <= $4 RETURNING name`,
    [new Date(now.getTime() + 60000), new Date(now.getTime() + 15 * 60000), owner, now]);
    if (!lease.rowCount) return;
    let status = 'unknown';
    try {
      const result = await telegram('sendMessage', { chat_id: config.adminId, text: 'Nokia CloudPhone: вход с правильным PIN.' });
      status = result.ok ? 'sent' : 'failed';
    } catch { /* Telegram may have accepted the notification; never replay automatically. */ }
    await pool.query('UPDATE notifications SET status=$1,lease_until=$2 WHERE name=$3 AND owner=$4', [status, clock(), 'visit', owner]);
  }

  app.get('/health', async (req, res) => {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  });
  app.post('/api/login', async (req, res) => {
    const device = req.body?.deviceId;
    if (typeof device !== 'string' || !/^[a-f0-9]{32}$/.test(device)) return res.status(400).json({ error: 'Некорректный идентификатор устройства.' });
    const now = clock(), windowStart = new Date(now.getTime() - 15 * 60000);
    const allowed = await transaction(pool, async db => {
      // Per-device limits don't lock all CloudPhone users behind one proxy. The global
      // budget is also necessary: an attacker can rotate both device IDs and IPs.
      let allowed = true;
      for (const [key, maximum] of [[`device:${hash(device)}`, 10], [`ip:${hash(req.ip)}`, 200], ['global', 300]]) {
        const result = await db.query(`INSERT INTO login_limits(ip,attempts,window_at) VALUES($1,1,$2)
          ON CONFLICT(ip) DO UPDATE SET attempts=CASE WHEN login_limits.window_at <= $3 THEN 1 ELSE login_limits.attempts+1 END,
          window_at=CASE WHEN login_limits.window_at <= $3 THEN $2 ELSE login_limits.window_at END RETURNING attempts`, [key, now, windowStart]);
        if (result.rows[0].attempts > maximum) allowed = false;
      }
      return allowed;
    });
    if (!allowed) return res.status(429).set('Retry-After', '900').json({ error: 'Слишком много попыток. Подождите 15 минут.' });
    if (!pinOk(req.body?.pin) || !equal(req.body.pin, config.pin)) return res.status(401).json({ error: 'Неверный PIN.' });
    const token = crypto.randomBytes(32).toString('base64url');
    await pool.query('INSERT INTO sessions(token_hash,expires_at) VALUES($1,$2)', [hash(token), new Date(now.getTime() + 12 * 3600000)]);
    // A notification failure must not prevent a valid login. Errors contain no secrets.
    try { await notifyVisit(); } catch { console.error('visit notification failed'); }
    res.json({ token });
  });
  app.post('/api/logout', auth, async (req, res) => {
    await pool.query('DELETE FROM sessions WHERE token_hash=$1', [req.tokenHash]);
    res.json({ ok: true });
  });
  app.get('/api/chats', auth, async (req, res) => {
    const result = await pool.query(`SELECT c.id,c.name,c.username,
      (SELECT count(*) FROM messages m WHERE m.chat_id=c.id AND m.direction='in' AND m.id>c.last_read_id AND m.created_at >= $1) AS unread
      FROM chats c WHERE c.id IN (SELECT chat_id FROM messages WHERE created_at >= $1)
      ORDER BY c.updated_at DESC,c.id`, [cutoff()]);
    res.json(result.rows);
  });
  app.get('/api/messages', auth, async (req, res) => {
    const chat = String(req.query.chat || ''), after = String(req.query.after || '0');
    if (!idOk(chat) || !/^\d{1,19}$/.test(after) || BigInt(after) > 9223372036854775807n) return res.status(400).json({ error: 'Некорректный чат или курсор.' });
    if (!(await pool.query('SELECT 1 FROM chats WHERE id=$1', [chat])).rowCount) return res.status(404).json({ error: 'Чат не найден.' });
    const result = await pool.query(`SELECT id,direction,body,photo,delivery,client_id AS "clientId",created_at AS "createdAt"
      FROM messages WHERE chat_id=$1 AND id>$2 AND created_at >= $3 ORDER BY id LIMIT 100`, [chat, after, cutoff()]);
    res.json(result.rows.map(row => ({ ...row, id: String(row.id) })));
  });
  app.post('/api/read', auth, async (req, res) => {
    const chat = String(req.body?.chat || ''), lastId = String(req.body?.lastId || '');
    if (!idOk(chat) || !/^\d{1,19}$/.test(lastId) || BigInt(lastId) > 9223372036854775807n) return res.status(400).json({ error: 'Нужны chat и lastId.' });
    // Only a real, displayed message can advance the watermark. New arrivals remain unread.
    const result = await pool.query(`UPDATE chats SET last_read_id=GREATEST(last_read_id,$2)
      WHERE id=$1 AND EXISTS(SELECT 1 FROM messages WHERE chat_id=$1 AND id=$2 AND created_at >= $3) RETURNING id`, [chat, lastId, cutoff()]);
    if (!result.rowCount) return res.status(404).json({ error: 'Сообщение не найдено.' });
    res.json({ ok: true });
  });
  app.post('/api/messages', auth, async (req, res) => {
    const chat = String(req.body?.chat || ''), body = req.body?.body, client = req.body?.clientId;
    if (!idOk(chat) || !validBody(body) || typeof client !== 'string' || !/^[a-f0-9-]{32,36}$/.test(client)) return res.status(400).json({ error: 'Некорректное сообщение (1–4096 символов).' });
    const reserved = await transaction(pool, async db => {
      if (!(await db.query('SELECT id FROM chats WHERE id=$1 FOR UPDATE', [chat])).rowCount) return null;
      const result = await db.query(`INSERT INTO messages(chat_id,direction,body,client_id,delivery)
        VALUES($1,'out',$2,$3,'pending') ON CONFLICT(chat_id,client_id) DO NOTHING RETURNING id,body,delivery,created_at`, [chat, body, client]);
      if (result.rowCount) {
        await db.query('UPDATE chats SET updated_at=$2 WHERE id=$1', [chat, clock()]);
        return { ...result.rows[0], fresh: true };
      }
      return (await db.query('SELECT id,body,delivery,created_at FROM messages WHERE chat_id=$1 AND client_id=$2', [chat, client])).rows[0];
    });
    if (!reserved) return res.status(404).json({ error: 'Чат не найден.' });
    if (reserved.body !== body) return res.status(409).json({ error: 'Этот ключ отправки уже использован для другого текста.' });
    if (!reserved.fresh) {
      if (reserved.delivery === 'pending' && clock() - new Date(reserved.created_at) > 60000) {
        await pool.query("UPDATE messages SET delivery='unknown' WHERE id=$1 AND delivery='pending'", [reserved.id]);
        reserved.delivery = 'unknown';
      }
      return res.json({ id: String(reserved.id), delivery: reserved.delivery });
    }
    let delivery = 'unknown', telegramId = null;
    try {
      const result = await telegram('sendMessage', { chat_id: chat, text: body });
      if (result.ok === false) delivery = 'failed';
      if (result.ok === true && Number.isSafeInteger(result.result?.message_id)) {
        delivery = 'sent'; telegramId = result.result.message_id;
      }
    } catch { /* Unknown outcome: there is no Telegram idempotency key. */ }
    // If persistence fails after Telegram succeeds, the reservation still prevents a replay.
    await pool.query('UPDATE messages SET delivery=$2,telegram_message_id=$3 WHERE id=$1', [reserved.id, delivery, telegramId]);
    res.json({ id: String(reserved.id), delivery });
  });
  app.get('/api/photos/:id', auth, async (req, res) => {
    if (!/^\d{1,19}$/.test(req.params.id) || BigInt(req.params.id) > 9223372036854775807n) return res.status(400).json({ error: 'Некорректный номер фото.' });
    const result = await pool.query('SELECT file_id FROM messages WHERE id=$1 AND photo=true AND created_at >= $2', [req.params.id, cutoff()]);
    if (!result.rowCount) return res.status(404).json({ error: 'Фото удалено или не найдено.' });
    try {
      const file = await telegram('getFile', { file_id: result.rows[0].file_id });
      const filePath = file.result?.file_path;
      if (!file.ok || typeof filePath !== 'string' || !/^[A-Za-z0-9_/-]+\.[A-Za-z0-9]+$/.test(filePath) || filePath.includes('..') || file.result.file_size > MAX_PHOTO) throw Error('invalid file');
      const response = await fetcher(`https://api.telegram.org/file/bot${config.botToken}/${filePath}`, { signal: AbortSignal.timeout(15000), redirect: 'error' });
      if (!response.ok) throw Error('photo fetch failed');
      const bytes = await boundedBody(response, MAX_PHOTO);
      let mime;
      if (bytes.subarray(0, 3).equals(Buffer.from([255, 216, 255]))) mime = 'image/jpeg';
      else if (bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) mime = 'image/png';
      else if (['GIF87a', 'GIF89a'].includes(bytes.subarray(0, 6).toString())) mime = 'image/gif';
      else if (bytes.subarray(0, 4).toString() === 'RIFF' && bytes.subarray(8, 12).toString() === 'WEBP') mime = 'image/webp';
      else throw Error('unsupported image');
      // A second retention check covers a fetch that crosses the expiration boundary.
      if (!(await pool.query('SELECT 1 FROM messages WHERE id=$1 AND created_at >= $2', [req.params.id, cutoff()])).rowCount) return res.status(404).json({ error: 'Срок хранения фото истёк.' });
      res.type(mime).send(bytes);
    } catch { res.status(502).json({ error: 'Фото недоступно, слишком велико (максимум 5 МБ) или загрузка прервана. Повторите позже.' }); }
  });
  app.post('/telegram/webhook', async (req, res) => {
    if (!equal(req.get('X-Telegram-Bot-Api-Secret-Token') || '', config.webhookSecret)) return res.sendStatus(401);
    const update = req.body, message = update?.message;
    if (!Number.isSafeInteger(update?.update_id) || update.update_id < 0 || message?.chat?.type !== 'private' || !idOk(message.chat.id) || !idOk(message.from?.id) || message.from.is_bot) return res.sendStatus(200);
    const photo = Array.isArray(message.photo) ? message.photo.filter(p => typeof p.file_id === 'string' && (!p.file_size || p.file_size <= MAX_PHOTO)).at(-1) : null;
    const body = typeof message.text === 'string' ? message.text : typeof message.caption === 'string' ? message.caption : '';
    if (!body && !photo) return res.sendStatus(200);
    const name = [message.from.first_name, message.from.last_name].filter(x => typeof x === 'string').join(' ').slice(0, 256) || 'Без имени';
    await transaction(pool, async db => {
      const accepted = await db.query('INSERT INTO telegram_updates(id,created_at) VALUES($1,$2) ON CONFLICT(id) DO NOTHING RETURNING id', [update.update_id, clock()]);
      if (!accepted.rowCount) return;
      const chat = String(message.chat.id);
      await db.query(`INSERT INTO chats(id,name,username,updated_at) VALUES($1,$2,$3,$4)
        ON CONFLICT(id) DO UPDATE SET name=$2,username=$3,updated_at=$4`, [chat, name, typeof message.from.username === 'string' ? message.from.username.slice(0, 64) : '', clock()]);
      await db.query("INSERT INTO messages(chat_id,direction,body,photo,file_id,created_at) VALUES($1,'in',$2,$3,$4,$5)", [chat, body.slice(0, 4096), !!photo, photo?.file_id || null, clock()]);
    });
    res.sendStatus(200);
  });
  app.use('/api', (req, res) => res.status(404).json({ error: 'API не найден.' }));
  app.use(express.static(path.join(__dirname, 'public'), { etag: false, lastModified: false, cacheControl: false }));
  app.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    const status = error.type === 'entity.too.large' ? 413 : error.type === 'entity.parse.failed' ? 400 : 503;
    // Never log URLs, request bodies, DB connection strings or Telegram errors.
    if (status === 503) console.error('request failed');
    res.status(status).json({ error: status === 503 ? 'Сервис временно недоступен. Повторите запрос.' : 'Некорректный запрос.' });
  });
  return app;
}

async function main() {
  const config = configFromEnv();
  const pool = new Pool({ connectionString: config.databaseUrl, max: 5, connectionTimeoutMillis: 10000, query_timeout: 15000, statement_timeout: 15000 });
  pool.on('error', () => console.error('database connection failed'));
  await pool.query(schema);
  await cleanup(pool);
  let cleaning = false;
  const timer = setInterval(async () => {
    if (cleaning) return;
    cleaning = true;
    try { await cleanup(pool); } catch { console.error('retention cleanup failed'); } finally { cleaning = false; }
  }, 3600000);
  timer.unref();
  const server = createApp({ pool, config }).listen(config.port, () => console.log('CloudPhone listening'));
  for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => {
    clearInterval(timer);
    server.close(() => pool.end().finally(() => process.exit(0)));
    setTimeout(() => process.exit(1), 10000).unref();
  });
}
if (require.main === module) main().catch(() => { console.error('Startup failed. Check configuration and database access.'); process.exitCode = 1; });
module.exports = { createApp, configFromEnv, schema, cleanup, transaction, boundedBody, telegramClient, hash, pinOk, idOk, validBody };

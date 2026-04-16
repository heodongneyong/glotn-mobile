const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const USE_POSTGRES = Boolean(DATABASE_URL);
const ADMIN_ID = process.env.ADMIN_ID || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '1234';
const ADMIN_SESSION_MS = 1000 * 60 * 60 * 24; // 24h
const ADMIN_TOKEN_SECRET = process.env.ADMIN_TOKEN_SECRET || process.env.ADMIN_PASSWORD || 'change-this-secret';

let sqliteDb = null;
let pgPool = null;

if (USE_POSTGRES) {
  pgPool = new Pool({
    connectionString: DATABASE_URL,
    ssl: process.env.PGSSL_DISABLE === 'true' ? false : { rejectUnauthorized: false }
  });
} else {
  const sqlite3 = require('sqlite3').verbose();
  const dataDir = path.join(__dirname, 'data');
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
  const dbPath = path.join(dataDir, 'glotn_mobile.db');
  sqliteDb = new sqlite3.Database(dbPath);
}

app.use(express.json({ limit: '20mb' }));
app.use(cors());
app.use(express.static(__dirname));

function toPgPlaceholders(sql) {
  let index = 0;
  return sql.replace(/\?/g, () => `$${++index}`);
}

async function run(sql, params = []) {
  if (USE_POSTGRES) {
    const result = await pgPool.query(toPgPlaceholders(sql), params);
    return { rowCount: result.rowCount, rows: result.rows || [], lastID: result.rows?.[0]?.id };
  }

  return new Promise((resolve, reject) => {
    sqliteDb.run(sql, params, function onRun(error) {
      if (error) reject(error);
      else resolve(this);
    });
  });
}

async function all(sql, params = []) {
  if (USE_POSTGRES) {
    const result = await pgPool.query(toPgPlaceholders(sql), params);
    return result.rows;
  }

  return new Promise((resolve, reject) => {
    sqliteDb.all(sql, params, (error, rows) => {
      if (error) reject(error);
      else resolve(rows);
    });
  });
}

async function get(sql, params = []) {
  if (USE_POSTGRES) {
    const result = await pgPool.query(toPgPlaceholders(sql), params);
    return result.rows[0] || null;
  }

  return new Promise((resolve, reject) => {
    sqliteDb.get(sql, params, (error, row) => {
      if (error) reject(error);
      else resolve(row || null);
    });
  });
}

async function insertAndGetId(insertSql, params = []) {
  if (USE_POSTGRES) {
    const result = await run(`${insertSql} RETURNING id`, params);
    return result.lastID;
  }
  const result = await run(insertSql, params);
  return result.lastID;
}

function formatUsimRow(row) {
  return {
    id: row.id,
    submittedAt: row.submitted_at,
    name: row.name,
    birthDate: row.birth_date,
    phone: row.phone
  };
}

function formatResumeRow(row) {
  return {
    id: row.id,
    submittedAt: row.submitted_at,
    name: row.name,
    contactVisa: row.contact_visa,
    fileName: row.file_name,
    hasResumeFile: !!row.resume_file_data_url,
    status: row.status,
    resume: {
      position: row.position,
      summary: row.summary,
      experience: row.experience,
      skills: row.skills
    }
  };
}

function formatMobileApplicationRow(row) {
  return {
    id: row.id,
    submittedAt: row.submitted_at,
    applicationType: row.application_type,
    name: row.name,
    birthDate: row.birth_date,
    phone: row.phone,
    desiredModel: row.desired_model,
    carrier: row.carrier
  };
}

function formatPrepaidRow(row) {
  return {
    id: row.id,
    submittedAt: row.submitted_at,
    name: row.name,
    birthDate: row.birth_date,
    phone: row.phone,
    passportFileName: row.passport_file_name,
    passportFileDataUrl: row.passport_file_data_url
  };
}

function parseBase64DataUrl(dataUrl) {
  if (typeof dataUrl !== 'string') return null;
  const matched = dataUrl.match(/^data:([^;]+);base64,(.+)$/);
  if (!matched) return null;
  return {
    mimeType: (matched[1] || '').toLowerCase(),
    base64: matched[2]
  };
}

function isPdfBuffer(buffer) {
  if (!buffer || buffer.length < 5) return false;
  const signature = buffer.subarray(0, 5).toString('utf8');
  return signature === '%PDF-';
}

function parsePdfDataUrlOrNull(dataUrl) {
  const parsed = parseBase64DataUrl(dataUrl);
  if (!parsed) return null;

  let buffer;
  try {
    buffer = Buffer.from(parsed.base64, 'base64');
  } catch (error) {
    return null;
  }

  if (!isPdfBuffer(buffer)) return null;
  return { buffer };
}

function toBase64Url(value) {
  return Buffer.from(value)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function fromBase64Url(value) {
  if (typeof value !== 'string' || !value) return null;
  const padded = `${value}${'='.repeat((4 - (value.length % 4)) % 4)}`
    .replace(/-/g, '+')
    .replace(/_/g, '/');
  try {
    return Buffer.from(padded, 'base64').toString('utf8');
  } catch (error) {
    return null;
  }
}

function signAdminTokenPayload(payloadBase64) {
  return crypto.createHmac('sha256', ADMIN_TOKEN_SECRET).update(payloadBase64).digest('hex');
}

function createAdminToken() {
  const payload = {
    exp: Date.now() + ADMIN_SESSION_MS,
    iat: Date.now()
  };
  const payloadBase64 = toBase64Url(JSON.stringify(payload));
  const signature = signAdminTokenPayload(payloadBase64);
  return `${payloadBase64}.${signature}`;
}

function isValidAdminToken(token) {
  if (typeof token !== 'string' || !token.includes('.')) return false;
  const [payloadBase64, signature] = token.split('.', 2);
  if (!payloadBase64 || !signature) return false;

  const expectedSignature = signAdminTokenPayload(payloadBase64);
  if (signature !== expectedSignature) return false;

  const payloadJson = fromBase64Url(payloadBase64);
  if (!payloadJson) return false;

  try {
    const payload = JSON.parse(payloadJson);
    return typeof payload.exp === 'number' && Date.now() <= payload.exp;
  } catch (error) {
    return false;
  }
}

function requireAdmin(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
  if (!isValidAdminToken(token)) {
    return res.status(401).json({ message: '관리자 인증이 필요합니다.' });
  }
  next();
}

async function initDb() {
  if (USE_POSTGRES) {
    await run(`
      CREATE TABLE IF NOT EXISTS usim_complete_reports (
        id SERIAL PRIMARY KEY,
        submitted_at TEXT NOT NULL,
        name TEXT NOT NULL,
        birth_date TEXT NOT NULL,
        phone TEXT NOT NULL,
        created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW()))
      )
    `);
    await run(`ALTER TABLE usim_complete_reports ADD COLUMN IF NOT EXISTS created_at BIGINT`);
    await run(`UPDATE usim_complete_reports SET created_at = EXTRACT(EPOCH FROM NOW()) WHERE created_at IS NULL`);

    await run(`
      CREATE TABLE IF NOT EXISTS resume_submissions (
        id SERIAL PRIMARY KEY,
        submitted_at TEXT NOT NULL,
        name TEXT NOT NULL,
        contact_visa TEXT NOT NULL,
        file_name TEXT NOT NULL,
        resume_file_data_url TEXT,
        status TEXT NOT NULL,
        position TEXT NOT NULL,
        summary TEXT NOT NULL,
        experience TEXT NOT NULL,
        skills TEXT NOT NULL
      )
    `);
    await run(`ALTER TABLE resume_submissions ADD COLUMN IF NOT EXISTS resume_file_data_url TEXT`);

    await run(`
      CREATE TABLE IF NOT EXISTS mobile_applications (
        id SERIAL PRIMARY KEY,
        submitted_at TEXT NOT NULL,
        application_type TEXT NOT NULL,
        name TEXT NOT NULL,
        birth_date TEXT NOT NULL,
        phone TEXT NOT NULL,
        desired_model TEXT NOT NULL,
        carrier TEXT NOT NULL,
        created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW()))
      )
    `);
    await run(`ALTER TABLE mobile_applications ADD COLUMN IF NOT EXISTS created_at BIGINT`);
    await run(`UPDATE mobile_applications SET created_at = EXTRACT(EPOCH FROM NOW()) WHERE created_at IS NULL`);

    await run(`
      CREATE TABLE IF NOT EXISTS prepaid_submissions (
        id SERIAL PRIMARY KEY,
        submitted_at TEXT NOT NULL,
        name TEXT NOT NULL,
        birth_date TEXT NOT NULL,
        phone TEXT NOT NULL,
        passport_file_name TEXT NOT NULL,
        passport_file_data_url TEXT NOT NULL,
        created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW()))
      )
    `);
    await run(`ALTER TABLE prepaid_submissions ADD COLUMN IF NOT EXISTS created_at BIGINT`);
    await run(`UPDATE prepaid_submissions SET created_at = EXTRACT(EPOCH FROM NOW()) WHERE created_at IS NULL`);
    return;
  }

  await run(`
    CREATE TABLE IF NOT EXISTS usim_complete_reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      submitted_at TEXT NOT NULL,
      name TEXT NOT NULL,
      birth_date TEXT NOT NULL,
      phone TEXT NOT NULL,
      created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
    )
  `);
  const usimTableInfo = await all(`PRAGMA table_info(usim_complete_reports)`);
  if (!usimTableInfo.some((column) => column.name === 'created_at')) {
    await run(`ALTER TABLE usim_complete_reports ADD COLUMN created_at INTEGER`);
    await run(`UPDATE usim_complete_reports SET created_at = strftime('%s','now') WHERE created_at IS NULL`);
  }

  await run(`
    CREATE TABLE IF NOT EXISTS resume_submissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      submitted_at TEXT NOT NULL,
      name TEXT NOT NULL,
      contact_visa TEXT NOT NULL,
      file_name TEXT NOT NULL,
      resume_file_data_url TEXT,
      status TEXT NOT NULL,
      position TEXT NOT NULL,
      summary TEXT NOT NULL,
      experience TEXT NOT NULL,
      skills TEXT NOT NULL
    )
  `);
  const resumeTableInfo = await all(`PRAGMA table_info(resume_submissions)`);
  if (!resumeTableInfo.some((column) => column.name === 'resume_file_data_url')) {
    await run(`ALTER TABLE resume_submissions ADD COLUMN resume_file_data_url TEXT`);
  }

  await run(`
    CREATE TABLE IF NOT EXISTS mobile_applications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      submitted_at TEXT NOT NULL,
      application_type TEXT NOT NULL,
      name TEXT NOT NULL,
      birth_date TEXT NOT NULL,
      phone TEXT NOT NULL,
      desired_model TEXT NOT NULL,
      carrier TEXT NOT NULL,
      created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
    )
  `);
  const mobileTableInfo = await all(`PRAGMA table_info(mobile_applications)`);
  if (!mobileTableInfo.some((column) => column.name === 'created_at')) {
    await run(`ALTER TABLE mobile_applications ADD COLUMN created_at INTEGER`);
    await run(`UPDATE mobile_applications SET created_at = strftime('%s','now') WHERE created_at IS NULL`);
  }

  await run(`
    CREATE TABLE IF NOT EXISTS prepaid_submissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      submitted_at TEXT NOT NULL,
      name TEXT NOT NULL,
      birth_date TEXT NOT NULL,
      phone TEXT NOT NULL,
      passport_file_name TEXT NOT NULL,
      passport_file_data_url TEXT NOT NULL,
      created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
    )
  `);
  const prepaidTableInfo = await all(`PRAGMA table_info(prepaid_submissions)`);
  if (!prepaidTableInfo.some((column) => column.name === 'created_at')) {
    await run(`ALTER TABLE prepaid_submissions ADD COLUMN created_at INTEGER`);
    await run(`UPDATE prepaid_submissions SET created_at = strftime('%s','now') WHERE created_at IS NULL`);
  }
}

let dbInitPromise = null;
function ensureDbInitialized() {
  if (!dbInitPromise) {
    dbInitPromise = initDb();
  }
  return dbInitPromise;
}

app.use('/api', async (req, res, next) => {
  if (req.path === '/admin/login') {
    return next();
  }
  try {
    await ensureDbInitialized();
    next();
  } catch (error) {
    console.error('DB initialization failed:', error);
    res.status(500).json({ message: '서버 초기화 오류가 발생했습니다.' });
  }
});

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', database: USE_POSTGRES ? 'postgres' : 'sqlite' });
});

app.post('/api/admin/login', async (req, res) => {
  const { id, password } = req.body || {};
  if (id !== ADMIN_ID || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ message: '아이디 또는 비밀번호가 일치하지 않습니다.' });
  }
  const token = createAdminToken();
  res.json({ token });
});

app.get('/api/usim-complete', requireAdmin, async (req, res) => {
  try {
    const rows = await all('SELECT * FROM usim_complete_reports ORDER BY id DESC');
    res.json(rows.map(formatUsimRow));
  } catch (error) {
    res.status(500).json({ message: '유심 완료 내역 조회 실패' });
  }
});

app.post('/api/usim-complete', async (req, res) => {
  const { name, birthDate, phone } = req.body || {};
  if (!name || !birthDate || !phone) {
    return res.status(400).json({ message: '필수 값이 누락되었습니다.' });
  }

  try {
    // Prevent accidental duplicate writes from double-clicks/retries
    const latestSame = await get(
      `SELECT * FROM usim_complete_reports
       WHERE name = ? AND birth_date = ? AND phone = ? AND created_at >= ?
       ORDER BY id DESC LIMIT 1`,
      [name, birthDate, phone, Math.floor(Date.now() / 1000) - 10]
    );
    if (latestSame) {
      return res.json(formatUsimRow(latestSame));
    }

    const submittedAt = new Date().toLocaleString('ko-KR');
    const createdAt = Math.floor(Date.now() / 1000);
    const insertedId = await insertAndGetId(
      `INSERT INTO usim_complete_reports (submitted_at, name, birth_date, phone, created_at)
       VALUES (?, ?, ?, ?, ?)`,
      [submittedAt, name, birthDate, phone, createdAt]
    );
    const inserted = await get('SELECT * FROM usim_complete_reports WHERE id = ?', [insertedId]);
    res.status(201).json(formatUsimRow(inserted));
  } catch (error) {
    res.status(500).json({ message: '유심 완료 내역 저장 실패' });
  }
});

app.delete('/api/usim-complete/:id', requireAdmin, async (req, res) => {
  try {
    await run('DELETE FROM usim_complete_reports WHERE id = ?', [req.params.id]);
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ message: '유심 내역 삭제 실패' });
  }
});

app.get('/api/resumes', requireAdmin, async (req, res) => {
  try {
    const rows = await all('SELECT * FROM resume_submissions ORDER BY id DESC');
    res.json(rows.map(formatResumeRow));
  } catch (error) {
    res.status(500).json({ message: '이력서 내역 조회 실패' });
  }
});

app.post('/api/resumes', async (req, res) => {
  const { name, contactVisa, fileName, resumeFileDataUrl, status, position, summary, experience, skills } = req.body || {};
  if (!name || !contactVisa || !fileName || !resumeFileDataUrl || !status) {
    return res.status(400).json({ message: '필수 값이 누락되었습니다.' });
  }

  const parsedResumePdf = parsePdfDataUrlOrNull(resumeFileDataUrl);
  if (!parsedResumePdf) {
    return res.status(400).json({ message: '이력서 PDF 파일 형식이 올바르지 않습니다.' });
  }

  try {
    const submittedAt = new Date().toLocaleString('ko-KR');
    const insertedId = await insertAndGetId(
      `INSERT INTO resume_submissions (submitted_at, name, contact_visa, file_name, resume_file_data_url, status, position, summary, experience, skills)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        submittedAt,
        name,
        contactVisa,
        fileName,
        resumeFileDataUrl,
        status,
        position || '취업 지원',
        summary || `${name} 지원자의 기본 이력서입니다. 상담 후 상세 경력 업데이트 예정.`,
        experience || '추가 경력 정보 미입력',
        skills || '추가 기술 정보 미입력'
      ]
    );
    const inserted = await get('SELECT * FROM resume_submissions WHERE id = ?', [insertedId]);
    res.status(201).json(formatResumeRow(inserted));
  } catch (error) {
    res.status(500).json({ message: '이력서 내역 저장 실패' });
  }
});

app.patch('/api/resumes/:id/status', requireAdmin, async (req, res) => {
  const { status } = req.body || {};
  if (!status) return res.status(400).json({ message: '상태 값이 필요합니다.' });

  try {
    await run('UPDATE resume_submissions SET status = ? WHERE id = ?', [status, req.params.id]);
    const updated = await get('SELECT * FROM resume_submissions WHERE id = ?', [req.params.id]);
    if (!updated) return res.status(404).json({ message: '대상이 없습니다.' });
    res.json(formatResumeRow(updated));
  } catch (error) {
    res.status(500).json({ message: '이력서 상태 변경 실패' });
  }
});

app.delete('/api/resumes/:id', requireAdmin, async (req, res) => {
  try {
    await run('DELETE FROM resume_submissions WHERE id = ?', [req.params.id]);
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ message: '이력서 내역 삭제 실패' });
  }
});

app.get('/api/resumes/:id/file', requireAdmin, async (req, res) => {
  try {
    const row = await get('SELECT file_name, resume_file_data_url FROM resume_submissions WHERE id = ?', [req.params.id]);
    if (!row) {
      return res.status(404).json({ message: '대상이 없습니다.' });
    }

    const parsedResumePdf = parsePdfDataUrlOrNull(row.resume_file_data_url);
    if (!parsedResumePdf) {
      return res.status(400).json({ message: '저장된 이력서 파일이 PDF 형식이 아닙니다.' });
    }

    const encodedFileName = encodeURIComponent(row.file_name || 'resume.pdf');
    const isDownload = req.query.download === '1';
    const contentDisposition = isDownload ? 'attachment' : 'inline';

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Length', parsedResumePdf.buffer.length);
    res.setHeader('Content-Disposition', `${contentDisposition}; filename*=UTF-8''${encodedFileName}`);
    res.send(parsedResumePdf.buffer);
  } catch (error) {
    res.status(500).json({ message: '이력서 파일 조회 실패' });
  }
});

app.get('/api/mobile-applications', requireAdmin, async (req, res) => {
  try {
    const rows = await all('SELECT * FROM mobile_applications ORDER BY id DESC');
    res.json(rows.map(formatMobileApplicationRow));
  } catch (error) {
    res.status(500).json({ message: '모바일 신청 내역 조회 실패' });
  }
});

app.post('/api/mobile-applications', async (req, res) => {
  const {
    applicationType,
    name,
    birthDate,
    phone,
    desiredModel,
    carrier
  } = req.body || {};
  if (!applicationType || !name || !birthDate || !phone || !desiredModel || !carrier) {
    return res.status(400).json({ message: '필수 값이 누락되었습니다.' });
  }

  try {
    // Prevent accidental duplicate writes from double-clicks/retries
    const latestSame = await get(
      `SELECT * FROM mobile_applications
       WHERE application_type = ? AND name = ? AND birth_date = ? AND phone = ? AND desired_model = ? AND carrier = ? AND created_at >= ?
       ORDER BY id DESC LIMIT 1`,
      [applicationType, name, birthDate, phone, desiredModel, carrier, Math.floor(Date.now() / 1000) - 10]
    );
    if (latestSame) {
      return res.json(formatMobileApplicationRow(latestSame));
    }

    const submittedAt = new Date().toLocaleString('ko-KR');
    const createdAt = Math.floor(Date.now() / 1000);
    const insertedId = await insertAndGetId(
      `INSERT INTO mobile_applications (submitted_at, application_type, name, birth_date, phone, desired_model, carrier, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [submittedAt, applicationType, name, birthDate, phone, desiredModel, carrier, createdAt]
    );
    const inserted = await get('SELECT * FROM mobile_applications WHERE id = ?', [insertedId]);
    res.status(201).json(formatMobileApplicationRow(inserted));
  } catch (error) {
    res.status(500).json({ message: '모바일 신청 내역 저장 실패' });
  }
});

app.delete('/api/mobile-applications/:id', requireAdmin, async (req, res) => {
  try {
    await run('DELETE FROM mobile_applications WHERE id = ?', [req.params.id]);
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ message: '모바일 신청 내역 삭제 실패' });
  }
});

app.get('/api/prepaid-submissions', requireAdmin, async (req, res) => {
  try {
    const rows = await all('SELECT * FROM prepaid_submissions ORDER BY id DESC');
    res.json(rows.map(formatPrepaidRow));
  } catch (error) {
    res.status(500).json({ message: '선불 신청 내역 조회 실패' });
  }
});

app.post('/api/prepaid-submissions', async (req, res) => {
  const {
    name,
    birthDate,
    phone,
    passportFileName,
    passportFileDataUrl
  } = req.body || {};

  if (!name || !birthDate || !phone || !passportFileName || !passportFileDataUrl) {
    return res.status(400).json({ message: '필수 값이 누락되었습니다.' });
  }

  const parsedDataUrl = parseBase64DataUrl(passportFileDataUrl);
  if (!parsedDataUrl) {
    return res.status(400).json({ message: '여권 스캔본 PDF만 업로드할 수 있습니다.' });
  }

  let passportBuffer;
  try {
    passportBuffer = Buffer.from(parsedDataUrl.base64, 'base64');
  } catch (error) {
    return res.status(400).json({ message: '여권 파일 형식이 올바르지 않습니다.' });
  }

  if (!isPdfBuffer(passportBuffer)) {
    return res.status(400).json({ message: '여권 스캔본 PDF 파일만 업로드할 수 있습니다.' });
  }

  try {
    // Prevent accidental duplicate writes from double-clicks/retries
    const latestSame = await get(
      `SELECT * FROM prepaid_submissions
       WHERE name = ? AND birth_date = ? AND phone = ? AND passport_file_name = ? AND created_at >= ?
       ORDER BY id DESC LIMIT 1`,
      [name, birthDate, phone, passportFileName, Math.floor(Date.now() / 1000) - 10]
    );

    if (latestSame) {
      return res.json(formatPrepaidRow(latestSame));
    }

    const submittedAt = new Date().toLocaleString('ko-KR');
    const createdAt = Math.floor(Date.now() / 1000);
    const insertedId = await insertAndGetId(
      `INSERT INTO prepaid_submissions (submitted_at, name, birth_date, phone, passport_file_name, passport_file_data_url, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [submittedAt, name, birthDate, phone, passportFileName, passportFileDataUrl, createdAt]
    );
    const inserted = await get('SELECT * FROM prepaid_submissions WHERE id = ?', [insertedId]);
    res.status(201).json(formatPrepaidRow(inserted));
  } catch (error) {
    res.status(500).json({ message: '선불 신청 내역 저장 실패' });
  }
});

app.delete('/api/prepaid-submissions/:id', requireAdmin, async (req, res) => {
  try {
    await run('DELETE FROM prepaid_submissions WHERE id = ?', [req.params.id]);
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ message: '선불 신청 내역 삭제 실패' });
  }
});

app.get('/api/prepaid-submissions/:id/passport', requireAdmin, async (req, res) => {
  try {
    const row = await get('SELECT passport_file_name, passport_file_data_url FROM prepaid_submissions WHERE id = ?', [req.params.id]);
    if (!row) {
      return res.status(404).json({ message: '대상이 없습니다.' });
    }

    const parsedDataUrl = parseBase64DataUrl(row.passport_file_data_url);
    if (!parsedDataUrl) {
      return res.status(400).json({ message: '저장된 여권 파일 형식이 올바르지 않습니다.' });
    }

    const buffer = Buffer.from(parsedDataUrl.base64, 'base64');
    if (!isPdfBuffer(buffer)) {
      return res.status(400).json({ message: '저장된 파일이 PDF 형식이 아닙니다.' });
    }
    const encodedFileName = encodeURIComponent(row.passport_file_name || 'passport_scan.pdf');
    const isDownload = req.query.download === '1';
    const contentDisposition = isDownload ? 'attachment' : 'inline';

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Length', buffer.length);
    res.setHeader('Content-Disposition', `${contentDisposition}; filename*=UTF-8''${encodedFileName}`);
    res.send(buffer);
  } catch (error) {
    res.status(500).json({ message: '여권 파일 조회 실패' });
  }
});

app.get('/{*any}', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

if (!process.env.VERCEL) {
  ensureDbInitialized()
    .then(() => {
      app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
      });
    })
    .catch((error) => {
      console.error('DB initialization failed:', error);
      process.exit(1);
    });
}

module.exports = app;

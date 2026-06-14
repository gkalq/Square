import express from 'express';
import jwt from 'jsonwebtoken';
import { createHmac, timingSafeEqual } from 'crypto';
import { readFileSync, writeFileSync, renameSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const PASSCODE = process.env.PASSCODE;
const DATA_PATH = process.env.DATA_PATH || 'data.json';

if (!PASSCODE) { console.error('Error: PASSCODE env var is required'); process.exit(1); }
if (!JWT_SECRET) { console.error('Error: JWT_SECRET env var is required'); process.exit(1); }

const app = express();
app.use(express.json({ limit: '4mb' }));
app.use(express.static(__dirname));

function checkPasscode(input) {
  try {
    const h = s => createHmac('sha256', JWT_SECRET).update(String(s)).digest('hex');
    const a = Buffer.from(h(input));
    const b = Buffer.from(h(PASSCODE));
    return a.length === b.length && timingSafeEqual(a, b);
  } catch { return false; }
}

function loadData() {
  if (!existsSync(DATA_PATH)) return { tasks: { q1:[], q2:[], q3:[], q4:[] }, history: [] };
  try { return JSON.parse(readFileSync(DATA_PATH, 'utf8')); }
  catch { return { tasks: { q1:[], q2:[], q3:[], q4:[] }, history: [] }; }
}

function saveData(data) {
  const tmp = DATA_PATH + '.tmp';
  writeFileSync(tmp, JSON.stringify(data), 'utf8');
  renameSync(tmp, DATA_PATH);
}

function auth(req, res, next) {
  const header = req.headers.authorization;
  const token = header?.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try { jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Unauthorized' }); }
}

app.get('/api/health', (req, res) => res.json({ ok: true }));

app.post('/api/auth', (req, res) => {
  const { passcode } = req.body || {};
  if (!passcode || !checkPasscode(passcode)) {
    return res.status(401).json({ error: 'Wrong passcode' });
  }
  const token = jwt.sign({ v: 1 }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token });
});

app.get('/api/data', auth, (req, res) => {
  res.json(loadData());
});

app.put('/api/data', auth, (req, res) => {
  const { tasks, history } = req.body || {};
  if (!tasks || !Array.isArray(history)) return res.status(400).json({ error: 'Invalid data' });
  saveData({ tasks, history });
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`Matrix running on http://localhost:${PORT}`));

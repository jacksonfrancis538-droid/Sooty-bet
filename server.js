import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';

const { Pool } = pg;
const app = express();
const PORT = process.env.PORT || 10000;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const JWT_SECRET = process.env.JWT_SECRET;
if (!process.env.DATABASE_URL || !JWT_SECRET || !ADMIN_EMAIL || !ADMIN_PASSWORD) {
  console.error('Missing DATABASE_URL, JWT_SECRET, ADMIN_EMAIL or ADMIN_PASSWORD');
  process.exit(1);
}
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false }
});
app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_ORIGIN ? process.env.FRONTEND_ORIGIN.split(',') : true }));
app.use(express.json({ limit: '20kb' }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 20 }));
app.use('/api/withdrawals', rateLimit({ windowMs: 60 * 60 * 1000, limit: 8 }));

await pool.query(`
CREATE TABLE IF NOT EXISTS users (
 id BIGSERIAL PRIMARY KEY,
 email TEXT UNIQUE,
 phone TEXT UNIQUE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')),
 status TEXT NOT NULL DEFAULT 'pending_verification',
 balance_kobo BIGINT NOT NULL DEFAULT 0 CHECK (balance_kobo >= 0),
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS withdrawals (
 id BIGSERIAL PRIMARY KEY,
 user_id BIGINT NOT NULL REFERENCES users(id),
 reference TEXT NOT NULL UNIQUE,
 amount_kobo BIGINT NOT NULL CHECK (amount_kobo > 0),
 bank_name TEXT NOT NULL,
 account_name TEXT NOT NULL,
 account_number TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','paid','rejected')),
 admin_note TEXT,
 reviewed_by BIGINT REFERENCES users(id),
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS wallet_ledger (
 id BIGSERIAL PRIMARY KEY,
 user_id BIGINT NOT NULL REFERENCES users(id),
 type TEXT NOT NULL,
 amount_kobo BIGINT NOT NULL,
 reference TEXT NOT NULL UNIQUE,
 description TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS withdrawals_status_created_idx ON withdrawals(status, created_at DESC);
ALTER TABLE users ADD COLUMN IF NOT EXISTS date_of_birth DATE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_reviewed_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_note TEXT;
`);

const adminHash = await bcrypt.hash(ADMIN_PASSWORD, 12);
const existingAdmin = await pool.query('SELECT id FROM users WHERE lower(email)=lower($1)', [ADMIN_EMAIL]);
if (!existingAdmin.rowCount) {
  await pool.query("INSERT INTO users(email,password_hash,role,status) VALUES($1,$2,'admin','active')", [ADMIN_EMAIL, adminHash]);
} else {
  await pool.query("UPDATE users SET role='admin',status='active',password_hash=$2 WHERE id=$1", [existingAdmin.rows[0].id, adminHash]);
}

function tokenFor(user) {
 return jwt.sign({ sub: String(user.id), role: user.role }, JWT_SECRET, { expiresIn: '12h', issuer: 'sooty-bet' });
}
function auth(req,res,next) {
 const raw = req.headers.authorization || '';
 try {
  const payload = jwt.verify(raw.replace(/^Bearer\s+/i,''), JWT_SECRET, { issuer: 'sooty-bet' });
  req.auth = payload; next();
 } catch { res.status(401).json({ error: 'Please sign in again.' }); }
}
function adminOnly(req,res,next) {
 if (req.auth?.role !== 'admin') return res.status(403).json({ error: 'Admin access only.' });
 next();
}
function cleanText(v,max=100) { return typeof v === 'string' ? v.trim().slice(0,max) : ''; }
function ref() { return 'SWD-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).slice(2,7).toUpperCase(); }


// Free football fixtures from TheSportsDB. Its free tier does not include live scores.
const sportsCache = new Map();
async function sportsDay(date) {
  const key = 'day:' + date;
  const cached = sportsCache.get(key);
  if (cached && Date.now() - cached.at < 10 * 60 * 1000) return cached.data;
  const url = 'https://www.thesportsdb.com/api/v1/json/123/eventsday.php?d=' + encodeURIComponent(date) + '&s=Soccer';
  const response = await fetch(url, { headers: { accept: 'application/json' } });
  if (!response.ok) {
    const error = new Error('The free sports fixtures service is temporarily unavailable.');
    error.status = 502;
    throw error;
  }
  const body = await response.json().catch(() => ({}));
  const data = (body.events || []).map(item => ({
    id: item.idEvent,
    league: item.strLeague || 'Football',
    country: item.strCountry || '',
    home: item.strHomeTeam || 'Home',
    away: item.strAwayTeam || 'Away',
    homeScore: item.intHomeScore == null ? null : Number(item.intHomeScore),
    awayScore: item.intAwayScore == null ? null : Number(item.intAwayScore),
    status: 'NS',
    statusText: 'Scheduled fixture',
    elapsed: null,
    kickoff: item.strTimestamp || (item.dateEvent && item.strTime ? item.dateEvent + 'T' + item.strTime + 'Z' : item.dateEvent || null),
    venue: item.strVenue || ''
  })).filter(item => item.home && item.away);
  sportsCache.set(key, { at: Date.now(), data });
  return data;
}
function dateOffset(days) {
  const date = new Date();
  date.setUTCHours(0, 0, 0, 0);
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString().slice(0, 10);
}
app.get('/api/sports/live', (_req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({
    matches: [],
    updatedAt: new Date().toISOString(),
    provider: 'TheSportsDB Free',
    message: 'Live scores are not included in the free tier.'
  });
});
app.get('/api/sports/upcoming', async (_req, res) => {
  try {
    // Three daily requests stay within TheSportsDB free schedule endpoint allowance.
    const days = await Promise.all([0, 1, 2].map(offset => sportsDay(dateOffset(offset))));
    const matches = days.flat().sort((a, b) => new Date(a.kickoff || 0) - new Date(b.kickoff || 0));
    res.set('Cache-Control', 'no-store');
    res.json({ matches, updatedAt: new Date().toISOString(), provider: 'TheSportsDB Free' });
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message || 'Could not load upcoming fixtures.' });
  }
});

app.get('/health', (_req,res)=>res.json({ok:true,service:'sooty-bet-api'}));
app.post('/api/auth/register', async (req,res) => {
 try {
  const email = cleanText(req.body.email,254).toLowerCase() || null;
  const phone = cleanText(req.body.phone,20) || null;
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  if ((!email && !phone) || password.length < 12) return res.status(400).json({error:'Enter a valid email or phone and a password of at least 12 characters.'});
  const password_hash = await bcrypt.hash(password,12);
  const q = await pool.query('INSERT INTO users(email,phone,password_hash) VALUES($1,$2,$3) RETURNING id,email,phone,role,status,balance_kobo', [email,phone,password_hash]);
  const u=q.rows[0];
  res.status(201).json({token:tokenFor(u),user:{id:u.id,email:u.email,phone:u.phone,role:u.role,status:u.status}});
 } catch(e) { res.status(e.code==='23505'?409:500).json({error:e.code==='23505'?'That email or phone is already registered.':'Could not create account.'}); }
});
app.post('/api/auth/login', async (req,res) => {
 try {
  const identifier = cleanText(req.body.identifier,254).toLowerCase();
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  const q = await pool.query('SELECT * FROM users WHERE lower(coalesce(email,phone))=$1 OR phone=$1 LIMIT 1',[identifier]);
  const u=q.rows[0];
  if (!u || !(await bcrypt.compare(password,u.password_hash))) return res.status(401).json({error:'Invalid login details.'});
  res.json({token:tokenFor(u),user:{id:u.id,email:u.email,phone:u.phone,role:u.role,status:u.status}});
 } catch { res.status(500).json({error:'Login failed.'}); }
});
app.get('/api/wallet',auth,async(req,res)=>{
 const q=await pool.query('SELECT balance_kobo FROM users WHERE id=$1',[req.auth.sub]);
 const entries=await pool.query('SELECT type,amount_kobo,reference,description,created_at FROM wallet_ledger WHERE user_id=$1 ORDER BY created_at DESC LIMIT 30',[req.auth.sub]);
 res.json({balanceKobo:q.rows[0]?.balance_kobo||0,entries:entries.rows.map(x=>({type:x.type,amountKobo:x.amount_kobo,reference:x.reference,description:x.description,createdAt:x.created_at}))});
});
app.get('/api/bets',auth,(_req,res)=>res.json([]));
app.get('/api/admin/users/pending-verification',auth,adminOnly,async(_req,res)=>{
 const q=await pool.query("SELECT id,email,phone,created_at FROM users WHERE role='user' AND status='pending_verification' ORDER BY created_at ASC LIMIT 200");
 res.json(q.rows);
});
app.patch('/api/admin/users/:id/verification',auth,adminOnly,async(req,res)=>{
 const decision=cleanText(req.body.decision,20);
 const evidenceChecked=req.body.evidenceChecked===true;
 const note=cleanText(req.body.note,300);
 if(!['approved','rejected'].includes(decision)) return res.status(400).json({error:'Choose approve or reject.'});
 if(!evidenceChecked) return res.status(400).json({error:'Confirm that you reviewed valid age evidence before submitting.'});
 let dob=null;
 if(decision==='approved'){
  const raw=cleanText(req.body.dateOfBirth,10);
  if(!/^\d{4}-\d{2}-\d{2}$/.test(raw)) return res.status(400).json({error:'Enter the date of birth shown on the verified identity document.'});
  const parsed=new Date(raw+'T00:00:00Z');
  if(Number.isNaN(parsed.getTime())||parsed.toISOString().slice(0,10)!==raw) return res.status(400).json({error:'Enter a valid date of birth.'});
  const today=new Date(); let age=today.getUTCFullYear()-parsed.getUTCFullYear();
  const month=today.getUTCMonth()-parsed.getUTCMonth();
  if(month<0||(month===0&&today.getUTCDate()<parsed.getUTCDate())) age--;
  if(age<18) return res.status(403).json({error:'This user is under 18 and cannot be approved.'});
  dob=raw;
 }
 const status=decision==='approved'?'active':'verification_rejected';
 const q=await pool.query("UPDATE users SET status=$1,date_of_birth=$2,verification_reviewed_at=NOW(),verification_note=$3 WHERE id=$4 AND role='user' AND status='pending_verification' RETURNING id,email,phone,status,verification_reviewed_at",[status,dob,note||('Age verification '+decision),req.params.id]);
 if(!q.rowCount) return res.status(404).json({error:'Pending user not found. Refresh the list.'});
 res.json({ok:true,user:q.rows[0],message:decision==='approved'?'Age verified. Account activated.':'Verification rejected.'});
});
app.get('/api/admin/overview',auth,adminOnly,async(_req,res)=>{
 const [users,bets,pending]=await Promise.all([
  pool.query('SELECT count(*)::int n FROM users WHERE role=\'user\''),
  pool.query('SELECT 0::int n'),
  pool.query("SELECT count(*)::int n FROM users WHERE role='user' AND status='pending_verification'")
 ]);
 res.json({users:users.rows[0].n,bets:bets.rows[0].n,pendingVerification:pending.rows[0].n,note:'Withdrawal requests are managed below. No automated payouts are connected.'});
});
app.post('/api/withdrawals',auth,async(req,res)=>{
 const amountNaira=Number(req.body.amount);
 const amountKobo=Math.round(amountNaira*100);
 const bank=cleanText(req.body.bankName,80), accountName=cleanText(req.body.accountName,100), accountNumber=cleanText(req.body.accountNumber,20);
 if (!Number.isSafeInteger(amountKobo)||amountKobo<10000||amountKobo>100000000||!bank||!accountName||!/^[0-9]{10}$/.test(accountNumber))
  return res.status(400).json({error:'Enter a valid amount (minimum ₦100), bank, account name and 10-digit account number.'});
 const client=await pool.connect();
 try {
  await client.query('BEGIN');
  const u=await client.query('SELECT balance_kobo FROM users WHERE id=$1 FOR UPDATE',[req.auth.sub]);
  if (!u.rowCount || BigInt(u.rows[0].balance_kobo)<BigInt(amountKobo)) { await client.query('ROLLBACK'); return res.status(400).json({error:'Insufficient available wallet balance.'}); }
  const reference=ref();
  await client.query('UPDATE users SET balance_kobo=balance_kobo-$1 WHERE id=$2',[amountKobo,req.auth.sub]);
  await client.query('INSERT INTO wallet_ledger(user_id,type,amount_kobo,reference,description) VALUES($1,\'withdrawal_hold\',$2,$3,\'Withdrawal request reserved pending admin review\')',[req.auth.sub,amountKobo,reference]);
  const w=await client.query('INSERT INTO withdrawals(user_id,reference,amount_kobo,bank_name,account_name,account_number) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,reference,amount_kobo,bank_name,account_name,account_number,status,created_at',[req.auth.sub,reference,amountKobo,bank,accountName,accountNumber]);
  await client.query('COMMIT');
  res.status(201).json({withdrawal:{...w.rows[0],amountNaira:amountNaira,createdAt:w.rows[0].created_at}});
 } catch(e) { await client.query('ROLLBACK'); res.status(500).json({error:'Could not submit withdrawal request.'}); }
 finally { client.release(); }
});
app.get('/api/withdrawals',auth,async(req,res)=>{
 const q=await pool.query('SELECT id,reference,amount_kobo,bank_name,account_name,account_number,status,admin_note,created_at,updated_at FROM withdrawals WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50',[req.auth.sub]);
 res.json(q.rows);
});
app.get('/api/admin/withdrawals',auth,adminOnly,async(_req,res)=>{
 const q=await pool.query('SELECT w.id,w.reference,w.amount_kobo,w.bank_name,w.account_name,w.account_number,w.status,w.admin_note,w.created_at,u.email,u.phone FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY CASE WHEN w.status=\'pending\' THEN 0 WHEN w.status=\'approved\' THEN 1 ELSE 2 END,w.created_at DESC LIMIT 200');
 res.json(q.rows);
});
app.patch('/api/admin/withdrawals/:id',auth,adminOnly,async(req,res)=>{
 const status=cleanText(req.body.status,20), note=cleanText(req.body.note,300);
 if (!['approved','paid','rejected'].includes(status)) return res.status(400).json({error:'Status must be approved, paid or rejected.'});
 const client=await pool.connect();
 try {
  await client.query('BEGIN');
  const q=await client.query('SELECT * FROM withdrawals WHERE id=$1 FOR UPDATE',[req.params.id]);
  if (!q.rowCount) { await client.query('ROLLBACK'); return res.status(404).json({error:'Withdrawal not found.'}); }
  const w=q.rows[0];
  if (w.status==='paid'||w.status==='rejected') { await client.query('ROLLBACK'); return res.status(409).json({error:'This request is already closed.'}); }
  if (status==='paid' && w.status!=='approved') { await client.query('ROLLBACK'); return res.status(409).json({error:'Approve the request first. Transfer the money manually, then mark it paid.'}); }
  if (status==='rejected') {
   await client.query('UPDATE users SET balance_kobo=balance_kobo+$1 WHERE id=$2',[w.amount_kobo,w.user_id]);
   await client.query('INSERT INTO wallet_ledger(user_id,type,amount_kobo,reference,description) VALUES($1,\'withdrawal_refund\',$2,$3,\'Rejected withdrawal returned to wallet\')',[w.user_id,w.amount_kobo,'REF-'+w.reference]);
  }
  await client.query('UPDATE withdrawals SET status=$1,admin_note=$2,reviewed_by=$3,updated_at=NOW() WHERE id=$4',[status,note,req.auth.sub,w.id]);
  await client.query('COMMIT');
  res.json({ok:true,status,message:status==='paid'?'Marked paid. Confirm the bank transfer has actually succeeded.':status==='approved'?'Approved. Make the bank transfer manually before marking paid.':'Rejected; reserved wallet funds returned.'});
 } catch { await client.query('ROLLBACK'); res.status(500).json({error:'Could not update request.'}); }
 finally { client.release(); }
});
app.listen(PORT,'0.0.0.0',()=>console.log('SOOTY BET API listening on '+PORT));
